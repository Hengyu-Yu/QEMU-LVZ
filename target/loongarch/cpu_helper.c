/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LoongArch CPU helpers for qemu
 *
 * Copyright (c) 2024 Loongson Technology Corporation Limited
 *
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "cpu-csr.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"
#include "qemu/log.h"

#ifdef CONFIG_TCG
static int loongarch_map_tlb_entry(CPULoongArchState *env, hwaddr *physical,
                                   int *prot, target_ulong address,
                                   int access_type, int index, int mmu_idx, bool guest)
{
    LoongArchTLB *tlb = guest ? &env->gtlb[index] : &env->tlb[index];
    uint64_t plv = mmu_idx_to_plv(mmu_idx);
    uint64_t tlb_entry, tlb_ppn;
    uint8_t tlb_ps, n, tlb_v, tlb_d, tlb_plv, tlb_nx, tlb_nr, tlb_rplv;

    if (index >= LOONGARCH_STLB) {
        tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
    } else {
        tlb_ps = FIELD_EX64(GET_CSR_IF(guest, STLBPS), CSR_STLBPS, PS);
    }
    n = (address >> tlb_ps) & 0x1;/* Odd or even */

    tlb_entry = n ? tlb->tlb_entry1 : tlb->tlb_entry0;
    tlb_v = FIELD_EX64(tlb_entry, TLBENTRY, V);
    tlb_d = FIELD_EX64(tlb_entry, TLBENTRY, D);
    tlb_plv = FIELD_EX64(tlb_entry, TLBENTRY, PLV);
    if (is_la64(env)) {
        tlb_ppn = FIELD_EX64(tlb_entry, TLBENTRY_64, PPN);
        tlb_nx = FIELD_EX64(tlb_entry, TLBENTRY_64, NX);
        tlb_nr = FIELD_EX64(tlb_entry, TLBENTRY_64, NR);
        tlb_rplv = FIELD_EX64(tlb_entry, TLBENTRY_64, RPLV);
    } else {
        tlb_ppn = FIELD_EX64(tlb_entry, TLBENTRY_32, PPN);
        tlb_nx = 0;
        tlb_nr = 0;
        tlb_rplv = 0;
    }

    /* Remove sw bit between bit12 -- bit PS*/
    tlb_ppn = tlb_ppn & ~(((0x1UL << (tlb_ps - 12)) -1));

    /* Check access rights */
    if (!tlb_v) {
        return TLBRET_INVALID;
    }

    if (access_type == MMU_INST_FETCH && tlb_nx) {
        return TLBRET_XI;
    }

    if (access_type == MMU_DATA_LOAD && tlb_nr) {
        return TLBRET_RI;
    }

    if (((tlb_rplv == 0) && (plv > tlb_plv)) ||
        ((tlb_rplv == 1) && (plv != tlb_plv))) {
        return TLBRET_PE;
    }

    if ((access_type == MMU_DATA_STORE) && !tlb_d) {
        return TLBRET_DIRTY;
    }

    *physical = (tlb_ppn << R_TLBENTRY_64_PPN_SHIFT) |
                (address & MAKE_64BIT_MASK(0, tlb_ps));

    *prot = PAGE_READ;
    if (tlb_d) {
        *prot |= PAGE_WRITE;
    }
    if (!tlb_nx) {
        *prot |= PAGE_EXEC;
    }
    return TLBRET_MATCH;
}

/*
 * One tlb entry holds an adjacent odd/even pair, the vpn is the
 * content of the virtual page number divided by 2. So the
 * compare vpn is bit[47:15] for 16KiB page. while the vppn
 * field in tlb entry contains bit[47:13], so need adjust.
 * virt_vpn = vaddr[47:13]
 */
bool loongarch_tlb_search(CPULoongArchState *env, target_ulong vaddr,
                          int *index, bool guest, int gid)
{
    LoongArchTLB *tlb;
    uint16_t csr_asid, tlb_asid, stlb_idx;
    uint8_t tlb_e, tlb_ps, tlb_g, tlb_gid, stlb_ps;
    int i, compare_shift;
    uint64_t vpn, tlb_vppn;

    csr_asid = FIELD_EX64(GET_CSR_IF(guest, ASID), CSR_ASID, ASID);
    stlb_ps = FIELD_EX64(GET_CSR_IF(guest, STLBPS), CSR_STLBPS, PS);
    vpn = (vaddr & TARGET_VIRT_MASK) >> (stlb_ps + 1);
    stlb_idx = vpn & 0xff; /* VA[25:15] <==> TLBIDX.index for 16KiB Page */
    compare_shift = stlb_ps + 1 - R_TLB_MISC_VPPN_SHIFT;

    /* Search STLB */
    for (i = 0; i < 8; ++i) {
        if (guest) {
            tlb = &env->gtlb[i * 256 + stlb_idx];
        } else {
            tlb = &env->tlb[i * 256 + stlb_idx];
        }
        tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);
        if (tlb_e) {
            tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
            tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
            tlb_gid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, GID);
            tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
            if ((tlb_g == 1 || tlb_asid == csr_asid) &&
                (vpn == (tlb_vppn >> compare_shift)) &&
                (tlb_gid == gid)) {
                *index = i * 256 + stlb_idx;
                if (guest)
                    qemu_log("Found tlb index=%d tlb_misc=%016lx tlb_entry0=%016lx tlb_entry1=%016lx gid=%d asid=%d  stlbps=%d\n", *index, tlb->tlb_misc, tlb->tlb_entry0, tlb->tlb_entry1, gid, csr_asid, stlb_ps);
                return true;
            }
        }
    }

    /* Search MTLB */
    for (i = LOONGARCH_STLB; i < LOONGARCH_TLB_MAX; ++i) {
        if (guest) {
            tlb = &env->gtlb[i];
        } else {
            tlb = &env->tlb[i];
        }
        tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);
        if (tlb_e) {
            tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
            tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
            tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
            tlb_gid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, GID);
            tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
            compare_shift = tlb_ps + 1 - R_TLB_MISC_VPPN_SHIFT;
            vpn = (vaddr & TARGET_VIRT_MASK) >> (tlb_ps + 1);
            if ((tlb_g == 1 || tlb_asid == csr_asid) &&
                (vpn == (tlb_vppn >> compare_shift)) &&
                (tlb_gid == gid)) {
                *index = i;
                if (guest)
                    qemu_log("Found tlb index=%d tlb_misc=%016lx tlb_entry0=%016lx tlb_entry1=%016lx gid=%d asid=%d\n", *index, tlb->tlb_misc, tlb->tlb_entry0, tlb->tlb_entry1, gid, csr_asid);
                return true;
            }
        }
    }
    return false;
}

int loongarch_map_host_address(CPULoongArchState *env, hwaddr *physical,
                                      int *prot, target_ulong gpa,
                                      MMUAccessType access_type)
{
    int match, index;

    match = loongarch_tlb_search(env, gpa, &index, false, get_tgid(env));
    if (match) {
        int ret = loongarch_map_tlb_entry(env, physical, prot,
                                           gpa, access_type, index, MMU_KERNEL_IDX, false);
        if (ret == TLBRET_MATCH) {
            qemu_log("GPA->HPA: %016lx %016lx tgid=%d guest=%d\n",
                     gpa, *physical, get_tgid(env), env->guest);
        } else {
            qemu_log("HOST_TLB_HIT_INV gpa=%016lx ret=%d tgid=%d guest=%d idx=%d"
                     " e0=%016lx e1=%016lx misc=%016lx\n",
                     gpa, TLBRET_HOST_MATCH + ret, get_tgid(env), env->guest, index,
                     env->tlb[index].tlb_entry0, env->tlb[index].tlb_entry1,
                     env->tlb[index].tlb_misc);
        }
        return TLBRET_HOST_MATCH + ret;
    }

    qemu_log("HOST_TLB_MISS gpa=%016lx tgid=%d guest=%d\n",
             gpa, get_tgid(env), env->guest);
    return TLBRET_HOST_NOMATCH;
}

static int loongarch_map_address(CPULoongArchState *env, hwaddr *physical,
                                 int *prot, target_ulong address,
                                 MMUAccessType access_type, int mmu_idx)
{
    int index, match;

    if (env->guest) {
        qemu_log("Searching for GVA %016lx, access type=%d, mmu_idx=%d\n", address, access_type, mmu_idx);
    }

    match = loongarch_tlb_search(env, address, &index, env->guest, get_tgid(env));
    if (match) {
        int ret = loongarch_map_tlb_entry(env, physical, prot,
                                        address, access_type, index, mmu_idx, env->guest);
        if (env->guest && ret == TLBRET_MATCH) {
            qemu_log("GVA->GPA: %016lx %016lx tgid=%d\n",
                     address, *physical, get_tgid(env));
        }
        return ret;
    }

    return TLBRET_NOMATCH;
}
#else
static int loongarch_map_address(CPULoongArchState *env, hwaddr *physical,
                                 int *prot, target_ulong address,
                                 MMUAccessType access_type, int mmu_idx)
{
    return TLBRET_NOMATCH;
}
#endif

static hwaddr dmw_va2pa(CPULoongArchState *env, target_ulong va,
                        target_ulong dmw)
{
    if (is_la64(env)) {
        return va & TARGET_VIRT_MASK;
    } else {
        uint32_t pseg = FIELD_EX32(dmw, CSR_DMW_32, PSEG);
        return (va & MAKE_64BIT_MASK(0, R_CSR_DMW_32_VSEG_SHIFT)) | \
            (pseg << R_CSR_DMW_32_VSEG_SHIFT);
    }
}

int get_physical_address(CPULoongArchState *env, hwaddr *physical,
                         int *prot, target_ulong address,
                         MMUAccessType access_type, int mmu_idx)
{
    uint32_t plv = mmu_idx_to_plv(mmu_idx);
    uint32_t base_c, base_v;
    int64_t addr_high;
    uint8_t da, pg;
    da = FIELD_EX64(GET_CSR_IF(env->guest, CRMD), CSR_CRMD, DA);
    pg = FIELD_EX64(GET_CSR_IF(env->guest, CRMD), CSR_CRMD, PG);

    /* Check PG and DA */
    if (da & !pg) {
        *physical = address & TARGET_PHYS_MASK;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return TLBRET_MATCH;
    }

    if (is_la64(env)) {
        base_v = address >> R_CSR_DMW_64_VSEG_SHIFT;
    } else {
        base_v = address >> R_CSR_DMW_32_VSEG_SHIFT;
    }
    /* Check direct map window */
    for (int i = 0; i < 4; i++) {
        if (is_la64(env)) {
            base_c = FIELD_EX64(GET_CSR_IF(env->guest, DMW[i]), CSR_DMW_64, VSEG);
        } else {
            base_c = FIELD_EX64(GET_CSR_IF(env->guest, DMW[i]), CSR_DMW_32, VSEG);
        }
        if ((GET_CSR_IF(env->guest, DMW[i]) & (1 << plv)) && (base_c == base_v)) {
            *physical = dmw_va2pa(env, address, GET_CSR_IF(env->guest, DMW[i]));
            *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
            return TLBRET_MATCH;
        }
    }

    /* Check valid extension */
    addr_high = sextract64(address, TARGET_VIRT_ADDR_SPACE_BITS, 16);
    if (!(addr_high == 0 || addr_high == -1)) {
        return TLBRET_BADADDR;
    }

    /* Mapped address */
    return loongarch_map_address(env, physical, prot, address,
                                 access_type, mmu_idx);
}

hwaddr loongarch_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    CPULoongArchState *env = cpu_env(cs);
    hwaddr phys_addr;
    int prot;

    if (get_physical_address(env, &phys_addr, &prot, addr, MMU_DATA_LOAD,
                             cpu_mmu_index(cs, false)) != 0) {
        return -1;
    }
    return phys_addr;
}
