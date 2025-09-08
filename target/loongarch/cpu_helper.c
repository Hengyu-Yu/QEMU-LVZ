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

#ifndef CONFIG_USER_ONLY
/* Virtual Machine Exit Handler for CPU Helper */
void helper_vm_exit_cpu(CPULoongArchState *env, uint32_t exit_reason)
{
    /* Only process VM exit in guest execution context */
    if (!is_guest_execution_context(env)) {
        qemu_log_mask(LOG_GUEST_ERROR, 
                      "VM exit called outside guest context, reason: %u\n", 
                      exit_reason);
        return;
    }

    /* Save current guest state in VM exit context */
    env->vm_exit_ctx.exit_reason = exit_reason;
    env->vm_exit_ctx.fault_gva = env->pc;  /* Current PC as fault GVA */
    env->vm_exit_ctx.fault_gpa = 0;        /* Will be filled by MMU if needed */
    env->vm_exit_ctx.gid = get_guest_id(env);
    env->vm_exit_ctx.access_type = 0;      /* Will be set by caller if needed */
    env->vm_exit_ctx.is_tlb_refill = false;

    /* Save current virtualization mode state in PVM */
    uint64_t vm_bit = FIELD_EX64(env->CSR_GSTAT, CSR_GSTAT, VM);
    env->CSR_GSTAT = FIELD_DP64(env->CSR_GSTAT, CSR_GSTAT, PVM, vm_bit);
    
    /* Clear VM bit to enter hypervisor mode */
    env->CSR_GSTAT = FIELD_DP64(env->CSR_GSTAT, CSR_GSTAT, VM, 0);

    /* Save current privilege level and interrupt state for guest */
    uint64_t crmd = env->CSR_CRMD;
    uint64_t guest_prmd = env->gpr[LOONGARCH_GCSR_PRMD];
    
    /* Update guest PRMD with current state before exit */
    guest_prmd = FIELD_DP64(guest_prmd, CSR_PRMD, PPLV, 
                           FIELD_EX64(crmd, CSR_CRMD, PLV));
    guest_prmd = FIELD_DP64(guest_prmd, CSR_PRMD, PIE, 
                           FIELD_EX64(crmd, CSR_CRMD, IE));
    env->gpr[LOONGARCH_GCSR_PRMD] = guest_prmd;

    /* Save guest's current PC in guest ERA */
    env->gpr[LOONGARCH_GCSR_ERA] = env->pc;

    /* Update guest exception status with VM exit code */
    env->gpr[LOONGARCH_GCSR_ESTAT] = FIELD_DP64(env->gpr[LOONGARCH_GCSR_ESTAT], 
                                               CSR_ESTAT, ECODE, EXCCODE_HVC);

    /* Set hypervisor privilege level and disable interrupts */
    env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, PLV, 0);
    env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, IE, 0);

    /* Log the VM exit for debugging */
    qemu_log_mask(CPU_LOG_INT, 
                  "VM Exit: reason=%u, GID=%u, GVA=0x%lx, switching to hypervisor\n",
                  exit_reason, env->vm_exit_ctx.gid, env->vm_exit_ctx.fault_gva);

    /* Trigger exception to hypervisor */
    do_raise_exception(env, EXCCODE_HVC, 0);
}

/* Virtual Machine State Save for context switch */
void helper_vm_save_state(CPULoongArchState *env)
{
    if (!is_guest_execution_context(env)) {
        return;
    }

    /* Save guest CSR state to GCSR registers */
    env->gpr[LOONGARCH_GCSR_CRMD] = env->CSR_CRMD;
    env->gpr[LOONGARCH_GCSR_ASID] = env->CSR_ASID;
    env->gpr[LOONGARCH_GCSR_PGDL] = env->CSR_PGDL;
    env->gpr[LOONGARCH_GCSR_PGDH] = env->CSR_PGDH;
    env->gpr[LOONGARCH_GCSR_BADV] = env->CSR_BADV;
    env->gpr[LOONGARCH_GCSR_BADI] = env->CSR_BADI;
    env->gpr[LOONGARCH_GCSR_EENTRY] = env->CSR_EENTRY;
    env->gpr[LOONGARCH_GCSR_TLBIDX] = env->CSR_TLBIDX;
    env->gpr[LOONGARCH_GCSR_TLBEHI] = env->CSR_TLBEHI;
    env->gpr[LOONGARCH_GCSR_TLBELO0] = env->CSR_TLBELO0;
    env->gpr[LOONGARCH_GCSR_TLBELO1] = env->CSR_TLBELO1;

    qemu_log_mask(CPU_LOG_INT, "VM state saved for GID %u\n", get_guest_id(env));
}

/* Virtual Machine State Restore for context switch */
void helper_vm_restore_state(CPULoongArchState *env)
{
    if (!is_hypervisor_execution_context(env)) {
        return;
    }

    /* Restore guest CSR state from GCSR registers */
    env->CSR_CRMD = env->gpr[LOONGARCH_GCSR_CRMD];
    env->CSR_ASID = env->gpr[LOONGARCH_GCSR_ASID];
    env->CSR_PGDL = env->gpr[LOONGARCH_GCSR_PGDL];
    env->CSR_PGDH = env->gpr[LOONGARCH_GCSR_PGDH];
    env->CSR_BADV = env->gpr[LOONGARCH_GCSR_BADV];
    env->CSR_BADI = env->gpr[LOONGARCH_GCSR_BADI];
    env->CSR_EENTRY = env->gpr[LOONGARCH_GCSR_EENTRY];
    env->CSR_TLBIDX = env->gpr[LOONGARCH_GCSR_TLBIDX];
    env->CSR_TLBEHI = env->gpr[LOONGARCH_GCSR_TLBEHI];
    env->CSR_TLBELO0 = env->gpr[LOONGARCH_GCSR_TLBELO0];
    env->CSR_TLBELO1 = env->gpr[LOONGARCH_GCSR_TLBELO1];

    qemu_log_mask(CPU_LOG_INT, "VM state restored for GID %u\n", get_guest_id(env));
}

/* Enhanced VM exit with detailed fault information */
void helper_vm_exit_with_fault(CPULoongArchState *env, uint32_t exit_reason, 
                               uint64_t fault_gva, uint64_t fault_gpa, 
                               uint32_t access_type)
{
    if (!is_guest_execution_context(env)) {
        return;
    }

    /* Save detailed fault information */
    env->vm_exit_ctx.exit_reason = exit_reason;
    env->vm_exit_ctx.fault_gva = fault_gva;
    env->vm_exit_ctx.fault_gpa = fault_gpa;
    env->vm_exit_ctx.gid = get_guest_id(env);
    env->vm_exit_ctx.access_type = access_type;
    env->vm_exit_ctx.is_tlb_refill = (exit_reason == VMEXIT_TLB);

    /* Update guest BADV with fault address */
    env->CSR_BADV = fault_gva;
    env->gpr[LOONGARCH_GCSR_BADV] = fault_gva;

    /* For second-level translation faults, save GPA in TRGP */
    if (exit_reason == VMEXIT_MMIO || exit_reason == VMEXIT_TLB) {
        env->CSR_TRGP = fault_gpa;
    }

    qemu_log_mask(CPU_LOG_INT, 
                  "VM Exit with fault: reason=%u, GVA=0x%lx, GPA=0x%lx, access=%u\n",
                  exit_reason, fault_gva, fault_gpa, access_type);

    /* Call standard VM exit handler */
    helper_vm_exit_cpu(env, exit_reason);
}
#endif

#ifdef CONFIG_TCG
static int loongarch_map_tlb_entry(CPULoongArchState *env, hwaddr *physical,
                                   int *prot, target_ulong address,
                                   int access_type, int index, int mmu_idx)
{
    LoongArchTLB *tlb = &env->tlb[index];
    uint64_t plv = mmu_idx;
    uint64_t tlb_entry, tlb_ppn;
    uint8_t tlb_ps, n, tlb_v, tlb_d, tlb_plv, tlb_nx, tlb_nr, tlb_rplv;

    if (index >= LOONGARCH_STLB) {
        tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
    } else {
        tlb_ps = FIELD_EX64(env->CSR_STLBPS, CSR_STLBPS, PS);
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
                          int *index)
{
    LoongArchTLB *tlb;
    uint16_t csr_asid, tlb_asid, stlb_idx;
    uint8_t tlb_e, tlb_ps, tlb_g, stlb_ps;
    int i, compare_shift;
    uint64_t vpn, tlb_vppn;

    csr_asid = FIELD_EX64(env->CSR_ASID, CSR_ASID, ASID);
    stlb_ps = FIELD_EX64(env->CSR_STLBPS, CSR_STLBPS, PS);
    vpn = (vaddr & TARGET_VIRT_MASK) >> (stlb_ps + 1);
    stlb_idx = vpn & 0xff; /* VA[25:15] <==> TLBIDX.index for 16KiB Page */
    compare_shift = stlb_ps + 1 - R_TLB_MISC_VPPN_SHIFT;

    /* Search STLB */
    for (i = 0; i < 8; ++i) {
        tlb = &env->tlb[i * 256 + stlb_idx];
        tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);
        if (tlb_e) {
            tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
            tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
            tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);

            if ((tlb_g == 1 || tlb_asid == csr_asid) &&
                (vpn == (tlb_vppn >> compare_shift))) {
                *index = i * 256 + stlb_idx;
                return true;
            }
        }
    }

    /* Search MTLB */
    for (i = LOONGARCH_STLB; i < LOONGARCH_TLB_MAX; ++i) {
        tlb = &env->tlb[i];
        tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);
        if (tlb_e) {
            tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
            tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
            tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
            tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
            compare_shift = tlb_ps + 1 - R_TLB_MISC_VPPN_SHIFT;
            vpn = (vaddr & TARGET_VIRT_MASK) >> (tlb_ps + 1);
            if ((tlb_g == 1 || tlb_asid == csr_asid) &&
                (vpn == (tlb_vppn >> compare_shift))) {
                *index = i;
                return true;
            }
        }
    }
    return false;
}

static int loongarch_map_address(CPULoongArchState *env, hwaddr *physical,
                                 int *prot, target_ulong address,
                                 MMUAccessType access_type, int mmu_idx)
{
    int index, match;

    match = loongarch_tlb_search(env, address, &index);
    if (match) {
        return loongarch_map_tlb_entry(env, physical, prot,
                                       address, access_type, index, mmu_idx);
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
    int user_mode = mmu_idx == MMU_USER_IDX;
    int kernel_mode = mmu_idx == MMU_KERNEL_IDX;
    uint32_t plv, base_c, base_v;
    int64_t addr_high;
    uint8_t da = FIELD_EX64(env->CSR_CRMD, CSR_CRMD, DA);
    uint8_t pg = FIELD_EX64(env->CSR_CRMD, CSR_CRMD, PG);

    /* Check PG and DA */
    if (da & !pg) {
        *physical = address & TARGET_PHYS_MASK;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return TLBRET_MATCH;
    }

    plv = kernel_mode | (user_mode << R_CSR_DMW_PLV3_SHIFT);
    if (is_la64(env)) {
        base_v = address >> R_CSR_DMW_64_VSEG_SHIFT;
    } else {
        base_v = address >> R_CSR_DMW_32_VSEG_SHIFT;
    }
    /* Check direct map window */
    for (int i = 0; i < 4; i++) {
        if (is_la64(env)) {
            base_c = FIELD_EX64(env->CSR_DMW[i], CSR_DMW_64, VSEG);
        } else {
            base_c = FIELD_EX64(env->CSR_DMW[i], CSR_DMW_32, VSEG);
        }
        if ((plv & env->CSR_DMW[i]) && (base_c == base_v)) {
            *physical = dmw_va2pa(env, address, env->CSR_DMW[i]);
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

#ifndef CONFIG_USER_ONLY
/* Enhanced physical address translation with virtualization support */
int get_physical_address_lvz(CPULoongArchState *env, hwaddr *physical,
                             int *prot, target_ulong address,
                             MMUAccessType access_type, int mmu_idx)
{
    int ret;
    hwaddr first_level_pa;
    
    /* First level translation (GVA -> GPA) */
    ret = get_physical_address(env, &first_level_pa, prot, address, 
                              access_type, mmu_idx);
    
    if (ret != TLBRET_MATCH) {
        /* First level translation failed */
        if (is_guest_execution_context(env)) {
            /* In guest mode, trigger VM exit for TLB miss */
            helper_vm_exit_with_fault(env, VMEXIT_TLB, address, 0, access_type);
            return TLBRET_SECOND_LEVEL_FAULT;
        }
        return ret;
    }
    
    /* If not in guest mode, return first level result */
    if (!is_guest_execution_context(env)) {
        *physical = first_level_pa;
        return TLBRET_MATCH;
    }
    
    /* Second level translation (GPA -> HPA) */
    /* This is a simplified implementation - in a real system, 
     * this would involve hypervisor page tables */
    
    /* Check if this GPA should cause a VM exit */
    if (should_trigger_vm_exit(env, VMEXIT_MMIO)) {
        /* MMIO access or other reason for VM exit */
        helper_vm_exit_with_fault(env, VMEXIT_MMIO, address, first_level_pa, access_type);
        return TLBRET_SECOND_LEVEL_FAULT;
    }
    
    /* For now, identity mapping for second level */
    *physical = first_level_pa;
    return TLBRET_MATCH;
}

/* VM-aware TLB search function */
bool loongarch_tlb_search_lvz(CPULoongArchState *env, target_ulong vaddr,
                              int *index, uint8_t target_gid)
{
    LoongArchTLB *tlb;
    uint16_t csr_asid, tlb_asid, stlb_idx;
    uint8_t tlb_e, tlb_ps, tlb_g, stlb_ps, tlb_gid;
    int i, compare_shift;
    uint64_t vpn, tlb_vppn;

    csr_asid = FIELD_EX64(env->CSR_ASID, CSR_ASID, ASID);
    stlb_ps = FIELD_EX64(env->CSR_STLBPS, CSR_STLBPS, PS);
    vpn = (vaddr & TARGET_VIRT_MASK) >> (stlb_ps + 1);
    stlb_idx = vpn & 0xff;
    compare_shift = stlb_ps + 1 - R_TLB_MISC_VPPN_SHIFT;

    /* Search STLB with GID awareness */
    for (i = 0; i < 8; ++i) {
        tlb = &env->tlb[i * 256 + stlb_idx];
        tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);
        if (tlb_e) {
            tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
            tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
            tlb_gid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, GID);
            tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);

            /* Check GID match for guest entries */
            if (tlb_gid != 0 && tlb_gid != target_gid) {
                continue;
            }

            if ((tlb_g == 1 || tlb_asid == csr_asid) &&
                (vpn == (tlb_vppn >> compare_shift))) {
                *index = i * 256 + stlb_idx;
                return true;
            }
        }
    }

    /* Search MTLB with GID awareness */
    for (i = LOONGARCH_STLB; i < LOONGARCH_TLB_MAX; ++i) {
        tlb = &env->tlb[i];
        tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);
        if (tlb_e) {
            tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
            tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
            tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
            tlb_gid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, GID);
            tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
            compare_shift = tlb_ps + 1 - R_TLB_MISC_VPPN_SHIFT;
            vpn = (vaddr & TARGET_VIRT_MASK) >> (tlb_ps + 1);

            /* Check GID match for guest entries */
            if (tlb_gid != 0 && tlb_gid != target_gid) {
                continue;
            }

            if ((tlb_g == 1 || tlb_asid == csr_asid) &&
                (vpn == (tlb_vppn >> compare_shift))) {
                *index = i;
                return true;
            }
        }
    }
    return false;
}

/* VM exit handler for second-level translation faults */
void handle_second_level_fault(CPULoongArchState *env, target_ulong vaddr, 
                              hwaddr gpa, MMUAccessType access_type)
{
    uint32_t exit_reason;
    
    /* Determine exit reason based on access type and address */
    if (gpa >= 0x1fe00000 && gpa <= 0x1fffffff) {
        /* IOCSR space access */
        exit_reason = VMEXIT_IOCSR;
    } else if (gpa >= 0xe0000000 && gpa <= 0xefffffff) {
        /* Typical MMIO range */
        exit_reason = VMEXIT_MMIO;
    } else {
        /* General memory access requiring VM exit */
        exit_reason = VMEXIT_MMIO;
    }
    
    /* Trigger VM exit with fault information */
    helper_vm_exit_with_fault(env, exit_reason, vaddr, gpa, access_type);
}
#endif
