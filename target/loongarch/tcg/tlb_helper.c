/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QEMU LoongArch TLB helpers
 *
 * Copyright (c) 2021 Loongson Technology Corporation Limited
 *
 */

#include "qemu/osdep.h"
#include "qemu/guest-random.h"

#include "cpu.h"
#include "internals.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/page-protection.h"
#include "exec/cpu_ldst.h"
#include "exec/log.h"
#include "cpu-csr.h"

/* LVZ (Virtualization) helper functions */

/* Get Guest ID from current virtualization context */
static inline uint8_t get_current_guest_id(CPULoongArchState *env)
{
    if (is_guest_mode(env)) {
        return get_gid(env);
    }
    return 0; /* Host mode uses GID 0 */
}

/* Check if TLB entry belongs to current guest/host context */
static inline bool tlb_entry_matches_guest(CPULoongArchState *env, LoongArchTLB *tlb)
{
    uint8_t current_gid = get_current_guest_id(env);
    uint8_t entry_gid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, GID);

    return entry_gid == current_gid;
}

/* Check if TLB entry belongs to current guest/host context */
static inline bool tlb_entry_matches_gid(LoongArchTLB *tlb, uint8_t gid)
{
    uint8_t entry_gid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, GID);
    return entry_gid == gid;
}

static void get_dir_base_width(CPULoongArchState *env, uint64_t *dir_base,
                               uint64_t *dir_width, target_ulong level)
{
    uint64_t pwcl, pwch;
    pwcl = GET_CSR(env, PWCL);
    pwch = GET_CSR(env, PWCH);
    switch (level) {
    case 1:
        *dir_base = FIELD_EX64(pwcl, CSR_PWCL, DIR1_BASE);
        *dir_width = FIELD_EX64(pwcl, CSR_PWCL, DIR1_WIDTH);
        break;
    case 2:
        *dir_base = FIELD_EX64(pwcl, CSR_PWCL, DIR2_BASE);
        *dir_width = FIELD_EX64(pwcl, CSR_PWCL, DIR2_WIDTH);
        break;
    case 3:
        *dir_base = FIELD_EX64(pwch, CSR_PWCH, DIR3_BASE);
        *dir_width = FIELD_EX64(pwch, CSR_PWCH, DIR3_WIDTH);
        break;
    case 4:
        *dir_base = FIELD_EX64(pwch, CSR_PWCH, DIR4_BASE);
        *dir_width = FIELD_EX64(pwch, CSR_PWCH, DIR4_WIDTH);
        break;
    default:
        /* level may be zero for ldpte */
        *dir_base = FIELD_EX64(pwcl, CSR_PWCL, PTBASE);
        *dir_width = FIELD_EX64(pwcl, CSR_PWCL, PTWIDTH);
        break;
    }
}

static void raise_mmu_exception(CPULoongArchState *env, target_ulong address,
                                MMUAccessType access_type, int tlb_error)
{
    CPUState *cs = env_cpu(env);
    bool guest = env->guest_mode;

    if (guest && tlb_error > TLBRET_HOST_MATCH) {
        trigger_vm_exit(env);
    }

    switch (tlb_error) {
    default:
    case TLBRET_BADADDR:
    case TLBRET_HOST_BADADDR:
        cs->exception_index = access_type == MMU_INST_FETCH
                              ? EXCCODE_ADEF : EXCCODE_ADEM;
        break;
    case TLBRET_NOMATCH:
    case TLBRET_HOST_NOMATCH:
        /* No TLB match for a mapped address */
        if (access_type == MMU_DATA_LOAD) {
            cs->exception_index = EXCCODE_PIL;
        } else if (access_type == MMU_DATA_STORE) {
            cs->exception_index = EXCCODE_PIS;
        } else if (access_type == MMU_INST_FETCH) {
            cs->exception_index = EXCCODE_PIF;
        }
        SET_CSR(env, TLBRERA, FIELD_DP64(GET_CSR(env, TLBRERA), CSR_TLBRERA, ISTLBR, 1));
        break;
    case TLBRET_INVALID:
    case TLBRET_HOST_INVALID:
        /* TLB match with no valid bit */
        if (access_type == MMU_DATA_LOAD) {
            cs->exception_index = EXCCODE_PIL;
        } else if (access_type == MMU_DATA_STORE) {
            cs->exception_index = EXCCODE_PIS;
        } else if (access_type == MMU_INST_FETCH) {
            cs->exception_index = EXCCODE_PIF;
        }
        break;
    case TLBRET_DIRTY:
    case TLBRET_HOST_DIRTY:
        /* TLB match but 'D' bit is cleared */
        cs->exception_index = EXCCODE_PME;
        break;
    case TLBRET_XI:
    case TLBRET_HOST_XI:
        /* Execute-Inhibit Exception */
        cs->exception_index = EXCCODE_PNX;
        break;
    case TLBRET_RI:
    case TLBRET_HOST_RI:
        /* Read-Inhibit Exception */
        cs->exception_index = EXCCODE_PNR;
        break;
    case TLBRET_PE:
    case TLBRET_HOST_PE:
        /* Privileged Exception */
        cs->exception_index = EXCCODE_PPI;
        break;
    }

    if (tlb_error == TLBRET_NOMATCH
        || tlb_error == TLBRET_HOST_NOMATCH) {
        SET_CSR(env, TLBRBADV, address);
        if (is_la64(env)) {
            SET_CSR(env, TLBREHI, FIELD_DP64(GET_CSR(env, TLBREHI), CSR_TLBREHI_64,
                                          VPPN, extract64(address, 13, 35)));
        } else {
            SET_CSR(env, TLBREHI, FIELD_DP64(GET_CSR(env, TLBREHI), CSR_TLBREHI_32,
                                          VPPN, extract64(address, 13, 19)));
        }
    } else {
        if (!FIELD_EX64(env->CSR_DBG, CSR_DBG, DST)) {
            SET_CSR(env, BADV, address);
        }
        SET_CSR(env, TLBEHI, address & (TARGET_PAGE_MASK << 1));
    }

}

static void invalidate_tlb_entry(CPULoongArchState *env, int index)
{
    target_ulong addr, mask, pagesize;
    uint8_t tlb_ps;
    LoongArchTLB *tlb = env->guest_mode ? &env->gtlb[index] : &env->tlb[index];

    int mmu_idx = cpu_mmu_index(env_cpu(env), false);
    uint8_t tlb_v0 = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, V);
    uint8_t tlb_v1 = FIELD_EX64(tlb->tlb_entry1, TLBENTRY, V);
    uint64_t tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);

    if (index >= LOONGARCH_STLB) {
        tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
    } else {
        tlb_ps = FIELD_EX64(GET_CSR(env, STLBPS), CSR_STLBPS, PS);
    }
    pagesize = MAKE_64BIT_MASK(tlb_ps, 1);
    mask = MAKE_64BIT_MASK(0, tlb_ps + 1);

    if (tlb_v0) {
        addr = (tlb_vppn << R_TLB_MISC_VPPN_SHIFT) & ~mask;    /* even */
        tlb_flush_range_by_mmuidx(env_cpu(env), addr, pagesize,
                                  mmu_idx, TARGET_LONG_BITS);
    }

    if (tlb_v1) {
        addr = (tlb_vppn << R_TLB_MISC_VPPN_SHIFT) & pagesize;    /* odd */
        tlb_flush_range_by_mmuidx(env_cpu(env), addr, pagesize,
                                  mmu_idx, TARGET_LONG_BITS);
    }
}

static void invalidate_tlb(CPULoongArchState *env, int index)
{
    LoongArchTLB *tlb;
    uint16_t csr_asid, tlb_asid, tlb_g;

    csr_asid = FIELD_EX64(GET_CSR(env, ASID), CSR_ASID, ASID);
    tlb = env->guest_mode ? &env->gtlb[index] : &env->tlb[index];
    tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
    tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
    if (tlb_g == 0 && tlb_asid != csr_asid) {
        return;
    }
    invalidate_tlb_entry(env, index);
}

static void fill_tlb_entry(CPULoongArchState *env, int index)
{
    LoongArchTLB *tlb = env->guest_mode ? &env->gtlb[index] : &env->tlb[index];
    uint64_t lo0, lo1, csr_vppn;
    uint16_t csr_asid;
    uint8_t csr_ps;

    if (FIELD_EX64(GET_CSR(env, TLBRERA), CSR_TLBRERA, ISTLBR)) {
        csr_ps = FIELD_EX64(GET_CSR(env, TLBREHI), CSR_TLBREHI, PS);
        if (is_la64(env)) {
            csr_vppn = FIELD_EX64(GET_CSR(env, TLBREHI), CSR_TLBREHI_64, VPPN);
        } else {
            csr_vppn = FIELD_EX64(GET_CSR(env, TLBREHI), CSR_TLBREHI_32, VPPN);
        }
        lo0 = GET_CSR(env, TLBRELO0);
        lo1 = GET_CSR(env, TLBRELO1);
    } else {
        csr_ps = FIELD_EX64(GET_CSR(env, TLBIDX), CSR_TLBIDX, PS);
        if (is_la64(env)) {
            csr_vppn = FIELD_EX64(GET_CSR(env, TLBEHI), CSR_TLBEHI_64, VPPN);
        } else {
            csr_vppn = FIELD_EX64(GET_CSR(env, TLBEHI), CSR_TLBEHI_32, VPPN);
        }
        lo0 = GET_CSR(env, TLBELO0);
        lo1 = GET_CSR(env, TLBELO1);
    }

    if (csr_ps == 0) {
        qemu_log_mask(CPU_LOG_MMU, "page size is 0\n");
    }

    /* Only MTLB has the ps fields */
    if (index >= LOONGARCH_STLB) {
        tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, PS, csr_ps);
    }

    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, VPPN, csr_vppn);
    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 1);
    csr_asid = FIELD_EX64(GET_CSR(env, ASID), CSR_ASID, ASID);
    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, ASID, csr_asid);

    /* Set Guest ID for virtualization support */
    if (has_lvz_capability(env)) {
        uint8_t gid = get_current_guest_id(env);
        tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, GID, gid);
    }

    tlb->tlb_entry0 = lo0;
    tlb->tlb_entry1 = lo1;
}

/* Return an random value between low and high */
static uint32_t get_random_tlb(uint32_t low, uint32_t high)
{
    uint32_t val;

    qemu_guest_getrandom_nofail(&val, sizeof(val));
    return val % (high - low + 1) + low;
}

void helper_tlbsrch(CPULoongArchState *env)
{
    int index, match;
    uint64_t search_ehi;

    if (FIELD_EX64(GET_CSR(env, TLBRERA),
            CSR_TLBRERA, ISTLBR)) {
        search_ehi = GET_CSR(env, TLBREHI);
    } else {
        /* Use effective CSR for virtualization support */
        search_ehi = GET_CSR(env, TLBEHI);
    }

    /* Search only in TLB entries that belong to current guest context */
    match = loongarch_tlb_search(env, search_ehi, &index, env->guest_mode);

    if (match) {
        SET_CSR(env, TLBIDX, FIELD_DP64(GET_CSR(env, TLBIDX), CSR_TLBIDX, INDEX, index));
        SET_CSR(env, TLBIDX, FIELD_DP64(GET_CSR(env, TLBIDX), CSR_TLBIDX, NE, 0));
        return;
    }

    SET_CSR(env, TLBIDX, FIELD_DP64(GET_CSR(env, TLBIDX), CSR_TLBIDX, NE, 1));
}

void helper_tlbrd(CPULoongArchState *env)
{
    LoongArchTLB *tlb;
    int index;
    uint8_t tlb_ps, tlb_e;

    index = FIELD_EX64(GET_CSR(env, TLBIDX), CSR_TLBIDX, INDEX);
    tlb = env->guest_mode ? &env->gtlb[index] : &env->tlb[index];

    /* Check if TLB entry belongs to current guest context */
    if (!tlb_entry_matches_guest(env, tlb)) {
        /* Invalid TLB entry for current guest */
        SET_CSR(env, TLBIDX, FIELD_DP64(GET_CSR(env, TLBIDX), CSR_TLBIDX, NE, 1));
        SET_CSR(env, ASID, FIELD_DP64(GET_CSR(env, ASID), CSR_ASID, ASID, 0));
        SET_CSR(env, TLBEHI, 0);
        SET_CSR(env, TLBELO0, 0);
        SET_CSR(env, TLBELO1, 0);
        SET_CSR(env, TLBIDX, FIELD_DP64(GET_CSR(env, TLBIDX), CSR_TLBIDX, PS, 0));
        return;
    }

    if (index >= LOONGARCH_STLB) {
        tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
    } else {
        tlb_ps = FIELD_EX64(GET_CSR(env, STLBPS), CSR_STLBPS, PS);
    }
    tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);

    if (!tlb_e) {
        /* Invalid TLB entry*/
        SET_CSR(env, TLBIDX, FIELD_DP64(GET_CSR(env, TLBIDX), CSR_TLBIDX, NE, 1));
        SET_CSR(env, ASID, FIELD_DP64(GET_CSR(env, ASID), CSR_ASID, ASID, 0));
        SET_CSR(env, TLBEHI, 0);
        SET_CSR(env, TLBELO0, 0);
        SET_CSR(env, TLBELO1, 0);
        SET_CSR(env, TLBIDX, FIELD_DP64(GET_CSR(env, TLBIDX), CSR_TLBIDX, PS, 0));
    } else {
        /* Valid TLB entry */
        SET_CSR(env, TLBIDX, FIELD_DP64(GET_CSR(env, TLBIDX), CSR_TLBIDX, NE, 0));
        SET_CSR(env, TLBIDX, FIELD_DP64(GET_CSR(env, TLBIDX), CSR_TLBIDX, PS, (tlb_ps & 0x3f)));
        SET_CSR(env, TLBEHI, FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN) << R_TLB_MISC_VPPN_SHIFT);
        SET_CSR(env, TLBELO0, tlb->tlb_entry0);
        SET_CSR(env, TLBELO1, tlb->tlb_entry1);
    }
}

void helper_tlbwr(CPULoongArchState *env)
{
    int index = FIELD_EX64(GET_CSR(env, TLBIDX), CSR_TLBIDX, INDEX);
    LoongArchTLB *tlb = env->guest_mode ? &env->gtlb[index] : &env->tlb[index];

    invalidate_tlb(env, index);

    if (FIELD_EX64(GET_CSR(env, TLBIDX), CSR_TLBIDX, NE)) {
        tlb[index].tlb_misc = FIELD_DP64(tlb[index].tlb_misc,
                                              TLB_MISC, E, 0);
        return;
    }

    fill_tlb_entry(env, index);
}

void helper_tlbfill(CPULoongArchState *env)
{
    uint64_t address, entryhi;
    int index, set, stlb_idx;
    uint16_t pagesize, stlb_ps;

    if (FIELD_EX64(GET_CSR(env, TLBRERA), CSR_TLBRERA, ISTLBR)) {
        entryhi = GET_CSR(env, TLBREHI);
        pagesize = FIELD_EX64(GET_CSR(env, TLBREHI), CSR_TLBREHI, PS);
    } else {
        /* Use effective CSR for virtualization support */
        entryhi = GET_CSR(env, TLBEHI);
        pagesize = FIELD_EX64(GET_CSR(env, TLBIDX), CSR_TLBIDX, PS);
    }

    stlb_ps = FIELD_EX64(env->CSR_STLBPS, CSR_STLBPS, PS);

    if (pagesize == stlb_ps) {
        /* Only write into STLB bits [47:13] */
        address = entryhi & ~MAKE_64BIT_MASK(0, R_CSR_TLBEHI_64_VPPN_SHIFT);

        /* Choose one set ramdomly */
        set = get_random_tlb(0, 7);

        /* Index in one set */
        stlb_idx = (address >> (stlb_ps + 1)) & 0xff; /* [0,255] */

        index = set * 256 + stlb_idx;
    } else {
        /* Only write into MTLB */
        index = get_random_tlb(LOONGARCH_STLB, LOONGARCH_TLB_MAX - 1);
    }

    invalidate_tlb(env, index);
    fill_tlb_entry(env, index);
}

void helper_tlbclr(CPULoongArchState *env)
{
    LoongArchTLB *tlb;
    int i, index;
    uint16_t csr_asid, tlb_asid, tlb_g;

    /* Use effective CSR for virtualization support */
    csr_asid = FIELD_EX64(GET_CSR(env, ASID), CSR_ASID, ASID);
    index = FIELD_EX64(GET_CSR(env, TLBIDX), CSR_TLBIDX, INDEX);

    if (index < LOONGARCH_STLB) {
        /* STLB. One line per operation */
        for (i = 0; i < 8; i++) {
            tlb = env->guest_mode ? &env->gtlb[i * 256 + (index % 256)] : &env->tlb[i * 256 + (index % 256)];

            /* Only clear entries belonging to current guest */
            if (!tlb_entry_matches_guest(env, tlb)) {
                continue;
            }

            tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
            tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
            if (!tlb_g && tlb_asid == csr_asid) {
                tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
            }
        }
    } else if (index < LOONGARCH_TLB_MAX) {
        /* All MTLB entries */
        for (i = LOONGARCH_STLB; i < LOONGARCH_TLB_MAX; i++) {
            tlb = env->guest_mode ? &env->gtlb[i] : &env->tlb[i];

            /* Only clear entries belonging to current guest */
            if (!tlb_entry_matches_guest(env, tlb)) {
                continue;
            }

            tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
            tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
            if (!tlb_g && tlb_asid == csr_asid) {
                tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
            }
        }
    }

    tlb_flush(env_cpu(env));
}

void helper_tlbflush(CPULoongArchState *env)
{
    int i, index;

    index = FIELD_EX64(GET_CSR(env, TLBIDX), CSR_TLBIDX, INDEX);
    LoongArchTLB *tlb;

    if (index < LOONGARCH_STLB) {
        /* STLB. One line per operation */
        for (i = 0; i < 8; i++) {
            int s_idx = i * 256 + (index % 256);
            tlb = env->guest_mode ? &env->gtlb[s_idx] : &env->tlb[s_idx];

            /* Only flush entries belonging to current guest */
            if (tlb_entry_matches_guest(env, tlb)) {
                tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc,
                                                      TLB_MISC, E, 0);
            }
        }
    } else if (index < LOONGARCH_TLB_MAX) {
        /* All MTLB entries */
        for (i = LOONGARCH_STLB; i < LOONGARCH_TLB_MAX; i++) {
            tlb = env->guest_mode ? &env->gtlb[i] : &env->tlb[i];
            /* Only flush entries belonging to current guest */
            if (tlb_entry_matches_guest(env, tlb)) {
                tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc,
                                                  TLB_MISC, E, 0);
            }
        }
    }

    tlb_flush(env_cpu(env));
}

void helper_invtlb_all(CPULoongArchState *env, uint32_t hostonly)
{
    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        /* Only invalidate entries belonging to current guest */
        if (is_guest_mode(env)) {
            if (tlb_entry_matches_guest(env, &env->gtlb[i])) {
                env->gtlb[i].tlb_misc = FIELD_DP64(env->gtlb[i].tlb_misc,
                                              TLB_MISC, E, 0);
            }
        } else {
            env->tlb[i].tlb_misc = FIELD_DP64(env->tlb[i].tlb_misc,
                                            TLB_MISC, E, 0);
            if (hostonly == 0) {
                env->gtlb[i].tlb_misc = FIELD_DP64(env->gtlb[i].tlb_misc,
                                                   TLB_MISC, E, 0);
            }
        }
    }
    tlb_flush(env_cpu(env));
}

void helper_invtlb_all_gid(CPULoongArchState *env, target_ulong info)
{
    if (is_guest_mode(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
    }
    uint16_t gid = (info >> 16) & 0xff;
    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        if (tlb_entry_matches_gid(&env->gtlb[i], gid)) {
            env->gtlb[i].tlb_misc = FIELD_DP64(env->gtlb[i].tlb_misc,
                                              TLB_MISC, E, 0);
        }
    }
    tlb_flush(env_cpu(env));
}

void helper_invtlb_all_g(CPULoongArchState *env, uint32_t g)
{
    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        LoongArchTLB *tlb = env->guest_mode ? &env->gtlb[i] : &env->tlb[i];
        uint8_t tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);

        /* Only invalidate entries belonging to current guest with matching G bit */
        if (tlb_g == g && tlb_entry_matches_guest(env, tlb)) {
            tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
        }
    }
    tlb_flush(env_cpu(env));
}

void helper_invtlb_all_g_gid(CPULoongArchState *env, uint32_t g, target_ulong info)
{
    if (is_guest_mode(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
    }
    uint16_t gid = (info >> 16) & 0xff;

    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        LoongArchTLB *tlb = &env->gtlb[i];
        uint8_t tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);

        if (tlb_g == g && tlb_entry_matches_gid(tlb, gid)) {
            tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
        }
    }
    tlb_flush(env_cpu(env));
}

void helper_invtlb_all_asid(CPULoongArchState *env, target_ulong info)
{
    uint16_t asid = info & R_CSR_ASID_ASID_MASK;

    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        LoongArchTLB *tlb = env->guest_mode ? &env->gtlb[i] : &env->tlb[i];
        uint8_t tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
        uint16_t tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);

        /* Only invalidate entries belonging to current guest with matching ASID */
        if (!tlb_g && (tlb_asid == asid) && tlb_entry_matches_guest(env, tlb)) {
            tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
        }
    }
    tlb_flush(env_cpu(env));
}

void helper_invtlb_all_asid_gid(CPULoongArchState *env, target_ulong info)
{
    if (is_guest_mode(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
    }
    uint16_t asid = info & R_CSR_ASID_ASID_MASK;
    uint16_t gid = (info >> 16) & 0xff;

    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        LoongArchTLB *tlb = &env->gtlb[i];
        uint8_t tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
        uint16_t tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);

        if (!tlb_g && (tlb_asid == asid)  && tlb_entry_matches_gid(tlb, gid)) {
            tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
        }
    }
    tlb_flush(env_cpu(env));
}

void helper_invtlb_page_asid(CPULoongArchState *env, target_ulong info,
                             target_ulong addr)
{
    uint16_t asid = info & 0x3ff;

    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        LoongArchTLB *tlb = env->guest_mode ? &env->gtlb[i] : &env->tlb[i];
        uint8_t tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
        uint16_t tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
        uint64_t vpn, tlb_vppn;
        uint8_t tlb_ps, compare_shift;

        /* Only check entries belonging to current guest */
        if (!tlb_entry_matches_guest(env, tlb)) {
            continue;
        }

        if (i >= LOONGARCH_STLB) {
            tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
        } else {
            tlb_ps = FIELD_EX64(GET_CSR(env, STLBPS), CSR_STLBPS, PS);
        }
        tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
        vpn = (addr & TARGET_VIRT_MASK) >> (tlb_ps + 1);
        compare_shift = tlb_ps + 1 - R_TLB_MISC_VPPN_SHIFT;

        if (!tlb_g && (tlb_asid == asid) &&
           (vpn == (tlb_vppn >> compare_shift))) {
            tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
        }
    }
    tlb_flush(env_cpu(env));
}

void helper_invtlb_page_asid_gid(CPULoongArchState *env, target_ulong info,
                             target_ulong addr)
{
    if (is_guest_mode(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
    }
    uint16_t asid = info & 0x3ff;
    uint16_t gid = (info >> 16) & 0xff;

    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        LoongArchTLB *tlb = &env->gtlb[i];
        uint8_t tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
        uint16_t tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
        uint64_t vpn, tlb_vppn;
        uint8_t tlb_ps, compare_shift;

        if (!tlb_entry_matches_gid(tlb, gid)) {
            continue;
        }

        if (i >= LOONGARCH_STLB) {
            tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
        } else {
            tlb_ps = FIELD_EX64(env->GCSR_STLBPS, CSR_STLBPS, PS);
        }
        tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
        vpn = (addr & TARGET_VIRT_MASK) >> (tlb_ps + 1);
        compare_shift = tlb_ps + 1 - R_TLB_MISC_VPPN_SHIFT;

        if (!tlb_g && (tlb_asid == asid) &&
            (vpn == (tlb_vppn >> compare_shift))) {
            tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
            }
    }
    tlb_flush(env_cpu(env));
}

void helper_invtlb_page_asid_or_g(CPULoongArchState *env,
                                  target_ulong info, target_ulong addr)
{
    uint16_t asid = info & 0x3ff;

    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        LoongArchTLB *tlb = env->guest_mode ? &env->gtlb[i] : &env->tlb[i];
        uint8_t tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
        uint16_t tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
        uint64_t vpn, tlb_vppn;
        uint8_t tlb_ps, compare_shift;

        /* Only check entries belonging to current guest */
        if (!tlb_entry_matches_guest(env, tlb)) {
            continue;
        }

        if (i >= LOONGARCH_STLB) {
            tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
        } else {
            tlb_ps = FIELD_EX64(GET_CSR(env, STLBPS), CSR_STLBPS, PS);
        }
        tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
        vpn = (addr & TARGET_VIRT_MASK) >> (tlb_ps + 1);
        compare_shift = tlb_ps + 1 - R_TLB_MISC_VPPN_SHIFT;

        if ((tlb_g || (tlb_asid == asid)) &&
            (vpn == (tlb_vppn >> compare_shift))) {
            tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
        }
    }
    tlb_flush(env_cpu(env));
}

void helper_invtlb_page_asid_or_g_gid(CPULoongArchState *env,
                                  target_ulong info, target_ulong addr)
{
    if (is_guest_mode(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
    }
    uint16_t asid = info & 0x3ff;
    uint16_t gid = (info >> 16) & 0xff;

    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        LoongArchTLB *tlb = &env->gtlb[i];
        uint8_t tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
        uint16_t tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
        uint64_t vpn, tlb_vppn;
        uint8_t tlb_ps, compare_shift;

        if (!tlb_entry_matches_gid(tlb, gid)) {
            continue;
        }

        if (i >= LOONGARCH_STLB) {
            tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
        } else {
            tlb_ps = FIELD_EX64(env->GCSR_STLBPS, CSR_STLBPS, PS);
        }
        tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
        vpn = (addr & TARGET_VIRT_MASK) >> (tlb_ps + 1);
        compare_shift = tlb_ps + 1 - R_TLB_MISC_VPPN_SHIFT;

        if ((tlb_g || (tlb_asid == asid)) &&
            (vpn == (tlb_vppn >> compare_shift))) {
            tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
            }
    }
    tlb_flush(env_cpu(env));
}

bool loongarch_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                            MMUAccessType access_type, int mmu_idx,
                            bool probe, uintptr_t retaddr)
{
    CPULoongArchState *env = cpu_env(cs);
    hwaddr physical;
    int prot;
    int ret;

    /* Data access */
    ret = get_physical_address(env, &physical, &prot, address,
                               access_type, mmu_idx);

    if (ret == TLBRET_MATCH || ret == TLBRET_HOST_MATCH) {
        tlb_set_page(cs, address & TARGET_PAGE_MASK,
                     physical & TARGET_PAGE_MASK, prot,
                     mmu_idx, TARGET_PAGE_SIZE);
        qemu_log_mask(CPU_LOG_MMU,
                      "%s address=%" VADDR_PRIx " physical " HWADDR_FMT_plx
                      " prot %d\n", __func__, address, physical, prot);
        return true;
    } else {
        qemu_log_mask(CPU_LOG_MMU,
                      "%s address=%" VADDR_PRIx " ret %d\n", __func__, address,
                      ret);
    }
    if (probe) {
        return false;
    }
    raise_mmu_exception(env, address, access_type, ret);
    cpu_loop_exit_restore(cs, retaddr);
}

target_ulong helper_lddir(CPULoongArchState *env, target_ulong base,
                          target_ulong level, uint32_t mem_idx)
{
    CPUState *cs = env_cpu(env);
    target_ulong badvaddr, index, phys, ret;
    int shift;
    uint64_t dir_base, dir_width;

    if (unlikely((level == 0) || (level > 4))) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "Attepted LDDIR with level %"PRId64"\n", level);
        return base;
    }

    if (FIELD_EX64(base, TLBENTRY, HUGE)) {
        if (unlikely(level == 4)) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "Attempted use of level 4 huge page\n");
        }

        if (FIELD_EX64(base, TLBENTRY, LEVEL)) {
            return base;
        } else {
            return FIELD_DP64(base, TLBENTRY, LEVEL, level);
        }
    }

    badvaddr = GET_CSR(env, TLBRBADV);
    base = base & TARGET_PHYS_MASK;

    /* 0:64bit, 1:128bit, 2:192bit, 3:256bit */
    shift = FIELD_EX64(GET_CSR(env, PWCL), CSR_PWCL, PTEWIDTH);
    shift = (shift + 1) * 3;

    get_dir_base_width(env, &dir_base, &dir_width, level);
    index = (badvaddr >> dir_base) & ((1 << dir_width) - 1);
    phys = base | index << shift;
    ret = ldq_phys(cs->as, phys) & TARGET_PHYS_MASK;
    return ret;
}

void helper_ldpte(CPULoongArchState *env, target_ulong base, target_ulong odd,
                  uint32_t mem_idx)
{
    CPUState *cs = env_cpu(env);
    target_ulong phys, tmp0, ptindex, ptoffset0, ptoffset1, ps, badv;
    int shift;
    uint64_t ptbase = FIELD_EX64(env->CSR_PWCL, CSR_PWCL, PTBASE);
    uint64_t ptwidth = FIELD_EX64(env->CSR_PWCL, CSR_PWCL, PTWIDTH);
    uint64_t dir_base, dir_width;

    /*
     * The parameter "base" has only two types,
     * one is the page table base address,
     * whose bit 6 should be 0,
     * and the other is the huge page entry,
     * whose bit 6 should be 1.
     */
    base = base & TARGET_PHYS_MASK;
    if (FIELD_EX64(base, TLBENTRY, HUGE)) {
        /*
         * Gets the huge page level and Gets huge page size.
         * Clears the huge page level information in the entry.
         * Clears huge page bit.
         * Move HGLOBAL bit to GLOBAL bit.
         */
        get_dir_base_width(env, &dir_base, &dir_width,
                           FIELD_EX64(base, TLBENTRY, LEVEL));

        base = FIELD_DP64(base, TLBENTRY, LEVEL, 0);
        base = FIELD_DP64(base, TLBENTRY, HUGE, 0);
        if (FIELD_EX64(base, TLBENTRY, HGLOBAL)) {
            base = FIELD_DP64(base, TLBENTRY, HGLOBAL, 0);
            base = FIELD_DP64(base, TLBENTRY, G, 1);
        }

        ps = dir_base + dir_width - 1;
        /*
         * Huge pages are evenly split into parity pages
         * when loaded into the tlb,
         * so the tlb page size needs to be divided by 2.
         */
        tmp0 = base;
        if (odd) {
            tmp0 += MAKE_64BIT_MASK(ps, 1);
        }
    } else {
        /* 0:64bit, 1:128bit, 2:192bit, 3:256bit */
        shift = FIELD_EX64(GET_CSR(env, PWCL), CSR_PWCL, PTEWIDTH);
        shift = (shift + 1) * 3;
        badv = GET_CSR(env, TLBRBADV);

        ptindex = (badv >> ptbase) & ((1 << ptwidth) - 1);
        ptindex = ptindex & ~0x1;   /* clear bit 0 */
        ptoffset0 = ptindex << shift;
        ptoffset1 = (ptindex + 1) << shift;

        phys = base | (odd ? ptoffset1 : ptoffset0);
        tmp0 = ldq_phys(cs->as, phys) & TARGET_PHYS_MASK;
        ps = ptbase;
    }

    if (odd) {
        SET_CSR(env, TLBRELO1, tmp0);
    } else {
        SET_CSR(env, TLBRELO0, tmp0);
    }
    SET_CSR(env, TLBREHI, FIELD_DP64(env->CSR_TLBREHI, CSR_TLBREHI, PS, ps));
}
