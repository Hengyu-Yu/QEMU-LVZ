/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LoongArch emulation helpers for LVZ (Virtualization) instructions
 *
 * Copyright (c) 2024 Loongson Technology Corporation Limited
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "internals.h"
#include "qemu/host-utils.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "exec/tlb-common.h"
#include "hw/irq.h"
#include "cpu-csr.h"
#include "qemu/guest-random.h"

/* Helper function to get guest CSR pointer */
static uint64_t *get_guest_csr_ptr(CPULoongArchState *env, uint32_t csr)
{
    switch (csr) {
    case LOONGARCH_GCSR_CRMD:
        return &env->GCSR_CRMD;
    case LOONGARCH_GCSR_PRMD:
        return &env->GCSR_PRMD;
    case LOONGARCH_GCSR_EUEN:
        return &env->GCSR_EUEN;
    case LOONGARCH_GCSR_MISC:
        return &env->GCSR_MISC;
    case LOONGARCH_GCSR_ECFG:
        return &env->GCSR_ECFG;
    case LOONGARCH_GCSR_ESTAT:
        return &env->GCSR_ESTAT;
    case LOONGARCH_GCSR_ERA:
        return &env->GCSR_ERA;
    case LOONGARCH_GCSR_BADV:
        return &env->GCSR_BADV;
    case LOONGARCH_GCSR_BADI:
        return &env->GCSR_BADI;
    case LOONGARCH_GCSR_EENTRY:
        return &env->GCSR_EENTRY;
    case LOONGARCH_GCSR_TLBIDX:
        return &env->GCSR_TLBIDX;
    case LOONGARCH_GCSR_TLBEHI:
        return &env->GCSR_TLBEHI;
    case LOONGARCH_GCSR_TLBELO0:
        return &env->GCSR_TLBELO0;
    case LOONGARCH_GCSR_TLBELO1:
        return &env->GCSR_TLBELO1;
    case LOONGARCH_GCSR_ASID:
        return &env->GCSR_ASID;
    case LOONGARCH_GCSR_PGDL:
        return &env->GCSR_PGDL;
    case LOONGARCH_GCSR_PGDH:
        return &env->GCSR_PGDH;
    case LOONGARCH_GCSR_PGD:
        return &env->GCSR_PGD;
    case LOONGARCH_GCSR_PWCL:
        return &env->GCSR_PWCL;
    case LOONGARCH_GCSR_PWCH:
        return &env->GCSR_PWCH;
    case LOONGARCH_GCSR_STLBPS:
        return &env->GCSR_STLBPS;
    case LOONGARCH_GCSR_RVACFG:
        return &env->GCSR_RVACFG;
    case LOONGARCH_GCSR_CPUID:
        return &env->GCSR_CPUID;
    case LOONGARCH_GCSR_PRCFG1:
        return &env->GCSR_PRCFG1;
    case LOONGARCH_GCSR_PRCFG2:
        return &env->GCSR_PRCFG2;
    case LOONGARCH_GCSR_PRCFG3:
        return &env->GCSR_PRCFG3;
    case LOONGARCH_GCSR_TID:
        return &env->GCSR_TID;
    case LOONGARCH_GCSR_TCFG:
        return &env->GCSR_TCFG;
    case LOONGARCH_GCSR_TVAL:
        return &env->GCSR_TVAL;
    case LOONGARCH_GCSR_CNTC:
        return &env->GCSR_CNTC;
    case LOONGARCH_GCSR_TICLR:
        return &env->GCSR_TICLR;
    case LOONGARCH_GCSR_LLBCTL:
        return &env->GCSR_LLBCTL;
    case LOONGARCH_GCSR_IMPCTL1:
        return &env->GCSR_IMPCTL1;
    case LOONGARCH_GCSR_IMPCTL2:
        return &env->GCSR_IMPCTL2;
    case LOONGARCH_GCSR_TLBRENTRY:
        return &env->GCSR_TLBRENTRY;
    case LOONGARCH_GCSR_TLBRBADV:
        return &env->GCSR_TLBRBADV;
    case LOONGARCH_GCSR_TLBRERA:
        return &env->GCSR_TLBRERA;
    case LOONGARCH_GCSR_TLBRSAVE:
        return &env->GCSR_TLBRSAVE;
    default:
        /* Handle GCSR_SAVE[0-15] */
        if (csr >= LOONGARCH_GCSR_SAVE(0) && csr <= LOONGARCH_GCSR_SAVE(15)) {
            int index = csr - LOONGARCH_GCSR_SAVE(0);
            return &env->GCSR_SAVE[index];
        }
        return NULL;
    }
}

/* Helper function to trigger VM exit */
static void trigger_vm_exit(CPULoongArchState *env, uint32_t reason, target_ulong info)
{
    /* Set VM exit reason in GSTAT register */
    env->CSR_GSTAT = FIELD_DP64(env->CSR_GSTAT, CSR_GSTAT, VM, 0);
    
    /* Store exit reason and info for hypervisor */
    /* In a full implementation, this would store reason and info 
     * in appropriate guest state registers */
    
    /* Generate a hypervisor exception to exit to hypervisor */
    do_raise_exception(env, EXCCODE_HVC, GETPC());
}

/* Guest CSR read helper */
target_ulong helper_gcsrrd(CPULoongArchState *env, uint32_t csr)
{
    /* Check if we're in guest mode */
    if (!is_guest_mode(env)) {
        /* If not in guest mode, this should cause an exception */
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return 0;
    }
    
    uint64_t *csr_ptr = get_guest_csr_ptr(env, csr);
    if (csr_ptr == NULL) {
        /* Invalid CSR number, trigger VM exit */
        trigger_vm_exit(env, VMEXIT_CSRR, csr);
        return 0;
    }
    
    /* Some CSRs might need special handling or VM exit */
    switch (csr) {
    case LOONGARCH_GCSR_ESTAT:
        /* Check guest interrupt configuration */
        if (!(env->CSR_GCFG & (1 << 6))) { /* SITP bit */
            trigger_vm_exit(env, VMEXIT_CSRR, csr);
            return 0;
        }
        break;
    case LOONGARCH_GCSR_TCFG:
    case LOONGARCH_GCSR_TVAL:
        /* Timer access might need VM exit depending on guest config */
        if (!(env->CSR_GCFG & (1 << 8))) { /* TITP bit */
            trigger_vm_exit(env, VMEXIT_TIMER, csr);
            return 0;
        }
        break;
    }
    
    return *csr_ptr;
}

/* Guest CSR write helper */
target_ulong helper_gcsrwr(CPULoongArchState *env, target_ulong val, uint32_t csr)
{
    /* Check if we're in guest mode */
    if (!is_guest_mode(env)) {
        /* If not in guest mode, this should cause an exception */
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return 0;
    }
    
    uint64_t *csr_ptr = get_guest_csr_ptr(env, csr);
    if (csr_ptr == NULL) {
        /* Invalid CSR number, trigger VM exit */
        trigger_vm_exit(env, VMEXIT_CSRW, csr);
        return 0;
    }
    
    target_ulong old_val = *csr_ptr;
    
    /* Some CSRs might need special handling or VM exit */
    switch (csr) {
    case LOONGARCH_GCSR_ESTAT:
        /* Check guest interrupt configuration */
        if (!(env->CSR_GCFG & (1 << 7))) { /* SITO bit */
            trigger_vm_exit(env, VMEXIT_CSRW, csr);
            return old_val;
        }
        break;
    case LOONGARCH_GCSR_TCFG:
        /* Timer config might need VM exit depending on guest config */
        if (!(env->CSR_GCFG & (1 << 9))) { /* TITO bit */
            trigger_vm_exit(env, VMEXIT_TIMER, csr);
            return old_val;
        }
        break;
    case LOONGARCH_GCSR_TICLR:
        /* Timer clear always needs special handling */
        trigger_vm_exit(env, VMEXIT_TIMER, csr);
        return old_val;
    }
    
    *csr_ptr = val;
    return old_val;
}

/* Guest CSR exchange helper */
target_ulong helper_gcsrxchg(CPULoongArchState *env, target_ulong rj, target_ulong rd, uint32_t csr)
{
    /* Check if we're in guest mode */
    if (!is_guest_mode(env)) {
        /* If not in guest mode, this should cause an exception */
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return 0;
    }
    
    uint64_t *csr_ptr = get_guest_csr_ptr(env, csr);
    if (csr_ptr == NULL) {
        /* Invalid CSR number, trigger VM exit */
        trigger_vm_exit(env, VMEXIT_CSRX, csr);
        return 0;
    }
    
    target_ulong old_val = *csr_ptr;
    target_ulong new_val = (old_val & ~rd) | (rj & rd);
    
    /* Some CSRs might need special handling or VM exit */
    switch (csr) {
    case LOONGARCH_GCSR_ESTAT:
        /* Check guest interrupt configuration */
        if (!(env->CSR_GCFG & (1 << 7))) { /* SITO bit */
            trigger_vm_exit(env, VMEXIT_CSRX, csr);
            return old_val;
        }
        break;
    case LOONGARCH_GCSR_TCFG:
        /* Timer config might need VM exit */
        if (!(env->CSR_GCFG & (1 << 9))) { /* TITO bit */
            trigger_vm_exit(env, VMEXIT_TIMER, csr);
            return old_val;
        }
        break;
    }
    
    *csr_ptr = new_val;
    return old_val;
}

/* Guest TLB clear helper */
void helper_gtlbclr(CPULoongArchState *env)
{
    /* Check if we're in guest mode */
    if (!is_guest_mode(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return;
    }
    
    /* Check if LVZ capability is available */
    if (!has_lvz_capability(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return;
    }
    
    /* In guest mode, TLB operations may need VM exit */
    trigger_vm_exit(env, VMEXIT_TLB, 0);
}

/* Guest TLB flush helper */
void helper_gtlbflush(CPULoongArchState *env)
{
    /* Check if we're in guest mode */
    if (!is_guest_mode(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return;
    }
    
    /* Check if LVZ capability is available */
    if (!has_lvz_capability(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return;
    }
    
    /* In guest mode, TLB operations may need VM exit */
    trigger_vm_exit(env, VMEXIT_TLB, 1);
}

/* Guest TLB search helper */
void helper_gtlbsrch(CPULoongArchState *env)
{
    /* Check if we're in guest mode */
    if (!is_guest_mode(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return;
    }
    
    /* Check if LVZ capability is available */
    if (!has_lvz_capability(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return;
    }
    
    /* Get guest TLB search parameters from guest CSRs */
    uint64_t ehi = env->GCSR_TLBEHI;
    uint64_t asid = env->GCSR_ASID;
    uint8_t gid = get_guest_id(env);
    
    /* Search in guest TLB entries */
    /* This is a simplified implementation - in practice, you'd search
     * through hardware TLB entries with matching GID, VPPN and ASID */
    int found_index = -1;
    uint64_t vppn = ehi >> 13;
    uint64_t guest_asid = FIELD_EX64(asid, CSR_ASID, ASID);
    
    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        /* Check if TLB entry matches guest criteria */
        if (env->tlb[i].tlb_misc & (1ULL << 54)) { /* Entry has GID */
            uint8_t entry_gid = FIELD_EX64(env->tlb[i].tlb_misc, TLB_MISC, GID);
            uint64_t entry_vppn = FIELD_EX64(env->tlb[i].tlb_misc, TLB_MISC, VPPN);
            uint64_t entry_asid = FIELD_EX64(env->tlb[i].tlb_misc, TLB_MISC, ASID);
            
            if (entry_gid == gid && entry_vppn == vppn && entry_asid == guest_asid) {
                found_index = i;
                break;
            }
        }
    }
    
    /* Update guest TLBIDX with search result */
    if (found_index >= 0) {
        env->GCSR_TLBIDX = FIELD_DP64(env->GCSR_TLBIDX, CSR_TLBIDX, INDEX, found_index);
        env->GCSR_TLBIDX = FIELD_DP64(env->GCSR_TLBIDX, CSR_TLBIDX, NE, 0);
    } else {
        env->GCSR_TLBIDX = FIELD_DP64(env->GCSR_TLBIDX, CSR_TLBIDX, NE, 1);
    }
}

/* Guest TLB read helper */
void helper_gtlbrd(CPULoongArchState *env)
{
    /* Check if we're in guest mode */
    if (!is_guest_mode(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return;
    }
    
    /* Check if LVZ capability is available */
    if (!has_lvz_capability(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return;
    }
    
    uint32_t index = FIELD_EX64(env->GCSR_TLBIDX, CSR_TLBIDX, INDEX);
    if (index >= LOONGARCH_TLB_MAX) {
        return;
    }
    
    uint8_t gid = get_guest_id(env);
    
    /* Check if the TLB entry belongs to this guest */
    if (env->tlb[index].tlb_misc & (1ULL << 54)) { /* Entry has GID */
        uint8_t entry_gid = FIELD_EX64(env->tlb[index].tlb_misc, TLB_MISC, GID);
        if (entry_gid == gid) {
            /* Read TLB entry into guest CSRs */
            env->GCSR_TLBEHI = FIELD_EX64(env->tlb[index].tlb_misc, TLB_MISC, VPPN) << 13;
            env->GCSR_TLBELO0 = env->tlb[index].tlb_entry0;
            env->GCSR_TLBELO1 = env->tlb[index].tlb_entry1;
            env->GCSR_ASID = FIELD_EX64(env->tlb[index].tlb_misc, TLB_MISC, ASID);
        }
    }
}

/* Guest TLB write helper */
void helper_gtlbwr(CPULoongArchState *env)
{
    /* Check if we're in guest mode */
    if (!is_guest_mode(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return;
    }
    
    /* Check if LVZ capability is available */
    if (!has_lvz_capability(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return;
    }
    
    uint32_t index = FIELD_EX64(env->GCSR_TLBIDX, CSR_TLBIDX, INDEX);
    if (index >= LOONGARCH_TLB_MAX) {
        return;
    }
    
    uint8_t gid = get_guest_id(env);
    
    /* Write guest CSR values to TLB entry with guest ID */
    env->tlb[index].tlb_misc = 0;
    env->tlb[index].tlb_misc = FIELD_DP64(env->tlb[index].tlb_misc, TLB_MISC, VPPN, 
                                         env->GCSR_TLBEHI >> 13);
    env->tlb[index].tlb_misc = FIELD_DP64(env->tlb[index].tlb_misc, TLB_MISC, ASID, 
                                         FIELD_EX64(env->GCSR_ASID, CSR_ASID, ASID));
    env->tlb[index].tlb_misc = FIELD_DP64(env->tlb[index].tlb_misc, TLB_MISC, GID, gid);
    env->tlb[index].tlb_misc = FIELD_DP64(env->tlb[index].tlb_misc, TLB_MISC, PS, 
                                         FIELD_EX64(env->GCSR_TLBIDX, CSR_TLBIDX, PS));
    env->tlb[index].tlb_misc = FIELD_DP64(env->tlb[index].tlb_misc, TLB_MISC, E, 1);
    
    env->tlb[index].tlb_entry0 = env->GCSR_TLBELO0;
    env->tlb[index].tlb_entry1 = env->GCSR_TLBELO1;
    
    /* Invalidate any cached translations */
    tlb_flush(env_cpu(env));
}

/* Guest TLB fill helper */
void helper_gtlbfill(CPULoongArchState *env)
{
    /* Check if we're in guest mode */
    if (!is_guest_mode(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return;
    }
    
    /* Check if LVZ capability is available */
    if (!has_lvz_capability(env)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
        return;
    }
    
    /* TLBFILL uses a random index in the STLB range */
    uint32_t random_index;
    qemu_guest_getrandom_nofail(&random_index, sizeof(uint32_t));
    random_index = random_index % LOONGARCH_STLB; /* Use STLB range only */
    
    uint8_t gid = get_guest_id(env);
    
    /* Fill TLB entry at random index */
    env->tlb[random_index].tlb_misc = 0;
    env->tlb[random_index].tlb_misc = FIELD_DP64(env->tlb[random_index].tlb_misc, TLB_MISC, VPPN,
                                                 env->GCSR_TLBEHI >> 13);
    env->tlb[random_index].tlb_misc = FIELD_DP64(env->tlb[random_index].tlb_misc, TLB_MISC, ASID,
                                                 FIELD_EX64(env->GCSR_ASID, CSR_ASID, ASID));
    env->tlb[random_index].tlb_misc = FIELD_DP64(env->tlb[random_index].tlb_misc, TLB_MISC, GID, gid);
    env->tlb[random_index].tlb_misc = FIELD_DP64(env->tlb[random_index].tlb_misc, TLB_MISC, PS,
                                                 FIELD_EX64(env->GCSR_TLBIDX, CSR_TLBIDX, PS));
    env->tlb[random_index].tlb_misc = FIELD_DP64(env->tlb[random_index].tlb_misc, TLB_MISC, E, 1);
    
    env->tlb[random_index].tlb_entry0 = env->GCSR_TLBELO0;
    env->tlb[random_index].tlb_entry1 = env->GCSR_TLBELO1;
    
    /* Update guest TLBIDX to reflect the filled index */
    env->GCSR_TLBIDX = FIELD_DP64(env->GCSR_TLBIDX, CSR_TLBIDX, INDEX, random_index);
    
    /* Invalidate any cached translations */
    tlb_flush(env_cpu(env));
}

/* Hypervisor call helper */
void helper_hvcl(CPULoongArchState *env, uint32_t code)
{
    /* Check if we're in guest mode */
    if (!is_guest_mode(env)) {
        /* HVCL from host mode should be treated as illegal instruction */
        do_raise_exception(env, EXCCODE_INE, GETPC());
        return;
    }
    
    /* Check if LVZ capability is available */
    if (!has_lvz_capability(env)) {
        do_raise_exception(env, EXCCODE_INE, GETPC());
        return;
    }
    
    /* Store the hypercall code for the hypervisor */
    /* In a real implementation, this might be stored in a specific register
     * or memory location that the hypervisor can access */
    
    /* HVCL instruction causes a VM exit to hypervisor with hypercall reason */
    trigger_vm_exit(env, VMEXIT_HYPERCALL, code);
}


