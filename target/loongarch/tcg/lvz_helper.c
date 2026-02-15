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
    trigger_vm_exit(env);
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
    trigger_vm_exit(env);
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
    uint8_t gid = get_gid(env);
    
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
    
    uint8_t gid = get_gid(env);
    
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
    
    uint8_t gid = get_gid(env);
    
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
    
    uint8_t gid = get_gid(env);
    
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
    trigger_vm_exit(env);
    do_raise_exception(env, EXCCODE_HVC, GETPC());
}


