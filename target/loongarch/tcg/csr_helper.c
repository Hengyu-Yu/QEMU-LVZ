/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LoongArch emulation helpers for CSRs
 *
 * Copyright (c) 2021 Loongson Technology Corporation Limited
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "internals.h"
#include "qemu/host-utils.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "hw/irq.h"
#include "cpu-csr.h"

target_ulong helper_csrrd_pgd(CPULoongArchState *env)
{
    int64_t v;

    if (env->CSR_TLBRERA & 0x1) {
        v = env->CSR_TLBRBADV;
    } else {
        v = env->CSR_BADV;
    }

    if ((v >> 63) & 0x1) {
        v = env->CSR_PGDH;
    } else {
        v = env->CSR_PGDL;
    }

    return v;
}

target_ulong helper_csrrd_cpuid(CPULoongArchState *env)
{
    LoongArchCPU *lac = env_archcpu(env);

    env->CSR_CPUID = CPU(lac)->cpu_index;

    return env->CSR_CPUID;
}

target_ulong helper_csrrd_tval(CPULoongArchState *env)
{
    LoongArchCPU *cpu = env_archcpu(env);

    return cpu_loongarch_get_constant_timer_ticks(cpu);
}

target_ulong helper_csrwr_estat(CPULoongArchState *env, target_ulong val)
{
    int64_t old_v = env->CSR_ESTAT;

    /* Only IS[1:0] can be written */
    env->CSR_ESTAT = deposit64(env->CSR_ESTAT, 0, 2, val);

    return old_v;
}

target_ulong helper_csrwr_asid(CPULoongArchState *env, target_ulong val)
{
    int64_t old_v = env->CSR_ASID;

    /* Only ASID filed of CSR_ASID can be written */
    env->CSR_ASID = deposit64(env->CSR_ASID, 0, 10, val);
    if (old_v != env->CSR_ASID) {
        tlb_flush(env_cpu(env));
    }
    return old_v;
}

target_ulong helper_csrwr_tcfg(CPULoongArchState *env, target_ulong val)
{
    LoongArchCPU *cpu = env_archcpu(env);
    int64_t old_v = env->CSR_TCFG;

    cpu_loongarch_store_constant_timer_config(cpu, val);

    return old_v;
}

target_ulong helper_csrwr_ticlr(CPULoongArchState *env, target_ulong val)
{
    LoongArchCPU *cpu = env_archcpu(env);
    int64_t old_v = 0;

    if (val & 0x1) {
        bql_lock();
        loongarch_cpu_set_irq(cpu, IRQ_TIMER, 0);
        bql_unlock();
    }
    return old_v;
}

/* LVZ CSR Access Helper Functions */

/* Helper function to check CSR access permissions in virtualization mode */
static bool check_csr_access_permission(CPULoongArchState *env, uint32_t csr, bool is_write)
{
    /* If not in guest mode, allow all CSR access */
    if (!is_guest_mode(env)) {
        return true;
    }
    
    /* In guest mode, check if LVZ is supported */
    if (!has_lvz_capability(env)) {
        return false;
    }
    
    /* Check access permissions based on CSR number and guest configuration */
    switch (csr) {
    /* Standard CSRs that guests can access */
    case LOONGARCH_CSR_CRMD:
    case LOONGARCH_CSR_PRMD:
    case LOONGARCH_CSR_EUEN:
    case LOONGARCH_CSR_MISC:
    case LOONGARCH_CSR_ECFG:
    case LOONGARCH_CSR_ERA:
    case LOONGARCH_CSR_BADV:
    case LOONGARCH_CSR_BADI:
    case LOONGARCH_CSR_EENTRY:
        return true;
        
    /* TLB-related CSRs */
    case LOONGARCH_CSR_TLBIDX:
    case LOONGARCH_CSR_TLBEHI:
    case LOONGARCH_CSR_TLBELO0:
    case LOONGARCH_CSR_TLBELO1:
    case LOONGARCH_CSR_ASID:
    case LOONGARCH_CSR_PGDL:
    case LOONGARCH_CSR_PGDH:
    case LOONGARCH_CSR_PGD:
    case LOONGARCH_CSR_PWCL:
    case LOONGARCH_CSR_PWCH:
    case LOONGARCH_CSR_STLBPS:
    case LOONGARCH_CSR_RVACFG:
        return true;
        
    /* Timer-related CSRs - check guest config */
    case LOONGARCH_CSR_TID:
    case LOONGARCH_CSR_TCFG:
    case LOONGARCH_CSR_TVAL:
    case LOONGARCH_CSR_CNTC:
        if (is_write) {
            return FIELD_EX64(env->CSR_GCFG, CSR_GCFG, TITO);
        } else {
            return FIELD_EX64(env->CSR_GCFG, CSR_GCFG, TITP);
        }
        
    case LOONGARCH_CSR_TICLR:
        /* Timer clear always needs hypervisor intervention */
        return false;
        
    /* Interrupt-related CSRs - check guest config */
    case LOONGARCH_CSR_ESTAT:
        if (is_write) {
            return FIELD_EX64(env->CSR_GCFG, CSR_GCFG, SITO);
        } else {
            return FIELD_EX64(env->CSR_GCFG, CSR_GCFG, SITP);
        }
        
    /* Configuration CSRs */
    case LOONGARCH_CSR_CPUID:
    case LOONGARCH_CSR_PRCFG1:
    case LOONGARCH_CSR_PRCFG2:
    case LOONGARCH_CSR_PRCFG3:
        return !is_write; /* Read-only for guests */
        
    /* Save registers */
    case LOONGARCH_CSR_SAVE(0) ... LOONGARCH_CSR_SAVE(15):
        return true;
        
    /* LLB control */
    case LOONGARCH_CSR_LLBCTL:
        return true;
        
    /* Privileged CSRs that require VM exit */
    case LOONGARCH_CSR_TLBRENTRY:
    case LOONGARCH_CSR_TLBRBADV:
    case LOONGARCH_CSR_TLBRERA:
    case LOONGARCH_CSR_TLBRSAVE:
    case LOONGARCH_CSR_TLBRELO0:
    case LOONGARCH_CSR_TLBRELO1:
    case LOONGARCH_CSR_TLBREHI:
    case LOONGARCH_CSR_TLBRPRMD:
    case LOONGARCH_CSR_MERRCTL:
    case LOONGARCH_CSR_MERRINFO1:
    case LOONGARCH_CSR_MERRINFO2:
    case LOONGARCH_CSR_MERRENTRY:
    case LOONGARCH_CSR_MERRERA:
    case LOONGARCH_CSR_MERRSAVE:
    case LOONGARCH_CSR_CTAG:
        return false; /* Require VM exit */
        
    /* Direct mapping windows - check guest config */
    case LOONGARCH_CSR_DMW(0) ... LOONGARCH_CSR_DMW(3):
        return true; /* Allow guest access with proper config */
        
    /* Implementation dependent CSRs */
    case LOONGARCH_CSR_IMPCTL1:
    case LOONGARCH_CSR_IMPCTL2:
        return false; /* Usually require VM exit */
        
    /* Debug CSRs */
    case LOONGARCH_CSR_DBG:
    case LOONGARCH_CSR_DERA:
    case LOONGARCH_CSR_DSAVE:
        return false; /* Debug CSRs require hypervisor privilege */
        
    default:
        /* Unknown CSR, deny access */
        return false;
    }
}

/* Trigger VM exit for CSR access that requires hypervisor intervention */
static void trigger_csr_vm_exit(CPULoongArchState *env, uint32_t csr, bool is_write, target_ulong val)
{
    uint32_t exit_reason;
    
    if (is_write) {
        exit_reason = VMEXIT_CSRW;
    } else {
        exit_reason = VMEXIT_CSRR;
    }
    
    /* Store CSR information for hypervisor */
    /* In a full implementation, the hypervisor would need access to:
     * - CSR number
     * - Access type (read/write)
     * - Value being written (for writes)
     * - Guest PC at time of access
     */
    
    /* Set VM mode to exit to hypervisor */
    env->CSR_GSTAT = FIELD_DP64(env->CSR_GSTAT, CSR_GSTAT, VM, 0);
    
    /* Generate hypervisor exception */
    do_raise_exception(env, EXCCODE_HVC, GETPC());
}

/* Enhanced CSR read function with LVZ support */
target_ulong helper_csrrd_with_lvz(CPULoongArchState *env, uint32_t csr)
{
    /* Check access permission */
    if (!check_csr_access_permission(env, csr, false)) {
        trigger_csr_vm_exit(env, csr, false, 0);
        return 0;
    }
    
    /* For guest mode, handle special CSRs */
    if (is_guest_mode(env)) {
        switch (csr) {
        case LOONGARCH_CSR_CPUID:
            /* Guest sees virtual CPU ID */
            return helper_csrrd_cpuid(env);
            
        case LOONGARCH_CSR_TVAL:
            /* Timer value adjusted for guest */
            return helper_csrrd_tval(env);
            
        case LOONGARCH_CSR_PGD:
            /* Page directory base adjusted for guest */
            return helper_csrrd_pgd(env);
            
        default:
            /* Standard CSR access for guest */
            break;
        }
    }
    
    /* Handle standard CSR reads */
    switch (csr) {
    case LOONGARCH_CSR_CRMD:
        return env->CSR_CRMD;
    case LOONGARCH_CSR_PRMD:
        return env->CSR_PRMD;
    case LOONGARCH_CSR_EUEN:
        return env->CSR_EUEN;
    case LOONGARCH_CSR_MISC:
        return env->CSR_MISC;
    case LOONGARCH_CSR_ECFG:
        return env->CSR_ECFG;
    case LOONGARCH_CSR_ESTAT:
        return env->CSR_ESTAT;
    case LOONGARCH_CSR_ERA:
        return env->CSR_ERA;
    case LOONGARCH_CSR_BADV:
        return env->CSR_BADV;
    case LOONGARCH_CSR_BADI:
        return env->CSR_BADI;
    case LOONGARCH_CSR_EENTRY:
        return env->CSR_EENTRY;
    case LOONGARCH_CSR_TLBIDX:
        return env->CSR_TLBIDX;
    case LOONGARCH_CSR_TLBEHI:
        return env->CSR_TLBEHI;
    case LOONGARCH_CSR_TLBELO0:
        return env->CSR_TLBELO0;
    case LOONGARCH_CSR_TLBELO1:
        return env->CSR_TLBELO1;
    case LOONGARCH_CSR_ASID:
        return env->CSR_ASID;
    case LOONGARCH_CSR_PGDL:
        return env->CSR_PGDL;
    case LOONGARCH_CSR_PGDH:
        return env->CSR_PGDH;
    case LOONGARCH_CSR_PGD:
        return helper_csrrd_pgd(env);
    case LOONGARCH_CSR_PWCL:
        return env->CSR_PWCL;
    case LOONGARCH_CSR_PWCH:
        return env->CSR_PWCH;
    case LOONGARCH_CSR_STLBPS:
        return env->CSR_STLBPS;
    case LOONGARCH_CSR_RVACFG:
        return env->CSR_RVACFG;
    case LOONGARCH_CSR_CPUID:
        return helper_csrrd_cpuid(env);
    case LOONGARCH_CSR_PRCFG1:
        return env->CSR_PRCFG1;
    case LOONGARCH_CSR_PRCFG2:
        return env->CSR_PRCFG2;
    case LOONGARCH_CSR_PRCFG3:
        return env->CSR_PRCFG3;
    case LOONGARCH_CSR_TID:
        return env->CSR_TID;
    case LOONGARCH_CSR_TCFG:
        return env->CSR_TCFG;
    case LOONGARCH_CSR_TVAL:
        return helper_csrrd_tval(env);
    case LOONGARCH_CSR_CNTC:
        return env->CSR_CNTC;
    case LOONGARCH_CSR_TICLR:
        return env->CSR_TICLR;
    case LOONGARCH_CSR_LLBCTL:
        return env->CSR_LLBCTL;
    case LOONGARCH_CSR_IMPCTL1:
        return env->CSR_IMPCTL1;
    case LOONGARCH_CSR_IMPCTL2:
        return env->CSR_IMPCTL2;
    default:
        /* Handle SAVE registers */
        if (csr >= LOONGARCH_CSR_SAVE(0) && csr <= LOONGARCH_CSR_SAVE(15)) {
            int index = csr - LOONGARCH_CSR_SAVE(0);
            return env->CSR_SAVE[index];
        }
        /* Handle DMW registers */
        if (csr >= LOONGARCH_CSR_DMW(0) && csr <= LOONGARCH_CSR_DMW(3)) {
            int index = csr - LOONGARCH_CSR_DMW(0);
            return env->CSR_DMW[index];
        }
        /* Unknown CSR, trigger VM exit */
        trigger_csr_vm_exit(env, csr, false, 0);
        return 0;
    }
}

/* Enhanced CSR write function with LVZ support */
target_ulong helper_csrwr_with_lvz(CPULoongArchState *env, target_ulong val, uint32_t csr)
{
    target_ulong old_val;
    
    /* Check access permission */
    if (!check_csr_access_permission(env, csr, true)) {
        trigger_csr_vm_exit(env, csr, true, val);
        return 0;
    }
    
    /* Handle special CSRs that need custom logic */
    switch (csr) {
    case LOONGARCH_CSR_ESTAT:
        return helper_csrwr_estat(env, val);
    case LOONGARCH_CSR_ASID:
        return helper_csrwr_asid(env, val);
    case LOONGARCH_CSR_TCFG:
        return helper_csrwr_tcfg(env, val);
    case LOONGARCH_CSR_TICLR:
        return helper_csrwr_ticlr(env, val);
    default:
        break;
    }
    
    /* Standard CSR writes */
    switch (csr) {
    case LOONGARCH_CSR_CRMD:
        old_val = env->CSR_CRMD;
        env->CSR_CRMD = val;
        return old_val;
    case LOONGARCH_CSR_PRMD:
        old_val = env->CSR_PRMD;
        env->CSR_PRMD = val;
        return old_val;
    case LOONGARCH_CSR_EUEN:
        old_val = env->CSR_EUEN;
        env->CSR_EUEN = val;
        return old_val;
    case LOONGARCH_CSR_MISC:
        old_val = env->CSR_MISC;
        env->CSR_MISC = val;
        return old_val;
    case LOONGARCH_CSR_ECFG:
        old_val = env->CSR_ECFG;
        env->CSR_ECFG = val;
        return old_val;
    case LOONGARCH_CSR_ERA:
        old_val = env->CSR_ERA;
        env->CSR_ERA = val;
        return old_val;
    case LOONGARCH_CSR_BADV:
        old_val = env->CSR_BADV;
        env->CSR_BADV = val;
        return old_val;
    case LOONGARCH_CSR_BADI:
        old_val = env->CSR_BADI;
        env->CSR_BADI = val;
        return old_val;
    case LOONGARCH_CSR_EENTRY:
        old_val = env->CSR_EENTRY;
        env->CSR_EENTRY = val;
        return old_val;
    case LOONGARCH_CSR_TLBIDX:
        old_val = env->CSR_TLBIDX;
        env->CSR_TLBIDX = val;
        return old_val;
    case LOONGARCH_CSR_TLBEHI:
        old_val = env->CSR_TLBEHI;
        env->CSR_TLBEHI = val;
        return old_val;
    case LOONGARCH_CSR_TLBELO0:
        old_val = env->CSR_TLBELO0;
        env->CSR_TLBELO0 = val;
        return old_val;
    case LOONGARCH_CSR_TLBELO1:
        old_val = env->CSR_TLBELO1;
        env->CSR_TLBELO1 = val;
        return old_val;
    case LOONGARCH_CSR_PGDL:
        old_val = env->CSR_PGDL;
        env->CSR_PGDL = val;
        return old_val;
    case LOONGARCH_CSR_PGDH:
        old_val = env->CSR_PGDH;
        env->CSR_PGDH = val;
        return old_val;
    case LOONGARCH_CSR_PGD:
        old_val = env->CSR_PGD;
        env->CSR_PGD = val;
        return old_val;
    case LOONGARCH_CSR_PWCL:
        old_val = env->CSR_PWCL;
        env->CSR_PWCL = val;
        return old_val;
    case LOONGARCH_CSR_PWCH:
        old_val = env->CSR_PWCH;
        env->CSR_PWCH = val;
        return old_val;
    case LOONGARCH_CSR_STLBPS:
        old_val = env->CSR_STLBPS;
        env->CSR_STLBPS = val;
        return old_val;
    case LOONGARCH_CSR_RVACFG:
        old_val = env->CSR_RVACFG;
        env->CSR_RVACFG = val;
        return old_val;
    case LOONGARCH_CSR_TID:
        old_val = env->CSR_TID;
        env->CSR_TID = val;
        return old_val;
    case LOONGARCH_CSR_CNTC:
        old_val = env->CSR_CNTC;
        env->CSR_CNTC = val;
        return old_val;
    case LOONGARCH_CSR_LLBCTL:
        old_val = env->CSR_LLBCTL;
        env->CSR_LLBCTL = val;
        return old_val;
    case LOONGARCH_CSR_IMPCTL1:
        old_val = env->CSR_IMPCTL1;
        env->CSR_IMPCTL1 = val;
        return old_val;
    case LOONGARCH_CSR_IMPCTL2:
        old_val = env->CSR_IMPCTL2;
        env->CSR_IMPCTL2 = val;
        return old_val;
    default:
        /* Handle SAVE registers */
        if (csr >= LOONGARCH_CSR_SAVE(0) && csr <= LOONGARCH_CSR_SAVE(15)) {
            int index = csr - LOONGARCH_CSR_SAVE(0);
            old_val = env->CSR_SAVE[index];
            env->CSR_SAVE[index] = val;
            return old_val;
        }
        /* Handle DMW registers */
        if (csr >= LOONGARCH_CSR_DMW(0) && csr <= LOONGARCH_CSR_DMW(3)) {
            int index = csr - LOONGARCH_CSR_DMW(0);
            old_val = env->CSR_DMW[index];
            env->CSR_DMW[index] = val;
            return old_val;
        }
        /* Unknown CSR, trigger VM exit */
        trigger_csr_vm_exit(env, csr, true, val);
        return 0;
    }
}

/* Enhanced CSR exchange function with LVZ support */
target_ulong helper_csrxchg_with_lvz(CPULoongArchState *env, target_ulong rj, target_ulong rd, uint32_t csr)
{
    target_ulong old_val, new_val;
    
    /* Check access permission */
    if (!check_csr_access_permission(env, csr, true)) {
        trigger_csr_vm_exit(env, csr, true, rj);
        return 0;
    }
    
    /* First read the current value */
    old_val = helper_csrrd_with_lvz(env, csr);
    
    /* Calculate new value: (old_val & ~rd) | (rj & rd) */
    new_val = (old_val & ~rd) | (rj & rd);
    
    /* Write the new value */
    helper_csrwr_with_lvz(env, new_val, csr);
    
    return old_val;
}
