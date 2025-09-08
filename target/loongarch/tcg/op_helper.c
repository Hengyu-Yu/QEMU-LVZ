/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LoongArch emulation helpers for QEMU.
 *
 * Copyright (c) 2021 Loongson Technology Corporation Limited
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "qemu/host-utils.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "internals.h"
#include "qemu/crc32c.h"
#include <zlib.h>
#include "cpu-csr.h"

/* Exceptions helpers */
void helper_raise_exception(CPULoongArchState *env, uint32_t exception)
{
    do_raise_exception(env, exception, GETPC());
}

target_ulong helper_bitrev_w(target_ulong rj)
{
    return (int32_t)revbit32(rj);
}

target_ulong helper_bitrev_d(target_ulong rj)
{
    return revbit64(rj);
}

target_ulong helper_bitswap(target_ulong v)
{
    v = ((v >> 1) & (target_ulong)0x5555555555555555ULL) |
        ((v & (target_ulong)0x5555555555555555ULL) << 1);
    v = ((v >> 2) & (target_ulong)0x3333333333333333ULL) |
        ((v & (target_ulong)0x3333333333333333ULL) << 2);
    v = ((v >> 4) & (target_ulong)0x0F0F0F0F0F0F0F0FULL) |
        ((v & (target_ulong)0x0F0F0F0F0F0F0F0FULL) << 4);
    return v;
}

/* loongarch assert op */
void helper_asrtle_d(CPULoongArchState *env, target_ulong rj, target_ulong rk)
{
    if (rj > rk) {
        env->CSR_BADV = rj;
        do_raise_exception(env, EXCCODE_BCE, GETPC());
    }
}

void helper_asrtgt_d(CPULoongArchState *env, target_ulong rj, target_ulong rk)
{
    if (rj <= rk) {
        env->CSR_BADV = rj;
        do_raise_exception(env, EXCCODE_BCE, GETPC());
    }
}

target_ulong helper_crc32(target_ulong val, target_ulong m, uint64_t sz)
{
    uint8_t buf[8];
    target_ulong mask = ((sz * 8) == 64) ? -1ULL : ((1ULL << (sz * 8)) - 1);

    m &= mask;
    stq_le_p(buf, m);
    return (int32_t) (crc32(val ^ 0xffffffff, buf, sz) ^ 0xffffffff);
}

target_ulong helper_crc32c(target_ulong val, target_ulong m, uint64_t sz)
{
    uint8_t buf[8];
    target_ulong mask = ((sz * 8) == 64) ? -1ULL : ((1ULL << (sz * 8)) - 1);
    m &= mask;
    stq_le_p(buf, m);
    return (int32_t) (crc32c(val, buf, sz) ^ 0xffffffff);
}

target_ulong helper_cpucfg(CPULoongArchState *env, target_ulong rj)
{
    return rj >= ARRAY_SIZE(env->cpucfg) ? 0 : env->cpucfg[rj];
}

uint64_t helper_rdtime_d(CPULoongArchState *env)
{
#ifdef CONFIG_USER_ONLY
    return cpu_get_host_ticks();
#else
    uint64_t plv;
    LoongArchCPU *cpu = env_archcpu(env);

    plv = FIELD_EX64(env->CSR_CRMD, CSR_CRMD, PLV);
    
    /* Check access permission based on current execution context */
    if (is_guest_execution_context(env)) {
        /* In guest mode, check guest-specific timer access permissions */
        if (extract64(env->GCSR_MISC, R_CSR_MISC_DRDTL_SHIFT + plv, 1)) {
            /* Guest timer access violation - trigger VM exit */
            helper_vm_exit(env, VMEXIT_TIMER);
            return 0;
        }
        
        /* Apply guest counter compensation if configured */
        uint64_t base_time = cpu_loongarch_get_constant_timer_counter(cpu);
        /* TODO: Add proper guest counter compensation */
        return base_time;
    } else {
        /* Host/hypervisor mode timer access */
        if (extract64(env->CSR_MISC, R_CSR_MISC_DRDTL_SHIFT + plv, 1)) {
            do_raise_exception(env, EXCCODE_IPE, GETPC());
        }
        return cpu_loongarch_get_constant_timer_counter(cpu);
    }
#endif
}

/* Enhanced CPUCFG helper with virtualization support */
target_ulong helper_cpucfg_vm(CPULoongArchState *env, target_ulong rj)
{
    if (is_guest_execution_context(env)) {
        /* In guest mode, some CPUCFG registers may be virtualized */
        if (rj == 2) {
            /* Mask virtualization features from guest view if configured */
            target_ulong host_cfg = (rj >= ARRAY_SIZE(env->cpucfg)) ? 0 : env->cpucfg[rj];
            /* TODO: Apply guest configuration mask based on GCFG */
            
            /* Hide certain features from guest */
            host_cfg = FIELD_DP32(host_cfg, CPUCFG2, LVZ, 0);
            return host_cfg;
        }
        
        /* Check if guest has permission to access this CPUCFG register */
        /* TODO: Check GCFG.GCOP for restricted CPUCFG access */
        if (rj > 15) {
            /* Trigger VM exit for restricted CPUCFG access */
            helper_vm_exit(env, VMEXIT_CPUCFG);
            return 0;
        }
    }
    
    return rj >= ARRAY_SIZE(env->cpucfg) ? 0 : env->cpucfg[rj];
}

#ifndef CONFIG_USER_ONLY
void helper_ertn(CPULoongArchState *env)
{
    uint64_t csr_pplv, csr_pie;
    uint64_t return_address;
    bool is_guest = is_guest_execution_context(env);
    
    if (FIELD_EX64(env->CSR_TLBRERA, CSR_TLBRERA, ISTLBR)) {
        /* TLB refill exception return */
        if (is_guest) {
            /* In guest mode, use guest TLB registers */
            csr_pplv = FIELD_EX64(env->GCSR_TLBRPRMD, CSR_TLBRPRMD, PPLV);
            csr_pie = FIELD_EX64(env->GCSR_TLBRPRMD, CSR_TLBRPRMD, PIE);
            return_address = env->GCSR_TLBRERA;
        } else {
            /* Host/hypervisor mode, use host TLB registers */
            csr_pplv = FIELD_EX64(env->CSR_TLBRPRMD, CSR_TLBRPRMD, PPLV);
            csr_pie = FIELD_EX64(env->CSR_TLBRPRMD, CSR_TLBRPRMD, PIE);
            return_address = env->CSR_TLBRERA;
        }

        env->CSR_TLBRERA = FIELD_DP64(env->CSR_TLBRERA, CSR_TLBRERA, ISTLBR, 0);
        env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, DA, 0);
        env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, PG, 1);
        set_pc(env, return_address);
        qemu_log_mask(CPU_LOG_INT, "%s: %sTLBRERA " TARGET_FMT_lx "\n",
                      __func__, is_guest ? "Guest " : "", return_address);
    } else {
        /* Normal exception return */
        if (is_guest) {
            /* In guest mode, use guest exception registers */
            csr_pplv = FIELD_EX64(env->GCSR_PRMD, CSR_PRMD, PPLV);
            csr_pie = FIELD_EX64(env->GCSR_PRMD, CSR_PRMD, PIE);
            return_address = env->GCSR_ERA;
        } else {
            /* Host/hypervisor mode, use host exception registers */
            csr_pplv = FIELD_EX64(env->CSR_PRMD, CSR_PRMD, PPLV);
            csr_pie = FIELD_EX64(env->CSR_PRMD, CSR_PRMD, PIE);
            return_address = env->CSR_ERA;
        }

        set_pc(env, return_address);
        qemu_log_mask(CPU_LOG_INT, "%s: %sERA " TARGET_FMT_lx "\n",
                      __func__, is_guest ? "Guest " : "", return_address);
    }
    
    /* Restore privilege level and interrupt enable */
    env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, PLV, csr_pplv);
    env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, IE, csr_pie);

    /* Handle virtualization mode state transition */
    if (is_guest) {
        /* Restore previous virtualization mode from GSTAT.PVM */
        uint64_t pvm = FIELD_EX64(env->CSR_GSTAT, CSR_GSTAT, PVM);
        env->CSR_GSTAT = FIELD_DP64(env->CSR_GSTAT, CSR_GSTAT, VM, pvm);
        qemu_log_mask(CPU_LOG_INT, "%s: Restored VM bit to %llu\n", __func__, pvm);
    }

    env->lladdr = 1;
}

void helper_idle(CPULoongArchState *env)
{
    CPUState *cs = env_cpu(env);

    cs->halted = 1;
    do_raise_exception(env, EXCP_HLT, 0);
}

/* LVZ virtualization helper functions */
void helper_vm_exit(CPULoongArchState *env, uint32_t exit_reason)
{
    /* Save guest state before VM exit */
    if (is_guest_execution_context(env)) {
        /* Clear VM bit to enter hypervisor mode */
        env->CSR_GSTAT = FIELD_DP64(env->CSR_GSTAT, CSR_GSTAT, PVM, 
                                   FIELD_EX64(env->CSR_GSTAT, CSR_GSTAT, VM));
        env->CSR_GSTAT = FIELD_DP64(env->CSR_GSTAT, CSR_GSTAT, VM, 0);
        
        /* Save exit reason for hypervisor */
        env->vm_exit_ctx.exit_reason = exit_reason;
        env->vm_exit_ctx.fault_gva = env->CSR_BADV;
        
        qemu_log_mask(CPU_LOG_INT, "%s: VM exit with reason %u, GVA " TARGET_FMT_lx "\n",
                      __func__, exit_reason, env->CSR_BADV);
        
        /* Trigger VM exit exception to hypervisor */
        do_raise_exception(env, EXCCODE_HVC, GETPC());
    }
}

/* Enhanced exception return for virtualization */
void helper_vm_enter(CPULoongArchState *env)
{
    if (is_hypervisor_execution_context(env)) {
        /* Set VM bit to enter guest mode */
        env->CSR_GSTAT = FIELD_DP64(env->CSR_GSTAT, CSR_GSTAT, VM, 1);
        
        qemu_log_mask(CPU_LOG_INT, "%s: Entering guest mode with GID %u\n",
                      __func__, get_guest_id(env));
    }
}

/* Guest exception handling with virtualization support */
void helper_guest_exception(CPULoongArchState *env, uint32_t exception, target_ulong pc)
{
    if (is_guest_execution_context(env)) {
        /* Save guest state in guest CSRs */
        uint64_t crmd = env->CSR_CRMD;
        uint64_t prmd = env->GCSR_PRMD;
        
        /* Update guest PRMD with current state */
        prmd = FIELD_DP64(prmd, CSR_PRMD, PPLV, FIELD_EX64(crmd, CSR_CRMD, PLV));
        prmd = FIELD_DP64(prmd, CSR_PRMD, PIE, FIELD_EX64(crmd, CSR_CRMD, IE));
        env->GCSR_PRMD = prmd;
        
        /* Save exception return address in guest ERA */
        env->GCSR_ERA = pc;
        
        /* Update guest exception status */
        env->GCSR_ESTAT = FIELD_DP64(env->GCSR_ESTAT, 
                                   CSR_ESTAT, ECODE, exception);
        
        /* Clear guest interrupt enable */
        env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, IE, 0);
        
        qemu_log_mask(CPU_LOG_INT, "%s: Guest exception %u at PC " TARGET_FMT_lx "\n",
                      __func__, exception, pc);
    } else {
        /* Host mode exception handling - use standard mechanism */
        do_raise_exception(env, exception, pc);
    }
}

/* Virtual machine context switch helper */
void helper_vm_context_switch(CPULoongArchState *env, uint32_t target_gid)
{
    if (is_hypervisor_execution_context(env)) {
        uint8_t current_gid = get_guest_id(env);
        
        if (current_gid != target_gid) {
            /* Update GID in GSTAT */
            env->CSR_GSTAT = FIELD_DP64(env->CSR_GSTAT, CSR_GSTAT, GID, target_gid);
            
            /* Invalidate TLB entries for the previous GID */
            tlb_flush_by_mmuidx(env_cpu(env), 1 << current_gid);
            
            qemu_log_mask(CPU_LOG_INT, "%s: Context switch from GID %u to GID %u\n",
                          __func__, current_gid, target_gid);
        }
    }
}

/* Virtualization-aware interrupt handling */
void helper_vm_interrupt(CPULoongArchState *env, uint32_t int_vec)
{
    if (is_guest_execution_context(env)) {
        /* Check guest interrupt configuration */
        /* TODO: Implement proper GINTC register access */
        
        /* Check if this interrupt should be handled by guest or cause VM exit */
        if (int_vec < 64) {
            /* Interrupt is configured for direct guest handling */
            uint64_t crmd = env->CSR_CRMD;
            
            if (FIELD_EX64(crmd, CSR_CRMD, IE)) {
                /* Guest interrupts enabled - deliver to guest */
                env->GCSR_ESTAT = FIELD_DP64(env->GCSR_ESTAT,
                                           CSR_ESTAT, IS, int_vec);
                
                /* Save current state in guest PRMD */
                uint64_t prmd = env->GCSR_PRMD;
                prmd = FIELD_DP64(prmd, CSR_PRMD, PPLV, FIELD_EX64(crmd, CSR_CRMD, PLV));
                prmd = FIELD_DP64(prmd, CSR_PRMD, PIE, FIELD_EX64(crmd, CSR_CRMD, IE));
                env->GCSR_PRMD = prmd;
                
                /* Jump to guest interrupt handler */
                env->GCSR_ERA = env->pc;
                set_pc(env, env->GCSR_EENTRY);
                
                /* Disable interrupts */
                env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, IE, 0);
                
                qemu_log_mask(CPU_LOG_INT, "%s: Guest interrupt %u delivered\n",
                              __func__, int_vec);
            }
        } else {
            /* Interrupt should cause VM exit to hypervisor */
            helper_vm_exit(env, VMEXIT_INT);
        }
    } else {
        /* Host/hypervisor mode - use normal interrupt handling */
        env->CSR_ESTAT = FIELD_DP64(env->CSR_ESTAT, CSR_ESTAT, IS, int_vec);
    }
}

/* Enhanced idle helper with virtualization support */
void helper_vm_idle(CPULoongArchState *env)
{
    if (is_guest_execution_context(env)) {
        /* Guest idle - may cause VM exit depending on configuration */
        /* TODO: Implement proper GCFG register access */
        
        /* Check if idle should cause VM exit */
        /* TODO: Check GCFG.GCOP for idle VM exit */
        if (is_guest_mode(env)) {
            helper_vm_exit(env, VMEXIT_CPUCFG);
            return;
        }
    }
    
    /* Standard idle processing */
    helper_idle(env);
}
#endif
