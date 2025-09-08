/*
 * LoongArch LVZ (Virtualization) Second-Level Address Translation
 *
 * Copyright (c) 2024 Loongson Technology Corporation Limited
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "exec/log.h"
#include "cpu-csr.h"

#ifndef CONFIG_USER_ONLY

/**
 * Initialize second-level address translation for LVZ
 */
void loongarch_init_second_level_translation(CPULoongArchState *env)
{
    if (!has_lvz_capability(env)) {
        return;
    }
    
    env->lvz_enabled = true;
    memset(&env->vm_exit_ctx, 0, sizeof(env->vm_exit_ctx));
    
    qemu_log_mask(CPU_LOG_MMU, "LVZ second-level translation initialized\n");
}

/**
 * Core second-level address translation function
 * Translates Guest Physical Address (GPA) to Host Physical Address (HPA)
 */
bool loongarch_second_level_translate(CPULoongArchState *env, 
                                     hwaddr gpa, 
                                     hwaddr *hpa,
                                     int access_type, 
                                     int mmu_idx,
                                     bool *vm_exit_required)
{
    *vm_exit_required = false;
    
    /* If not in guest mode or LVZ not enabled, no second-level translation */
    if (!is_second_level_translation_enabled(env)) {
        *hpa = gpa;
        return true;
    }
    
    uint8_t gid = get_guest_id(env);
    
    qemu_log_mask(CPU_LOG_MMU, 
                  "Second-level translate: GPA=0x%llx, GID=%d, access=%d\n",
                  gpa, gid, access_type);
    
    /* Try VMM TLB lookup first */
    if (loongarch_vmm_tlb_lookup(env, gpa, hpa, access_type, mmu_idx)) {
        qemu_log_mask(CPU_LOG_MMU, 
                      "Second-level TLB hit: GPA=0x%llx -> HPA=0x%llx\n",
                      gpa, *hpa);
        return true;
    }
    
    /* TLB miss - check if we should trigger VM exit */
    uint32_t exit_reason = VMEXIT_MMIO; /* Default to MMIO access */
    
    /* Determine specific exit reason based on access pattern */
    if (access_type & ACCESS_TYPE_EXEC) {
        exit_reason = VMEXIT_MMIO;
    } else if (access_type & ACCESS_TYPE_WRITE) {
        exit_reason = VMEXIT_MMIO;
    } else {
        exit_reason = VMEXIT_MMIO;
    }
    
    if (should_trigger_vm_exit(env, exit_reason)) {
        *vm_exit_required = true;
        prepare_vm_exit_context(env, gpa, 0, exit_reason, access_type);
        
        qemu_log_mask(CPU_LOG_MMU, 
                      "Second-level translation triggers VM exit: reason=%d\n",
                      exit_reason);
        return false;
    }
    
    /* If no VM exit required, perform direct mapping (for debugging) */
    *hpa = gpa;
    return true;
}

/**
 * Trigger VM exit and switch to hypervisor
 */
void loongarch_trigger_vm_exit(CPULoongArchState *env, 
                               uint32_t exit_reason,
                               uint64_t fault_gpa, 
                               uint64_t fault_gva)
{
    if (!is_guest_mode(env)) {
        return;
    }
    
    prepare_vm_exit_context(env, fault_gpa, fault_gva, exit_reason, 0);
    
    qemu_log_mask(CPU_LOG_MMU, 
                  "VM Exit: reason=%d, GPA=0x%llx, GVA=0x%llx, GID=%d\n",
                  exit_reason, fault_gpa, fault_gva, get_guest_id(env));
    
    /* Switch from Guest Mode to Host Mode */
    env->CSR_GSTAT = FIELD_DP64(env->CSR_GSTAT, CSR_GSTAT, VM, 0);
    
    /* The actual VM exit handling would be done by the hypervisor */
    /* This is typically handled in the CPU exception handling code */
}

/**
 * Guest TLB lookup for first-level translation (GVA -> GPA)
 */
bool loongarch_guest_tlb_lookup(CPULoongArchState *env, 
                               vaddr va, 
                               hwaddr *gpa,
                               int access_type, 
                               int mmu_idx)
{
    if (!is_guest_mode(env)) {
        return false;
    }
    
    uint8_t gid = get_guest_id(env);
    
    /* Search TLB for matching guest page entry */
    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        LoongArchTLB *tlb = &env->tlb[i];
        
        if (!tlb_entry_matches_gid(tlb->tlb_misc, gid)) {
            continue;
        }
        
        if (!is_guest_page_tlb_entry(tlb->tlb_misc)) {
            continue;
        }
        
        /* Check if VA matches this TLB entry */
        uint64_t entry_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
        uint64_t ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
        uint64_t page_mask = (1ULL << ps) - 1;
        uint64_t va_vppn = va >> ps;
        
        if (va_vppn == entry_vppn) {
            /* TLB hit - extract GPA */
            uint64_t page_offset = va & page_mask;
            
            /* Use appropriate TLB entry based on odd/even page */
            uint64_t tlb_entry = (va & (1ULL << ps)) ? 
                                 tlb->tlb_entry1 : tlb->tlb_entry0;
            
            uint64_t ppn = FIELD_EX64(tlb_entry, TLBENTRY_64, PPN);
            *gpa = (ppn << ps) | page_offset;
            
            qemu_log_mask(CPU_LOG_MMU, 
                          "Guest TLB hit: VA=0x%llx -> GPA=0x%llx (GID=%d)\n",
                          va, *gpa, gid);
            return true;
        }
    }
    
    qemu_log_mask(CPU_LOG_MMU, 
                  "Guest TLB miss: VA=0x%llx (GID=%d)\n", va, gid);
    return false;
}

/**
 * VMM TLB lookup for second-level translation (GPA -> HPA)
 */
bool loongarch_vmm_tlb_lookup(CPULoongArchState *env, 
                             hwaddr gpa, 
                             hwaddr *hpa,
                             int access_type, 
                             int mmu_idx)
{
    /* Search TLB for matching VMM page entry */
    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        LoongArchTLB *tlb = &env->tlb[i];
        
        if (!is_vmm_page_tlb_entry(tlb->tlb_misc)) {
            continue;
        }
        
        /* Check if GPA matches this TLB entry */
        uint64_t entry_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
        uint64_t ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
        uint64_t page_mask = (1ULL << ps) - 1;
        uint64_t gpa_vppn = gpa >> ps;
        
        if (gpa_vppn == entry_vppn) {
            /* TLB hit - extract HPA */
            uint64_t page_offset = gpa & page_mask;
            
            /* Use appropriate TLB entry based on odd/even page */
            uint64_t tlb_entry = (gpa & (1ULL << ps)) ? 
                                 tlb->tlb_entry1 : tlb->tlb_entry0;
            
            uint64_t ppn = FIELD_EX64(tlb_entry, TLBENTRY_64, PPN);
            *hpa = (ppn << ps) | page_offset;
            
            qemu_log_mask(CPU_LOG_MMU, 
                          "VMM TLB hit: GPA=0x%llx -> HPA=0x%llx\n", gpa, *hpa);
            return true;
        }
    }
    
    qemu_log_mask(CPU_LOG_MMU, "VMM TLB miss: GPA=0x%llx\n", gpa);
    return false;
}

/**
 * Fill guest TLB entry for first-level translation
 */
void loongarch_fill_guest_tlb(CPULoongArchState *env, 
                             vaddr va, 
                             hwaddr gpa,
                             uint32_t flags, 
                             int mmu_idx)
{
    if (!is_guest_mode(env)) {
        return;
    }
    
    uint8_t gid = get_guest_id(env);
    
    /* Find an empty or replaceable TLB entry */
    int tlb_index = 0; /* Simplified replacement policy */
    LoongArchTLB *tlb = &env->tlb[tlb_index];
    
    /* Set up TLB misc field with GID */
    uint64_t ps = 12; /* 4KB page size */
    uint64_t vppn = va >> ps;
    
    tlb->tlb_misc = 0;
    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 1);
    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, GID, gid);
    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, VPPN, vppn);
    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, PS, ps);
    
    /* Set up TLB entry with GPA */
    uint64_t ppn = gpa >> ps;
    tlb->tlb_entry0 = 0;
    tlb->tlb_entry0 = FIELD_DP64(tlb->tlb_entry0, TLBENTRY_64, PPN, ppn);
    tlb->tlb_entry0 = FIELD_DP64(tlb->tlb_entry0, TLBENTRY, V, 1);
    
    qemu_log_mask(CPU_LOG_MMU, 
                  "Fill guest TLB: VA=0x%llx -> GPA=0x%llx (GID=%d)\n",
                  va, gpa, gid);
}

/**
 * Fill VMM TLB entry for second-level translation
 */
void loongarch_fill_vmm_tlb(CPULoongArchState *env, 
                           hwaddr gpa, 
                           hwaddr hpa,
                           uint32_t flags, 
                           int mmu_idx)
{
    /* Find an empty or replaceable TLB entry */
    int tlb_index = 1; /* Use different index from guest TLB */
    LoongArchTLB *tlb = &env->tlb[tlb_index];
    
    /* Set up TLB misc field with GID=0 for VMM pages */
    uint64_t ps = 12; /* 4KB page size */
    uint64_t vppn = gpa >> ps;
    
    tlb->tlb_misc = 0;
    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 1);
    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, GID, 0); /* VMM page */
    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, VPPN, vppn);
    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, PS, ps);
    
    /* Set up TLB entry with HPA */
    uint64_t ppn = hpa >> ps;
    tlb->tlb_entry0 = 0;
    tlb->tlb_entry0 = FIELD_DP64(tlb->tlb_entry0, TLBENTRY_64, PPN, ppn);
    tlb->tlb_entry0 = FIELD_DP64(tlb->tlb_entry0, TLBENTRY, V, 1);
    
    qemu_log_mask(CPU_LOG_MMU, 
                  "Fill VMM TLB: GPA=0x%llx -> HPA=0x%llx\n", gpa, hpa);
}

/**
 * Clear all guest TLB entries for a specific GID
 */
void loongarch_clear_guest_tlb_by_gid(CPULoongArchState *env, uint8_t gid)
{
    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        LoongArchTLB *tlb = &env->tlb[i];
        
        if (tlb_entry_matches_gid(tlb->tlb_misc, gid) && 
            is_guest_page_tlb_entry(tlb->tlb_misc)) {
            /* Clear this TLB entry */
            tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
        }
    }
    
    qemu_log_mask(CPU_LOG_MMU, "Cleared guest TLB for GID=%d\n", gid);
}

/**
 * Flush all guest TLB entries for a specific GID
 */
void loongarch_flush_guest_tlb_by_gid(CPULoongArchState *env, uint8_t gid)
{
    loongarch_clear_guest_tlb_by_gid(env, gid);
    qemu_log_mask(CPU_LOG_MMU, "Flushed guest TLB for GID=%d\n", gid);
}

/**
 * Search guest TLB for a specific VA and GID
 */
int loongarch_search_guest_tlb(CPULoongArchState *env, 
                              vaddr va, 
                              uint8_t gid)
{
    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        LoongArchTLB *tlb = &env->tlb[i];
        
        if (!tlb_entry_matches_gid(tlb->tlb_misc, gid)) {
            continue;
        }
        
        if (!is_guest_page_tlb_entry(tlb->tlb_misc)) {
            continue;
        }
        
        /* Check if VA matches this TLB entry */
        uint64_t entry_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
        uint64_t ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
        uint64_t va_vppn = va >> ps;
        
        if (va_vppn == entry_vppn) {
            qemu_log_mask(CPU_LOG_MMU, 
                          "Guest TLB search hit: VA=0x%llx, index=%d (GID=%d)\n",
                          va, i, gid);
            return i;
        }
    }
    
    qemu_log_mask(CPU_LOG_MMU, 
                  "Guest TLB search miss: VA=0x%llx (GID=%d)\n", va, gid);
    return -1;
}

#endif /* !CONFIG_USER_ONLY */
