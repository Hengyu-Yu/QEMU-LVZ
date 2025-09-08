/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QEMU LoongArch CPU
 *
 * Copyright (c) 2021 Loongson Technology Corporation Limited
 */

#ifndef LOONGARCH_CPU_H
#define LOONGARCH_CPU_H

#include "qemu/int128.h"
#include "exec/cpu-defs.h"
#include "fpu/softfloat-types.h"
#include "hw/registerfields.h"
#include "qemu/timer.h"
#ifndef CONFIG_USER_ONLY
#include "exec/memory.h"
#endif
#include "cpu-csr.h"
#include "cpu-qom.h"

#define IOCSRF_TEMP             0
#define IOCSRF_NODECNT          1
#define IOCSRF_MSI              2
#define IOCSRF_EXTIOI           3
#define IOCSRF_CSRIPI           4
#define IOCSRF_FREQCSR          5
#define IOCSRF_FREQSCALE        6
#define IOCSRF_DVFSV1           7
#define IOCSRF_GMOD             9
#define IOCSRF_VM               11

#define VERSION_REG             0x0
#define FEATURE_REG             0x8
#define VENDOR_REG              0x10
#define CPUNAME_REG             0x20
#define MISC_FUNC_REG           0x420
#define IOCSRM_EXTIOI_EN        48
#define IOCSRM_EXTIOI_INT_ENCODE 49

#define IOCSR_MEM_SIZE          0x428

#define FCSR0_M1    0x1f         /* FCSR1 mask, Enables */
#define FCSR0_M2    0x1f1f0000   /* FCSR2 mask, Cause and Flags */
#define FCSR0_M3    0x300        /* FCSR3 mask, Round Mode */
#define FCSR0_RM    8            /* Round Mode bit num on fcsr0 */

FIELD(FCSR0, ENABLES, 0, 5)
FIELD(FCSR0, RM, 8, 2)
FIELD(FCSR0, FLAGS, 16, 5)
FIELD(FCSR0, CAUSE, 24, 5)

#define GET_FP_CAUSE(REG)      FIELD_EX32(REG, FCSR0, CAUSE)
#define SET_FP_CAUSE(REG, V) \
    do { \
        (REG) = FIELD_DP32(REG, FCSR0, CAUSE, V); \
    } while (0)
#define UPDATE_FP_CAUSE(REG, V) \
    do { \
        (REG) |= FIELD_DP32(0, FCSR0, CAUSE, V); \
    } while (0)

#define GET_FP_ENABLES(REG)    FIELD_EX32(REG, FCSR0, ENABLES)
#define SET_FP_ENABLES(REG, V) \
    do { \
        (REG) = FIELD_DP32(REG, FCSR0, ENABLES, V); \
    } while (0)

#define GET_FP_FLAGS(REG)      FIELD_EX32(REG, FCSR0, FLAGS)
#define SET_FP_FLAGS(REG, V) \
    do { \
        (REG) = FIELD_DP32(REG, FCSR0, FLAGS, V); \
    } while (0)

#define UPDATE_FP_FLAGS(REG, V) \
    do { \
        (REG) |= FIELD_DP32(0, FCSR0, FLAGS, V); \
    } while (0)

#define FP_INEXACT        1
#define FP_UNDERFLOW      2
#define FP_OVERFLOW       4
#define FP_DIV0           8
#define FP_INVALID        16

#define EXCODE(code, subcode) ( ((subcode) << 6) | (code) )
#define EXCODE_MCODE(code)    ( (code) & 0x3f )
#define EXCODE_SUBCODE(code)  ( (code) >> 6 )

#define  EXCCODE_EXTERNAL_INT        64   /* plus external interrupt number */
#define  EXCCODE_INT                 EXCODE(0, 0)
#define  EXCCODE_PIL                 EXCODE(1, 0)
#define  EXCCODE_PIS                 EXCODE(2, 0)
#define  EXCCODE_PIF                 EXCODE(3, 0)
#define  EXCCODE_PME                 EXCODE(4, 0)
#define  EXCCODE_PNR                 EXCODE(5, 0)
#define  EXCCODE_PNX                 EXCODE(6, 0)
#define  EXCCODE_PPI                 EXCODE(7, 0)
#define  EXCCODE_ADEF                EXCODE(8, 0) /* Different exception subcode */
#define  EXCCODE_ADEM                EXCODE(8, 1)
#define  EXCCODE_ALE                 EXCODE(9, 0)
#define  EXCCODE_BCE                 EXCODE(10, 0)
#define  EXCCODE_SYS                 EXCODE(11, 0)
#define  EXCCODE_BRK                 EXCODE(12, 0)
#define  EXCCODE_INE                 EXCODE(13, 0)
#define  EXCCODE_IPE                 EXCODE(14, 0)
#define  EXCCODE_FPD                 EXCODE(15, 0)
#define  EXCCODE_SXD                 EXCODE(16, 0)
#define  EXCCODE_ASXD                EXCODE(17, 0)
#define  EXCCODE_FPE                 EXCODE(18, 0) /* Different exception subcode */
#define  EXCCODE_VFPE                EXCODE(18, 1)
#define  EXCCODE_WPEF                EXCODE(19, 0) /* Different exception subcode */
#define  EXCCODE_WPEM                EXCODE(19, 1)
#define  EXCCODE_BTD                 EXCODE(20, 0)
#define  EXCCODE_BTE                 EXCODE(21, 0)
#define  EXCCODE_HVC                 EXCODE(22, 0) /* Hypervisor call */
#define  EXCCODE_DBP                 EXCODE(26, 0) /* Reserved subcode used for debug */

/* VM exit reason codes for LVZ */
#define  VMEXIT_MMIO                 1  /* MMIO access */
#define  VMEXIT_INT                  2  /* Interrupt */
#define  VMEXIT_TIMER                3  /* Timer */
#define  VMEXIT_IOCSR                4  /* IOCSR access */
#define  VMEXIT_CSRR                 5  /* CSR read */
#define  VMEXIT_CSRW                 6  /* CSR write */
#define  VMEXIT_CSRX                 7  /* CSR exchange */
#define  VMEXIT_HYPERCALL            8  /* Hypercall */
#define  VMEXIT_CPUCFG               9  /* CPUCFG */
#define  VMEXIT_TLB                  10 /* TLB operation */
#define  VMEXIT_CACHE                11 /* Cache operation */

/* cpucfg[0] bits */
FIELD(CPUCFG0, PRID, 0, 32)

/* cpucfg[1] bits */
FIELD(CPUCFG1, ARCH, 0, 2)
FIELD(CPUCFG1, PGMMU, 2, 1)
FIELD(CPUCFG1, IOCSR, 3, 1)
FIELD(CPUCFG1, PALEN, 4, 8)
FIELD(CPUCFG1, VALEN, 12, 8)
FIELD(CPUCFG1, UAL, 20, 1)
FIELD(CPUCFG1, RI, 21, 1)
FIELD(CPUCFG1, EP, 22, 1)
FIELD(CPUCFG1, RPLV, 23, 1)
FIELD(CPUCFG1, HP, 24, 1)
FIELD(CPUCFG1, IOCSR_BRD, 25, 1)
FIELD(CPUCFG1, MSG_INT, 26, 1)

/* cpucfg[1].arch */
#define CPUCFG1_ARCH_LA32R       0
#define CPUCFG1_ARCH_LA32        1
#define CPUCFG1_ARCH_LA64        2

/* cpucfg[2] bits */
FIELD(CPUCFG2, FP, 0, 1)
FIELD(CPUCFG2, FP_SP, 1, 1)
FIELD(CPUCFG2, FP_DP, 2, 1)
FIELD(CPUCFG2, FP_VER, 3, 3)
FIELD(CPUCFG2, LSX, 6, 1)
FIELD(CPUCFG2, LASX, 7, 1)
FIELD(CPUCFG2, COMPLEX, 8, 1)
FIELD(CPUCFG2, CRYPTO, 9, 1)
FIELD(CPUCFG2, LVZ, 10, 1)
FIELD(CPUCFG2, LVZ_VER, 11, 3)
FIELD(CPUCFG2, LLFTP, 14, 1)
FIELD(CPUCFG2, LLFTP_VER, 15, 3)
FIELD(CPUCFG2, LBT_X86, 18, 1)
FIELD(CPUCFG2, LBT_ARM, 19, 1)
FIELD(CPUCFG2, LBT_MIPS, 20, 1)
FIELD(CPUCFG2, LSPW, 21, 1)
FIELD(CPUCFG2, LAM, 22, 1)

/* cpucfg[3] bits */
FIELD(CPUCFG3, CCDMA, 0, 1)
FIELD(CPUCFG3, SFB, 1, 1)
FIELD(CPUCFG3, UCACC, 2, 1)
FIELD(CPUCFG3, LLEXC, 3, 1)
FIELD(CPUCFG3, SCDLY, 4, 1)
FIELD(CPUCFG3, LLDBAR, 5, 1)
FIELD(CPUCFG3, ITLBHMC, 6, 1)
FIELD(CPUCFG3, ICHMC, 7, 1)
FIELD(CPUCFG3, SPW_LVL, 8, 3)
FIELD(CPUCFG3, SPW_HP_HF, 11, 1)
FIELD(CPUCFG3, RVA, 12, 1)
FIELD(CPUCFG3, RVAMAX, 13, 4)

/* cpucfg[4] bits */
FIELD(CPUCFG4, CC_FREQ, 0, 32)

/* cpucfg[5] bits */
FIELD(CPUCFG5, CC_MUL, 0, 16)
FIELD(CPUCFG5, CC_DIV, 16, 16)

/* cpucfg[6] bits */
FIELD(CPUCFG6, PMP, 0, 1)
FIELD(CPUCFG6, PMVER, 1, 3)
FIELD(CPUCFG6, PMNUM, 4, 4)
FIELD(CPUCFG6, PMBITS, 8, 6)
FIELD(CPUCFG6, UPM, 14, 1)

/* cpucfg[16] bits */
FIELD(CPUCFG16, L1_IUPRE, 0, 1)
FIELD(CPUCFG16, L1_IUUNIFY, 1, 1)
FIELD(CPUCFG16, L1_DPRE, 2, 1)
FIELD(CPUCFG16, L2_IUPRE, 3, 1)
FIELD(CPUCFG16, L2_IUUNIFY, 4, 1)
FIELD(CPUCFG16, L2_IUPRIV, 5, 1)
FIELD(CPUCFG16, L2_IUINCL, 6, 1)
FIELD(CPUCFG16, L2_DPRE, 7, 1)
FIELD(CPUCFG16, L2_DPRIV, 8, 1)
FIELD(CPUCFG16, L2_DINCL, 9, 1)
FIELD(CPUCFG16, L3_IUPRE, 10, 1)
FIELD(CPUCFG16, L3_IUUNIFY, 11, 1)
FIELD(CPUCFG16, L3_IUPRIV, 12, 1)
FIELD(CPUCFG16, L3_IUINCL, 13, 1)
FIELD(CPUCFG16, L3_DPRE, 14, 1)
FIELD(CPUCFG16, L3_DPRIV, 15, 1)
FIELD(CPUCFG16, L3_DINCL, 16, 1)

/* cpucfg[17] bits */
FIELD(CPUCFG17, L1IU_WAYS, 0, 16)
FIELD(CPUCFG17, L1IU_SETS, 16, 8)
FIELD(CPUCFG17, L1IU_SIZE, 24, 7)

/* cpucfg[18] bits */
FIELD(CPUCFG18, L1D_WAYS, 0, 16)
FIELD(CPUCFG18, L1D_SETS, 16, 8)
FIELD(CPUCFG18, L1D_SIZE, 24, 7)

/* cpucfg[19] bits */
FIELD(CPUCFG19, L2IU_WAYS, 0, 16)
FIELD(CPUCFG19, L2IU_SETS, 16, 8)
FIELD(CPUCFG19, L2IU_SIZE, 24, 7)

/* cpucfg[20] bits */
FIELD(CPUCFG20, L3IU_WAYS, 0, 16)
FIELD(CPUCFG20, L3IU_SETS, 16, 8)
FIELD(CPUCFG20, L3IU_SIZE, 24, 7)

/*CSR_CRMD */
FIELD(CSR_CRMD, PLV, 0, 2)
FIELD(CSR_CRMD, IE, 2, 1)
FIELD(CSR_CRMD, DA, 3, 1)
FIELD(CSR_CRMD, PG, 4, 1)
FIELD(CSR_CRMD, DATF, 5, 2)
FIELD(CSR_CRMD, DATM, 7, 2)
FIELD(CSR_CRMD, WE, 9, 1)

extern const char * const regnames[32];
extern const char * const fregnames[32];

#define N_IRQS      13
#define IRQ_TIMER   11
#define IRQ_IPI     12

#define LOONGARCH_STLB         2048 /* 2048 STLB */
#define LOONGARCH_MTLB         64   /* 64 MTLB */
#define LOONGARCH_TLB_MAX      (LOONGARCH_STLB + LOONGARCH_MTLB)

/*
 * define the ASID PS E VPPN field of TLB
 */
FIELD(TLB_MISC, E, 0, 1)
FIELD(TLB_MISC, ASID, 1, 10)
FIELD(TLB_MISC, VPPN, 13, 35)
FIELD(TLB_MISC, PS, 48, 6)
FIELD(TLB_MISC, GID, 54, 8)

#define LSX_LEN    (128)
#define LASX_LEN   (256)

typedef union VReg {
    int8_t   B[LASX_LEN / 8];
    int16_t  H[LASX_LEN / 16];
    int32_t  W[LASX_LEN / 32];
    int64_t  D[LASX_LEN / 64];
    uint8_t  UB[LASX_LEN / 8];
    uint16_t UH[LASX_LEN / 16];
    uint32_t UW[LASX_LEN / 32];
    uint64_t UD[LASX_LEN / 64];
    Int128   Q[LASX_LEN / 128];
} VReg;

typedef union fpr_t fpr_t;
union fpr_t {
    VReg  vreg;
};

#ifdef CONFIG_TCG
struct LoongArchTLB {
    uint64_t tlb_misc;
    /* Fields corresponding to CSR_TLBELO0/1 */
    uint64_t tlb_entry0;
    uint64_t tlb_entry1;
};
typedef struct LoongArchTLB LoongArchTLB;

/* Second-level address translation structure for LVZ */
typedef struct LoongArchSecondLevelTLB {
    uint64_t gpa_base;      /* Guest Physical Address base */
    uint64_t hpa_base;      /* Host Physical Address base */
    uint64_t size;          /* Translation region size */
    uint8_t  gid;           /* Guest ID */
    uint32_t flags;         /* Permission and attribute flags */
    bool     valid;         /* Entry validity */
} LoongArchSecondLevelTLB;

/* VM exit context for second-level translation */
typedef struct VMExitContext {
    uint64_t fault_gpa;     /* Faulting Guest Physical Address */
    uint64_t fault_gva;     /* Faulting Guest Virtual Address */
    uint8_t  gid;           /* Guest ID causing the fault */
    uint32_t exit_reason;   /* VM exit reason code */
    uint32_t access_type;   /* Read/Write/Execute */
    bool     is_tlb_refill; /* True for TLB refill, false for page fault */
} VMExitContext;
#endif

typedef struct CPUArchState {
    uint64_t gpr[32];
    uint64_t pc;

    fpr_t fpr[32];
    bool cf[8];
    uint32_t fcsr0;

    uint32_t cpucfg[21];

    /* LoongArch CSRs */
    uint64_t CSR_CRMD;
    uint64_t CSR_PRMD;
    uint64_t CSR_EUEN;
    uint64_t CSR_MISC;
    uint64_t CSR_ECFG;
    uint64_t CSR_ESTAT;
    uint64_t CSR_ERA;
    uint64_t CSR_BADV;
    uint64_t CSR_BADI;
    uint64_t CSR_EENTRY;
    uint64_t CSR_TLBIDX;
    uint64_t CSR_TLBEHI;
    uint64_t CSR_TLBELO0;
    uint64_t CSR_TLBELO1;
    uint64_t CSR_ASID;
    uint64_t CSR_PGDL;
    uint64_t CSR_PGDH;
    uint64_t CSR_PGD;
    uint64_t CSR_PWCL;
    uint64_t CSR_PWCH;
    uint64_t CSR_STLBPS;
    uint64_t CSR_RVACFG;
    uint64_t CSR_CPUID;
    uint64_t CSR_PRCFG1;
    uint64_t CSR_PRCFG2;
    uint64_t CSR_PRCFG3;
    uint64_t CSR_SAVE[16];
    uint64_t CSR_TID;
    uint64_t CSR_TCFG;
    uint64_t CSR_TVAL;
    uint64_t CSR_CNTC;
    uint64_t CSR_TICLR;
    uint64_t CSR_LLBCTL;
    uint64_t CSR_IMPCTL1;
    uint64_t CSR_IMPCTL2;
    uint64_t CSR_TLBRENTRY;
    uint64_t CSR_TLBRBADV;
    uint64_t CSR_TLBRERA;
    uint64_t CSR_TLBRSAVE;
    uint64_t CSR_TLBRELO0;
    uint64_t CSR_TLBRELO1;
    uint64_t CSR_TLBREHI;
    uint64_t CSR_TLBRPRMD;
    uint64_t CSR_MERRCTL;
    uint64_t CSR_MERRINFO1;
    uint64_t CSR_MERRINFO2;
    uint64_t CSR_MERRENTRY;
    uint64_t CSR_MERRERA;
    uint64_t CSR_MERRSAVE;
    uint64_t CSR_CTAG;
    uint64_t CSR_DMW[4];
    uint64_t CSR_DBG;
    uint64_t CSR_DERA;
    uint64_t CSR_DSAVE;

    /* LVZ (LoongArch Virtualization) CSRs */
    uint64_t CSR_GSTAT;         /* Guest status */
    uint64_t CSR_GCFG;          /* Guest config */
    uint64_t CSR_GINTC;         /* Guest interrupt config */
    uint64_t CSR_GCNTC;         /* Guest counter compensation */

    /* Guest CSR registers (GCSR) */
    uint64_t GCSR_CRMD;
    uint64_t GCSR_PRMD;
    uint64_t GCSR_EUEN;
    uint64_t GCSR_MISC;
    uint64_t GCSR_ECFG;
    uint64_t GCSR_ESTAT;
    uint64_t GCSR_ERA;
    uint64_t GCSR_BADV;
    uint64_t GCSR_BADI;
    uint64_t GCSR_EENTRY;
    uint64_t GCSR_TLBIDX;
    uint64_t GCSR_TLBEHI;
    uint64_t GCSR_TLBELO0;
    uint64_t GCSR_TLBELO1;
    uint64_t GCSR_ASID;
    uint64_t GCSR_PGDL;
    uint64_t GCSR_PGDH;
    uint64_t GCSR_PGD;
    uint64_t GCSR_PWCL;
    uint64_t GCSR_PWCH;
    uint64_t GCSR_STLBPS;
    uint64_t GCSR_RVACFG;
    uint64_t GCSR_CPUID;
    uint64_t GCSR_PRCFG1;
    uint64_t GCSR_PRCFG2;
    uint64_t GCSR_PRCFG3;
    uint64_t GCSR_SAVE[16];
    uint64_t GCSR_TID;
    uint64_t GCSR_TCFG;
    uint64_t GCSR_TVAL;
    uint64_t GCSR_CNTC;
    uint64_t GCSR_TICLR;
    uint64_t GCSR_LLBCTL;
    uint64_t GCSR_IMPCTL1;
    uint64_t GCSR_IMPCTL2;
    uint64_t GCSR_TLBRENTRY;
    uint64_t GCSR_TLBRBADV;
    uint64_t GCSR_TLBRERA;
    uint64_t GCSR_TLBRSAVE;
    uint64_t GCSR_TLBRELO0;
    uint64_t GCSR_TLBRELO1;
    uint64_t GCSR_TLBREHI;
    uint64_t GCSR_TLBRPRMD;
    uint64_t GCSR_MERRCTL;
    uint64_t GCSR_MERRINFO1;
    uint64_t GCSR_MERRINFO2;
    uint64_t GCSR_MERRENTRY;
    uint64_t GCSR_MERRERA;
    uint64_t GCSR_MERRSAVE;
    uint64_t GCSR_CTAG;
    uint64_t GCSR_DMW[4];
    uint64_t GCSR_DBG;
    uint64_t GCSR_DERA;
    uint64_t GCSR_DSAVE;

    /* LVZ second-level address translation related fields */
    uint64_t CSR_GTLBC;         /* Guest TLB control */
    uint64_t CSR_TRGP;          /* Trapped guest physical address */
    VMExitContext vm_exit_ctx;  /* VM exit context */
    bool lvz_enabled;           /* LVZ virtualization enabled flag */

#ifdef CONFIG_TCG
    float_status fp_status;
    uint32_t fcsr0_mask;
    uint64_t lladdr; /* LL virtual address compared against SC */
    uint64_t llval;
#endif
#ifndef CONFIG_USER_ONLY
#ifdef CONFIG_TCG
    LoongArchTLB  tlb[LOONGARCH_TLB_MAX];
#endif

    AddressSpace *address_space_iocsr;
    bool load_elf;
    uint64_t elf_address;
    uint32_t mp_state;
    /* Store ipistate to access from this struct */
    DeviceState *ipistate;

    struct loongarch_boot_info *boot_info;
#endif
} CPULoongArchState;

/**
 * LoongArchCPU:
 * @env: #CPULoongArchState
 *
 * A LoongArch CPU.
 */
struct ArchCPU {
    CPUState parent_obj;

    CPULoongArchState env;
    QEMUTimer timer;
    uint32_t  phy_id;

    /* 'compatible' string for this CPU for Linux device trees */
    const char *dtb_compatible;
    /* used by KVM_REG_LOONGARCH_COUNTER ioctl to access guest time counters */
    uint64_t kvm_state_counter;
};

/**
 * LoongArchCPUClass:
 * @parent_realize: The parent class' realize handler.
 * @parent_phases: The parent class' reset phase handlers.
 *
 * A LoongArch CPU model.
 */
struct LoongArchCPUClass {
    CPUClass parent_class;

    DeviceRealize parent_realize;
    ResettablePhases parent_phases;
};

/*
 * LoongArch CPUs has 4 privilege levels.
 * 0 for kernel mode, 3 for user mode.
 * Define an extra index for DA(direct addressing) mode.
 */
#define MMU_PLV_KERNEL   0
#define MMU_PLV_USER     3
#define MMU_KERNEL_IDX   MMU_PLV_KERNEL
#define MMU_USER_IDX     MMU_PLV_USER
#define MMU_DA_IDX       4

static inline bool is_la64(CPULoongArchState *env)
{
    return FIELD_EX32(env->cpucfg[1], CPUCFG1, ARCH) == CPUCFG1_ARCH_LA64;
}

static inline bool is_va32(CPULoongArchState *env)
{
    /* VA32 if !LA64 or VA32L[1-3] */
    bool va32 = !is_la64(env);
    uint64_t plv = FIELD_EX64(env->CSR_CRMD, CSR_CRMD, PLV);
    if (plv >= 1 && (FIELD_EX64(env->CSR_MISC, CSR_MISC, VA32) & (1 << plv))) {
        va32 = true;
    }
    return va32;
}

static inline void set_pc(CPULoongArchState *env, uint64_t value)
{
    if (is_va32(env)) {
        env->pc = (uint32_t)value;
    } else {
        env->pc = value;
    }
}

/*
 * LoongArch CPUs hardware flags.
 */
#define HW_FLAGS_PLV_MASK   R_CSR_CRMD_PLV_MASK  /* 0x03 */
#define HW_FLAGS_EUEN_FPE   0x04
#define HW_FLAGS_EUEN_SXE   0x08
#define HW_FLAGS_CRMD_PG    R_CSR_CRMD_PG_MASK   /* 0x10 */
#define HW_FLAGS_VA32       0x20
#define HW_FLAGS_EUEN_ASXE  0x40

static inline void cpu_get_tb_cpu_state(CPULoongArchState *env, vaddr *pc,
                                        uint64_t *cs_base, uint32_t *flags)
{
    *pc = env->pc;
    *cs_base = 0;
    *flags = env->CSR_CRMD & (R_CSR_CRMD_PLV_MASK | R_CSR_CRMD_PG_MASK);
    *flags |= FIELD_EX64(env->CSR_EUEN, CSR_EUEN, FPE) * HW_FLAGS_EUEN_FPE;
    *flags |= FIELD_EX64(env->CSR_EUEN, CSR_EUEN, SXE) * HW_FLAGS_EUEN_SXE;
    *flags |= FIELD_EX64(env->CSR_EUEN, CSR_EUEN, ASXE) * HW_FLAGS_EUEN_ASXE;
    *flags |= is_va32(env) * HW_FLAGS_VA32;
}

#include "exec/cpu-all.h"

#define CPU_RESOLVING_TYPE TYPE_LOONGARCH_CPU

/* LVZ (LoongArch Virtualization) helper functions */
static inline bool has_lvz_capability(CPULoongArchState *env)
{
    return FIELD_EX32(env->cpucfg[2], CPUCFG2, LVZ);
}

static inline bool is_guest_mode(CPULoongArchState *env)
{
    return has_lvz_capability(env) && FIELD_EX64(env->CSR_GSTAT, CSR_GSTAT, VM);
}

static inline uint8_t get_guest_id(CPULoongArchState *env)
{
    return FIELD_EX64(env->CSR_GSTAT, CSR_GSTAT, GID);
}

/* Enhanced virtual machine mode judgment function */
static inline bool is_virtualization_mode_active(CPULoongArchState *env)
{
    return has_lvz_capability(env) && env->lvz_enabled;
}

/* Enhanced GID query function with validation */
static inline uint8_t get_current_effective_gid(CPULoongArchState *env)
{
    if (!is_virtualization_mode_active(env)) {
        return 0; /* Host mode always uses GID 0 */
    }
    
    if (is_guest_mode(env)) {
        return get_guest_id(env);
    }
    
    return 0; /* Hypervisor mode uses GID 0 */
}

/* Check if current execution is in guest context */
static inline bool is_guest_execution_context(CPULoongArchState *env)
{
    return is_virtualization_mode_active(env) && is_guest_mode(env);
}

/* Check if current execution is in hypervisor context */
static inline bool is_hypervisor_execution_context(CPULoongArchState *env)
{
    return is_virtualization_mode_active(env) && !is_guest_mode(env);
}

/* Get target GID for TLB operations */
static inline uint8_t get_target_gid(CPULoongArchState *env)
{
    if (!is_virtualization_mode_active(env)) {
        return 0;
    }
    
    /* Check if GTLBC.USETGID is set */
    if (FIELD_EX64(env->CSR_GTLBC, CSR_GTLBC, USETGID)) {
        return FIELD_EX64(env->CSR_GTLBC, CSR_GTLBC, TGID);
    }
    
    /* Use current effective GID */
    return get_current_effective_gid(env);
}

/* Validate GID bounds */
static inline bool is_valid_gid(uint8_t gid)
{
    /* For uint8_t, all values 0-255 are valid by definition */
    /* This function is kept for API consistency and future enhancement */
    (void)gid; /* Suppress unused parameter warning */
    return true;
}

/* Second-level address translation framework functions */
static inline bool is_second_level_translation_enabled(CPULoongArchState *env)
{
    return is_guest_mode(env) && has_lvz_capability(env) && env->lvz_enabled;
}

static inline bool should_trigger_vm_exit(CPULoongArchState *env, uint32_t exit_reason)
{
    /* Only trigger VM exit if in guest mode */
    if (!is_guest_execution_context(env)) {
        return false;
    }
    
    /* Check if this exit reason should trigger VM exit based on CSR_GCFG */
    uint64_t gcfg = env->CSR_GCFG;
    
    switch (exit_reason) {
    case VMEXIT_MMIO:
        return FIELD_EX64(gcfg, CSR_GCFG, TOEP);  /* Trap On Error Page fault */
    case VMEXIT_TIMER:
        return FIELD_EX64(gcfg, CSR_GCFG, TOE);   /* Trap On timer Expire */
    case VMEXIT_IOCSR:
        return FIELD_EX64(gcfg, CSR_GCFG, TIT);   /* Trap on Interrupt and Timer */
    case VMEXIT_CSRR:
    case VMEXIT_CSRW:
    case VMEXIT_CSRX:
        return FIELD_EX64(gcfg, CSR_GCFG, TOEP);
    case VMEXIT_HYPERCALL:
        return true;  /* HVCL always triggers VM exit */
    case VMEXIT_TLB:
        return FIELD_EX64(env->CSR_GTLBC, CSR_GTLBC, TOTI); /* Trap on TLB instruction */
    case VMEXIT_CPUCFG:
        return FIELD_EX64(gcfg, CSR_GCFG, TOEP);
    case VMEXIT_CACHE:
        return FIELD_EX64(gcfg, CSR_GCFG, TOEP);
    default:
        return FIELD_EX64(gcfg, CSR_GCFG, TOEP);
    }
}

static inline void prepare_vm_exit_context(CPULoongArchState *env, 
                                         uint64_t fault_gpa, 
                                         uint64_t fault_gva,
                                         uint32_t exit_reason,
                                         uint32_t access_type)
{
    if (!is_guest_execution_context(env)) {
        return;
    }
    
    /* Prepare VM exit context information */
    env->vm_exit_ctx.fault_gpa = fault_gpa;
    env->vm_exit_ctx.fault_gva = fault_gva;
    env->vm_exit_ctx.gid = get_guest_id(env);
    env->vm_exit_ctx.exit_reason = exit_reason;
    env->vm_exit_ctx.access_type = access_type;
    env->vm_exit_ctx.is_tlb_refill = (exit_reason == VMEXIT_TLB);
    
    /* Store fault GPA in CSR_TRGP for hypervisor access */
    env->CSR_TRGP = fault_gpa;
    
    /* Note: Detailed logging moved to implementation functions to avoid header dependencies */
}

static inline bool tlb_entry_matches_gid(uint64_t tlb_misc, uint8_t gid)
{
    uint8_t entry_gid = FIELD_EX64(tlb_misc, TLB_MISC, GID);
    return entry_gid == gid && FIELD_EX64(tlb_misc, TLB_MISC, E); /* Also check if entry is enabled */
}

/* Enhanced TLB entry matching with address space validation */
static inline bool tlb_entry_matches_context(CPULoongArchState *env, 
                                            const LoongArchTLB *tlb, 
                                            uint8_t target_gid)
{
    if (!has_lvz_capability(env)) {
        return FIELD_EX64(tlb->tlb_misc, TLB_MISC, E); /* Just check if enabled */
    }
    
    uint8_t entry_gid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, GID);
    bool entry_enabled = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);
    
    return entry_enabled && (entry_gid == target_gid);
}

/* Second-level TLB lookup and management */
static inline bool is_guest_page_tlb_entry(uint64_t tlb_misc)
{
    /* Guest page TLB entries have non-zero GID */
    return FIELD_EX64(tlb_misc, TLB_MISC, GID) != 0;
}

static inline bool is_vmm_page_tlb_entry(uint64_t tlb_misc)
{
    /* VMM page TLB entries have zero GID for second-level translation */
    return FIELD_EX64(tlb_misc, TLB_MISC, GID) == 0;
}

/* Access type definitions for second-level translation */
#define ACCESS_TYPE_READ    1
#define ACCESS_TYPE_WRITE   2
#define ACCESS_TYPE_EXEC    4

/* Second-level translation flags */
#define SECOND_LEVEL_VALID      0x01
#define SECOND_LEVEL_READABLE   0x02
#define SECOND_LEVEL_WRITABLE   0x04
#define SECOND_LEVEL_EXECUTABLE 0x08

/* Enhanced second-level translation state management */
static inline void enable_second_level_translation(CPULoongArchState *env)
{
    if (has_lvz_capability(env)) {
        env->lvz_enabled = true;
        /* Logging moved to implementation to avoid header dependencies */
    }
}

static inline void disable_second_level_translation(CPULoongArchState *env)
{
    env->lvz_enabled = false;
    /* Logging moved to implementation to avoid header dependencies */
}

/* Get the effective page size for translation */
static inline uint32_t get_effective_page_size(CPULoongArchState *env, int tlb_index)
{
    if (tlb_index >= LOONGARCH_STLB) {
        /* MTLB entry - use PS field from TLB entry */
        return FIELD_EX64(env->tlb[tlb_index].tlb_misc, TLB_MISC, PS);
    } else {
        /* STLB entry - use system STLB page size */
        return FIELD_EX64(env->CSR_STLBPS, CSR_STLBPS, PS);
    }
}

/* Check if a virtual address is in guest direct-mapped window */
static inline bool is_guest_direct_mapped(CPULoongArchState *env, vaddr va)
{
    if (!is_guest_execution_context(env)) {
        return false;
    }
    
    /* Check guest DMW entries */
    for (int i = 0; i < 4; i++) {
        uint64_t dmw = env->GCSR_DMW[i];
        if (is_la64(env)) {
            uint64_t vseg = FIELD_EX64(dmw, CSR_DMW_64, VSEG);
            if ((va >> 60) == vseg) {
                return true;
            }
        } else {
            uint32_t vseg = FIELD_EX32(dmw, CSR_DMW_32, VSEG);
            if ((va >> 29) == vseg) {
                return true;
            }
        }
    }
    
    return false;
}

void loongarch_cpu_post_init(Object *obj);

/* Second-level address translation framework function declarations */
#ifndef CONFIG_USER_ONLY
bool loongarch_second_level_translate(CPULoongArchState *env, 
                                     hwaddr gpa, 
                                     hwaddr *hpa,
                                     int access_type, 
                                     int mmu_idx,
                                     bool *vm_exit_required);

void loongarch_trigger_vm_exit(CPULoongArchState *env, 
                               uint32_t exit_reason,
                               uint64_t fault_gpa, 
                               uint64_t fault_gva);

bool loongarch_guest_tlb_lookup(CPULoongArchState *env, 
                               vaddr va, 
                               hwaddr *gpa,
                               int access_type, 
                               int mmu_idx);

bool loongarch_vmm_tlb_lookup(CPULoongArchState *env, 
                             hwaddr gpa, 
                             hwaddr *hpa,
                             int access_type, 
                             int mmu_idx);

void loongarch_fill_guest_tlb(CPULoongArchState *env, 
                             vaddr va, 
                             hwaddr gpa,
                             uint32_t flags, 
                             int mmu_idx);

void loongarch_fill_vmm_tlb(CPULoongArchState *env, 
                           hwaddr gpa, 
                           hwaddr hpa,
                           uint32_t flags, 
                           int mmu_idx);

void loongarch_clear_guest_tlb_by_gid(CPULoongArchState *env, uint8_t gid);

void loongarch_flush_guest_tlb_by_gid(CPULoongArchState *env, uint8_t gid);

int loongarch_search_guest_tlb(CPULoongArchState *env, 
                              vaddr va, 
                              uint8_t gid);

void loongarch_init_second_level_translation(CPULoongArchState *env);

/* TLB helper functions with guest support */
int loongarch_tlb_search_guest(CPULoongArchState *env, target_ulong vaddr, int *index);

bool loongarch_cpu_tlb_fill_guest(CPUState *cs, vaddr address, int size,
                                   MMUAccessType access_type, int mmu_idx,
                                   bool probe, uintptr_t retaddr);
#endif

#endif /* LOONGARCH_CPU_H */
