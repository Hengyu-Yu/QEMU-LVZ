/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QEMU LoongArch CSRs
 *
 * Copyright (c) 2021 Loongson Technology Corporation Limited
 */

#ifndef LOONGARCH_CPU_CSR_H
#define LOONGARCH_CPU_CSR_H

#include "hw/registerfields.h"

/* Based on kernel definitions: arch/loongarch/include/asm/loongarch.h */

/* Basic CSRs */
#define LOONGARCH_CSR_CRMD           0x0 /* Current mode info */

#define LOONGARCH_CSR_PRMD           0x1 /* Prev-exception mode info */
FIELD(CSR_PRMD, PPLV, 0, 2)
FIELD(CSR_PRMD, PIE, 2, 1)
FIELD(CSR_PRMD, PWE, 3, 1)

#define LOONGARCH_CSR_EUEN           0x2 /* Extended unit enable */
FIELD(CSR_EUEN, FPE, 0, 1)
FIELD(CSR_EUEN, SXE, 1, 1)
FIELD(CSR_EUEN, ASXE, 2, 1)
FIELD(CSR_EUEN, BTE, 3, 1)

#define LOONGARCH_CSR_MISC           0x3 /* Misc config */
FIELD(CSR_MISC, VA32, 0, 4)
FIELD(CSR_MISC, DRDTL, 4, 4)
FIELD(CSR_MISC, RPCNTL, 8, 4)
FIELD(CSR_MISC, ALCL, 12, 4)
FIELD(CSR_MISC, DWPL, 16, 3)

#define LOONGARCH_CSR_ECFG           0x4 /* Exception config */
FIELD(CSR_ECFG, LIE, 0, 13)
FIELD(CSR_ECFG, VS, 16, 3)

#define LOONGARCH_CSR_ESTAT          0x5 /* Exception status */
FIELD(CSR_ESTAT, IS, 0, 13)
FIELD(CSR_ESTAT, ECODE, 16, 6)
FIELD(CSR_ESTAT, ESUBCODE, 22, 9)

#define LOONGARCH_CSR_ERA            0x6 /* Exception return address */

#define LOONGARCH_CSR_BADV           0x7 /* Bad virtual address */

#define LOONGARCH_CSR_BADI           0x8 /* Bad instruction */

#define LOONGARCH_CSR_EENTRY         0xc /* Exception entry address */

/* TLB related CSRs */
#define LOONGARCH_CSR_TLBIDX         0x10 /* TLB Index, EHINV, PageSize, NP */
FIELD(CSR_TLBIDX, INDEX, 0, 12)
FIELD(CSR_TLBIDX, PS, 24, 6)
FIELD(CSR_TLBIDX, NE, 31, 1)

#define LOONGARCH_CSR_TLBEHI         0x11 /* TLB EntryHi */
FIELD(CSR_TLBEHI_32, VPPN, 13, 19)
FIELD(CSR_TLBEHI_64, VPPN, 13, 35)

#define LOONGARCH_CSR_TLBELO0        0x12 /* TLB EntryLo0 */
#define LOONGARCH_CSR_TLBELO1        0x13 /* TLB EntryLo1 */
FIELD(TLBENTRY, V, 0, 1)
FIELD(TLBENTRY, D, 1, 1)
FIELD(TLBENTRY, PLV, 2, 2)
FIELD(TLBENTRY, MAT, 4, 2)
FIELD(TLBENTRY, G, 6, 1)
FIELD(TLBENTRY, HUGE, 6, 1)
FIELD(TLBENTRY, HGLOBAL, 12, 1)
FIELD(TLBENTRY, LEVEL, 13, 2)
FIELD(TLBENTRY_32, PPN, 8, 24)
FIELD(TLBENTRY_64, PPN, 12, 36)
FIELD(TLBENTRY_64, NR, 61, 1)
FIELD(TLBENTRY_64, NX, 62, 1)
FIELD(TLBENTRY_64, RPLV, 63, 1)

#define LOONGARCH_CSR_ASID           0x18 /* Address space identifier */
FIELD(CSR_ASID, ASID, 0, 10)
FIELD(CSR_ASID, ASIDBITS, 16, 8)

/* Page table base address when badv[47] = 0 */
#define LOONGARCH_CSR_PGDL           0x19
/* Page table base address when badv[47] = 1 */
#define LOONGARCH_CSR_PGDH           0x1a

#define LOONGARCH_CSR_PGD            0x1b /* Page table base address */

/* Page walk controller's low addr */
#define LOONGARCH_CSR_PWCL           0x1c
FIELD(CSR_PWCL, PTBASE, 0, 5)
FIELD(CSR_PWCL, PTWIDTH, 5, 5)
FIELD(CSR_PWCL, DIR1_BASE, 10, 5)
FIELD(CSR_PWCL, DIR1_WIDTH, 15, 5)
FIELD(CSR_PWCL, DIR2_BASE, 20, 5)
FIELD(CSR_PWCL, DIR2_WIDTH, 25, 5)
FIELD(CSR_PWCL, PTEWIDTH, 30, 2)

/* Page walk controller's high addr */
#define LOONGARCH_CSR_PWCH           0x1d
FIELD(CSR_PWCH, DIR3_BASE, 0, 6)
FIELD(CSR_PWCH, DIR3_WIDTH, 6, 6)
FIELD(CSR_PWCH, DIR4_BASE, 12, 6)
FIELD(CSR_PWCH, DIR4_WIDTH, 18, 6)

#define LOONGARCH_CSR_STLBPS         0x1e /* Stlb page size */
FIELD(CSR_STLBPS, PS, 0, 5)

#define LOONGARCH_CSR_RVACFG         0x1f /* Reduced virtual address config */
FIELD(CSR_RVACFG, RBITS, 0, 4)

/* Config CSRs */
#define LOONGARCH_CSR_CPUID          0x20 /* CPU core id */

#define LOONGARCH_CSR_PRCFG1         0x21 /* Config1 */
FIELD(CSR_PRCFG1, SAVE_NUM, 0, 4)
FIELD(CSR_PRCFG1, TIMER_BITS, 4, 8)
FIELD(CSR_PRCFG1, VSMAX, 12, 3)

#define LOONGARCH_CSR_PRCFG2         0x22 /* Config2 */

#define LOONGARCH_CSR_PRCFG3         0x23 /* Config3 */
FIELD(CSR_PRCFG3, TLB_TYPE, 0, 4)
FIELD(CSR_PRCFG3, MTLB_ENTRY, 4, 8)
FIELD(CSR_PRCFG3, STLB_WAYS, 12, 8)
FIELD(CSR_PRCFG3, STLB_SETS, 20, 8)

/*
 * Save registers count can read from PRCFG1.SAVE_NUM
 * The Min count is 1. Max count is 15.
 */
#define LOONGARCH_CSR_SAVE(N)        (0x30 + N)

/* Timer CSRs */
#define LOONGARCH_CSR_TID            0x40 /* Timer ID */

#define LOONGARCH_CSR_TCFG           0x41 /* Timer config */
FIELD(CSR_TCFG, EN, 0, 1)
FIELD(CSR_TCFG, PERIODIC, 1, 1)
FIELD(CSR_TCFG, INIT_VAL, 2, 46)

#define LOONGARCH_CSR_TVAL           0x42 /* Timer ticks remain */

#define LOONGARCH_CSR_CNTC           0x43 /* Timer offset */

#define LOONGARCH_CSR_TICLR          0x44 /* Timer interrupt clear */

/* LLBCTL CSRs */
#define LOONGARCH_CSR_LLBCTL         0x60 /* LLBit control */
FIELD(CSR_LLBCTL, ROLLB, 0, 1)
FIELD(CSR_LLBCTL, WCLLB, 1, 1)
FIELD(CSR_LLBCTL, KLO, 2, 1)

/* Implement dependent */
#define LOONGARCH_CSR_IMPCTL1        0x80 /* LoongArch config1 */

#define LOONGARCH_CSR_IMPCTL2        0x81 /* LoongArch config2*/

/* TLB Refill CSRs */
#define LOONGARCH_CSR_TLBRENTRY      0x88 /* TLB refill exception address */
#define LOONGARCH_CSR_TLBRBADV       0x89 /* TLB refill badvaddr */
#define LOONGARCH_CSR_TLBRERA        0x8a /* TLB refill ERA */
#define LOONGARCH_CSR_TLBRSAVE       0x8b /* KScratch for TLB refill */
FIELD(CSR_TLBRERA, ISTLBR, 0, 1)
FIELD(CSR_TLBRERA, PC, 2, 62)
#define LOONGARCH_CSR_TLBRELO0       0x8c /* TLB refill entrylo0 */
#define LOONGARCH_CSR_TLBRELO1       0x8d /* TLB refill entrylo1 */
#define LOONGARCH_CSR_TLBREHI        0x8e /* TLB refill entryhi */
FIELD(CSR_TLBREHI, PS, 0, 6)
FIELD(CSR_TLBREHI_32, VPPN, 13, 19)
FIELD(CSR_TLBREHI_64, VPPN, 13, 35)
#define LOONGARCH_CSR_TLBRPRMD       0x8f /* TLB refill mode info */
FIELD(CSR_TLBRPRMD, PPLV, 0, 2)
FIELD(CSR_TLBRPRMD, PIE, 2, 1)
FIELD(CSR_TLBRPRMD, PWE, 4, 1)

/* Machine Error CSRs */
#define LOONGARCH_CSR_MERRCTL        0x90 /* ERRCTL */
FIELD(CSR_MERRCTL, ISMERR, 0, 1)
#define LOONGARCH_CSR_MERRINFO1      0x91
#define LOONGARCH_CSR_MERRINFO2      0x92
#define LOONGARCH_CSR_MERRENTRY      0x93 /* MError exception base */
#define LOONGARCH_CSR_MERRERA        0x94 /* MError exception PC */
#define LOONGARCH_CSR_MERRSAVE       0x95 /* KScratch for error exception */

#define LOONGARCH_CSR_CTAG           0x98 /* TagLo + TagHi */

/* Direct map windows CSRs*/
#define LOONGARCH_CSR_DMW(N)         (0x180 + N)
FIELD(CSR_DMW, PLV0, 0, 1)
FIELD(CSR_DMW, PLV1, 1, 1)
FIELD(CSR_DMW, PLV2, 2, 1)
FIELD(CSR_DMW, PLV3, 3, 1)
FIELD(CSR_DMW, MAT, 4, 2)
FIELD(CSR_DMW_32, PSEG, 25, 3)
FIELD(CSR_DMW_32, VSEG, 29, 3)
FIELD(CSR_DMW_64, VSEG, 60, 4)

/* Debug CSRs */
#define LOONGARCH_CSR_DBG            0x500 /* debug config */
FIELD(CSR_DBG, DST, 0, 1)
FIELD(CSR_DBG, DREV, 1, 7)
FIELD(CSR_DBG, DEI, 8, 1)
FIELD(CSR_DBG, DCL, 9, 1)
FIELD(CSR_DBG, DFW, 10, 1)
FIELD(CSR_DBG, DMW, 11, 1)
FIELD(CSR_DBG, ECODE, 16, 6)

#define LOONGARCH_CSR_DERA           0x501 /* Debug era */
#define LOONGARCH_CSR_DSAVE          0x502 /* Debug save */

/* LVZ (LoongArch Virtualization) CSRs */
/* Guest Status and Control CSRs */
#define LOONGARCH_CSR_GSTAT          0x50 /* Guest status */
FIELD(CSR_GSTAT, GID, 0, 8)      /* Guest ID */
FIELD(CSR_GSTAT, GIDBIT, 8, 4)   /* Guest ID bits */
FIELD(CSR_GSTAT, PVM, 16, 1)     /* Previous virtualization mode */
FIELD(CSR_GSTAT, VM, 17, 1)      /* Virtualization mode */

#define LOONGARCH_CSR_GCFG           0x51 /* Guest config */
FIELD(CSR_GCFG, GCIP, 0, 1)      /* Guest counter in privileged mode */
FIELD(CSR_GCFG, GCOP, 1, 1)      /* Guest counter in operating mode */
FIELD(CSR_GCFG, MATP, 2, 2)      /* Memory access type for privileged mode */
FIELD(CSR_GCFG, MATO, 4, 2)      /* Memory access type for operating mode */
FIELD(CSR_GCFG, SITP, 6, 1)      /* Software interrupt in privileged mode */
FIELD(CSR_GCFG, SITO, 7, 1)      /* Software interrupt in operating mode */
FIELD(CSR_GCFG, TITP, 8, 1)      /* Timer interrupt in privileged mode */
FIELD(CSR_GCFG, TITO, 9, 1)      /* Timer interrupt in operating mode */

#define LOONGARCH_CSR_GINTC          0x52 /* Guest interrupt config */
FIELD(CSR_GINTC, VIP, 0, 8)      /* Virtual interrupt pending */
FIELD(CSR_GINTC, VIE, 8, 8)      /* Virtual interrupt enable */

#define LOONGARCH_CSR_GCNTC          0x53 /* Guest counter compensation */

/* Guest CSR (GCSR) registers - aliases for guest mode access */
#define LOONGARCH_GCSR_CRMD          0x2000 /* Guest CRMD */
#define LOONGARCH_GCSR_PRMD          0x2001 /* Guest PRMD */
#define LOONGARCH_GCSR_EUEN          0x2002 /* Guest EUEN */
#define LOONGARCH_GCSR_MISC          0x2003 /* Guest MISC */
#define LOONGARCH_GCSR_ECFG          0x2004 /* Guest ECFG */
#define LOONGARCH_GCSR_ESTAT         0x2005 /* Guest ESTAT */
#define LOONGARCH_GCSR_ERA           0x2006 /* Guest ERA */
#define LOONGARCH_GCSR_BADV          0x2007 /* Guest BADV */
#define LOONGARCH_GCSR_BADI          0x2008 /* Guest BADI */
#define LOONGARCH_GCSR_EENTRY        0x200c /* Guest EENTRY */

/* Guest TLB related GCSRs */
#define LOONGARCH_GCSR_TLBIDX        0x2010 /* Guest TLBIDX */
#define LOONGARCH_GCSR_TLBEHI        0x2011 /* Guest TLBEHI */
#define LOONGARCH_GCSR_TLBELO0       0x2012 /* Guest TLBELO0 */
#define LOONGARCH_GCSR_TLBELO1       0x2013 /* Guest TLBELO1 */
#define LOONGARCH_GCSR_ASID          0x2018 /* Guest ASID */
#define LOONGARCH_GCSR_PGDL          0x2019 /* Guest PGDL */
#define LOONGARCH_GCSR_PGDH          0x201a /* Guest PGDH */
#define LOONGARCH_GCSR_PGD           0x201b /* Guest PGD */
#define LOONGARCH_GCSR_PWCL          0x201c /* Guest PWCL */
#define LOONGARCH_GCSR_PWCH          0x201d /* Guest PWCH */
#define LOONGARCH_GCSR_STLBPS        0x201e /* Guest STLBPS */
#define LOONGARCH_GCSR_RVACFG        0x201f /* Guest RVACFG */

/* Guest Config GCSRs */
#define LOONGARCH_GCSR_CPUID         0x2020 /* Guest CPUID */
#define LOONGARCH_GCSR_PRCFG1        0x2021 /* Guest PRCFG1 */
#define LOONGARCH_GCSR_PRCFG2        0x2022 /* Guest PRCFG2 */
#define LOONGARCH_GCSR_PRCFG3        0x2023 /* Guest PRCFG3 */

/* Guest Save registers */
#define LOONGARCH_GCSR_SAVE(N)       (0x2030 + N) /* Guest SAVE(N) */

/* Guest Timer GCSRs */
#define LOONGARCH_GCSR_TID           0x2040 /* Guest TID */
#define LOONGARCH_GCSR_TCFG          0x2041 /* Guest TCFG */
#define LOONGARCH_GCSR_TVAL          0x2042 /* Guest TVAL */
#define LOONGARCH_GCSR_CNTC          0x2043 /* Guest CNTC */
#define LOONGARCH_GCSR_TICLR         0x2044 /* Guest TICLR */

/* Guest LLBCTL GCSR */
#define LOONGARCH_GCSR_LLBCTL        0x2060 /* Guest LLBCTL */

/* Guest Implementation dependent GCSRs */
#define LOONGARCH_GCSR_IMPCTL1       0x2080 /* Guest IMPCTL1 */
#define LOONGARCH_GCSR_IMPCTL2       0x2081 /* Guest IMPCTL2 */

/* Guest TLB Refill GCSRs */
#define LOONGARCH_GCSR_TLBRENTRY     0x2088 /* Guest TLBRENTRY */
#define LOONGARCH_GCSR_TLBRBADV      0x2089 /* Guest TLBRBADV */
#define LOONGARCH_GCSR_TLBRERA       0x208a /* Guest TLBRERA */
#define LOONGARCH_GCSR_TLBRSAVE      0x208b /* Guest TLBRSAVE */
#define LOONGARCH_GCSR_TLBRELO0      0x208c /* Guest TLBRELO0 */
#define LOONGARCH_GCSR_TLBRELO1      0x208d /* Guest TLBRELO1 */
#define LOONGARCH_GCSR_TLBREHI       0x208e /* Guest TLBREHI */
#define LOONGARCH_GCSR_TLBRPRMD      0x208f /* Guest TLBRPRMD */

/* Guest Machine Error GCSRs */
#define LOONGARCH_GCSR_MERRCTL       0x2090 /* Guest MERRCTL */
#define LOONGARCH_GCSR_MERRINFO1     0x2091 /* Guest MERRINFO1 */
#define LOONGARCH_GCSR_MERRINFO2     0x2092 /* Guest MERRINFO2 */
#define LOONGARCH_GCSR_MERRENTRY     0x2093 /* Guest MERRENTRY */
#define LOONGARCH_GCSR_MERRERA       0x2094 /* Guest MERRERA */
#define LOONGARCH_GCSR_MERRSAVE      0x2095 /* Guest MERRSAVE */
#define LOONGARCH_GCSR_CTAG          0x2098 /* Guest CTAG */

/* Guest Direct map windows GCSRs */
#define LOONGARCH_GCSR_DMW(N)        (0x2180 + N) /* Guest DMW(N) */

/* Guest Debug GCSRs */
#define LOONGARCH_GCSR_DBG           0x2500 /* Guest DBG */
#define LOONGARCH_GCSR_DERA          0x2501 /* Guest DERA */
#define LOONGARCH_GCSR_DSAVE         0x2502 /* Guest DSAVE */

#endif /* LOONGARCH_CPU_CSR_H */
