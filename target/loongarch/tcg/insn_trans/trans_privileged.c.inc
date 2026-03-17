/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2021 Loongson Technology Corporation Limited
 *
 * LoongArch translation routines for the privileged instructions.
 */

#include "cpu-csr.h"

#ifdef CONFIG_USER_ONLY

#define GEN_FALSE_TRANS(name)   \
static bool trans_##name(DisasContext *ctx, arg_##name * a)  \
{   \
    return false;   \
}

GEN_FALSE_TRANS(csrrd)
GEN_FALSE_TRANS(csrwr)
GEN_FALSE_TRANS(csrxchg)
GEN_FALSE_TRANS(iocsrrd_b)
GEN_FALSE_TRANS(iocsrrd_h)
GEN_FALSE_TRANS(iocsrrd_w)
GEN_FALSE_TRANS(iocsrrd_d)
GEN_FALSE_TRANS(iocsrwr_b)
GEN_FALSE_TRANS(iocsrwr_h)
GEN_FALSE_TRANS(iocsrwr_w)
GEN_FALSE_TRANS(iocsrwr_d)
GEN_FALSE_TRANS(tlbsrch)
GEN_FALSE_TRANS(tlbrd)
GEN_FALSE_TRANS(tlbwr)
GEN_FALSE_TRANS(tlbfill)
GEN_FALSE_TRANS(tlbclr)
GEN_FALSE_TRANS(tlbflush)
GEN_FALSE_TRANS(invtlb)
GEN_FALSE_TRANS(cacop)
GEN_FALSE_TRANS(ldpte)
GEN_FALSE_TRANS(lddir)
GEN_FALSE_TRANS(ertn)
GEN_FALSE_TRANS(dbcl)
GEN_FALSE_TRANS(idle)
GEN_FALSE_TRANS(gcsrrd)
GEN_FALSE_TRANS(gcsrwr)
GEN_FALSE_TRANS(gcsrxchg)
GEN_FALSE_TRANS(gtlbclr)
GEN_FALSE_TRANS(gtlbflush)
GEN_FALSE_TRANS(gtlbsrch)
GEN_FALSE_TRANS(gtlbrd)
GEN_FALSE_TRANS(gtlbwr)
GEN_FALSE_TRANS(gtlbfill)
GEN_FALSE_TRANS(hvcl)

#else

typedef void (*GenCSRRead)(TCGv dest, TCGv_ptr env);
typedef void (*GenCSRWrite)(TCGv dest, TCGv_ptr env, TCGv src);

typedef struct {
    int offset;
    int flags;
    GenCSRRead readfn;
    GenCSRWrite writefn;
} CSRInfo;

enum {
    CSRFL_READONLY = (1 << 0),
    CSRFL_EXITTB   = (1 << 1),
    CSRFL_IO       = (1 << 2),
    CSRFL_GUEST_READONLY = (1 << 3),
    CSRFL_GSPR     = (1 << 4),
};

#define CSR_OFF_FUNCS(NAME, FL, RD, WR)                     \
    [LOONGARCH_CSR_##NAME] = {                              \
        .offset = offsetof(CPULoongArchState, CSR_##NAME),  \
        .flags = FL, .readfn = RD, .writefn = WR            \
    }

#define CSR_OFF_ARRAY(NAME, N)                                 \
    [LOONGARCH_CSR_##NAME(N)] = {                              \
        .offset = offsetof(CPULoongArchState, CSR_##NAME[N]),  \
        .flags = 0, .readfn = NULL, .writefn = NULL            \
    }

#define CSR_OFF_FLAGS(NAME, FL) \
    CSR_OFF_FUNCS(NAME, FL, NULL, NULL)

#define CSR_OFF(NAME) \
    CSR_OFF_FLAGS(NAME, 0)

#define GCSR_OFF_FUNCS(NAME, FL, RD, WR)                    \
    [LOONGARCH_CSR_##NAME] = {                             \
        .offset = offsetof(CPULoongArchState, GCSR_##NAME), \
        .flags = FL, .readfn = RD, .writefn = WR            \
    }

#define GCSR_OFF_ARRAY(NAME, N)                                \
    [LOONGARCH_CSR_##NAME(N)] = {                             \
        .offset = offsetof(CPULoongArchState, GCSR_##NAME[N]), \
        .flags = 0, .readfn = NULL, .writefn = NULL            \
    }

#define GCSR_OFF_FLAGS(NAME, FL) \
    GCSR_OFF_FUNCS(NAME, FL, NULL, NULL)

#define GCSR_OFF(NAME) \
    GCSR_OFF_FLAGS(NAME, 0)

#define GCSR_GSPR(NAME) \
    GCSR_OFF_FUNCS(NAME, CSRFL_GSPR, gen_helper_gspr_rd, gen_helper_gspr_wr)

static const CSRInfo csr_info[] = {
    CSR_OFF_FLAGS(CRMD, CSRFL_EXITTB),
    CSR_OFF(PRMD),
    CSR_OFF_FLAGS(EUEN, CSRFL_EXITTB),
    CSR_OFF_FLAGS(MISC, CSRFL_READONLY),
    CSR_OFF(ECFG),
    CSR_OFF_FUNCS(ESTAT, CSRFL_EXITTB, NULL, gen_helper_csrwr_estat),
    CSR_OFF(ERA),
    CSR_OFF(BADV),
    CSR_OFF_FLAGS(BADI, CSRFL_READONLY),
    CSR_OFF(EENTRY),
    CSR_OFF(TLBIDX),
    CSR_OFF(TLBEHI),
    CSR_OFF(TLBELO0),
    CSR_OFF(TLBELO1),
    CSR_OFF_FUNCS(ASID, CSRFL_EXITTB, NULL, gen_helper_csrwr_asid),
    CSR_OFF(PGDL),
    CSR_OFF(PGDH),
    CSR_OFF_FUNCS(PGD, CSRFL_READONLY, gen_helper_csrrd_pgd, NULL),
    CSR_OFF(PWCL),
    CSR_OFF(PWCH),
    CSR_OFF(STLBPS),
    CSR_OFF(RVACFG),
    CSR_OFF_FUNCS(CPUID, CSRFL_READONLY, gen_helper_csrrd_cpuid, NULL),
    CSR_OFF_FLAGS(PRCFG1, CSRFL_READONLY),
    CSR_OFF_FLAGS(PRCFG2, CSRFL_READONLY),
    CSR_OFF_FLAGS(PRCFG3, CSRFL_READONLY),
    CSR_OFF_ARRAY(SAVE, 0),
    CSR_OFF_ARRAY(SAVE, 1),
    CSR_OFF_ARRAY(SAVE, 2),
    CSR_OFF_ARRAY(SAVE, 3),
    CSR_OFF_ARRAY(SAVE, 4),
    CSR_OFF_ARRAY(SAVE, 5),
    CSR_OFF_ARRAY(SAVE, 6),
    CSR_OFF_ARRAY(SAVE, 7),
    CSR_OFF_ARRAY(SAVE, 8),
    CSR_OFF_ARRAY(SAVE, 9),
    CSR_OFF_ARRAY(SAVE, 10),
    CSR_OFF_ARRAY(SAVE, 11),
    CSR_OFF_ARRAY(SAVE, 12),
    CSR_OFF_ARRAY(SAVE, 13),
    CSR_OFF_ARRAY(SAVE, 14),
    CSR_OFF_ARRAY(SAVE, 15),
    CSR_OFF(TID),
    CSR_OFF_FUNCS(TCFG, CSRFL_IO, NULL, gen_helper_csrwr_tcfg),
    CSR_OFF_FUNCS(TVAL, CSRFL_READONLY | CSRFL_IO, gen_helper_csrrd_tval, NULL),
    CSR_OFF(CNTC),
    CSR_OFF_FUNCS(TICLR, CSRFL_IO, NULL, gen_helper_csrwr_ticlr),
    CSR_OFF(LLBCTL),
    CSR_OFF(IMPCTL1),
    CSR_OFF(IMPCTL2),
    CSR_OFF(TLBRENTRY),
    CSR_OFF(TLBRBADV),
    CSR_OFF(TLBRERA),
    CSR_OFF(TLBRSAVE),
    CSR_OFF(TLBRELO0),
    CSR_OFF(TLBRELO1),
    CSR_OFF(TLBREHI),
    CSR_OFF(TLBRPRMD),
    CSR_OFF(MERRCTL),
    CSR_OFF(MERRINFO1),
    CSR_OFF(MERRINFO2),
    CSR_OFF(MERRENTRY),
    CSR_OFF(MERRERA),
    CSR_OFF(MERRSAVE),
    CSR_OFF(CTAG),
    CSR_OFF_ARRAY(DMW, 0),
    CSR_OFF_ARRAY(DMW, 1),
    CSR_OFF_ARRAY(DMW, 2),
    CSR_OFF_ARRAY(DMW, 3),
    CSR_OFF(DBG),
    CSR_OFF(DERA),
    CSR_OFF(DSAVE),
    CSR_OFF(GTLBC),
    CSR_OFF(TRGP),
    CSR_OFF(GSTAT),
    CSR_OFF(GCFG),
    CSR_OFF(GINTC),
    CSR_OFF(GCNTC),
};

static const CSRInfo gcsr_info[] = {
    GCSR_OFF_FLAGS(CRMD, CSRFL_EXITTB),
    GCSR_OFF(PRMD),
    GCSR_OFF_FLAGS(EUEN, CSRFL_EXITTB),
    GCSR_OFF_FLAGS(MISC, CSRFL_GUEST_READONLY),
    GCSR_OFF(ECFG),
    GCSR_OFF_FUNCS(ESTAT, CSRFL_EXITTB, NULL, gen_helper_gcsrwr_estat),
    GCSR_OFF(ERA),
    GCSR_OFF(BADV),
    GCSR_OFF_FLAGS(BADI, CSRFL_GUEST_READONLY),
    GCSR_OFF(EENTRY),
    GCSR_OFF(TLBIDX),
    GCSR_OFF(TLBEHI),
    GCSR_OFF(TLBELO0),
    GCSR_OFF(TLBELO1),
    GCSR_OFF_FUNCS(ASID, CSRFL_EXITTB, NULL, gen_helper_gcsrwr_asid),
    GCSR_OFF(PGDL),
    GCSR_OFF(PGDH),
    GCSR_OFF_FUNCS(PGD, CSRFL_GUEST_READONLY, gen_helper_gcsrrd_pgd, NULL),
    GCSR_OFF(PWCL),
    GCSR_OFF(PWCH),
    GCSR_OFF(STLBPS),
    GCSR_OFF(RVACFG),
    GCSR_OFF_FLAGS(CPUID, CSRFL_GUEST_READONLY),
    GCSR_OFF_FLAGS(PRCFG1, CSRFL_GUEST_READONLY),
    GCSR_OFF_FLAGS(PRCFG2, CSRFL_GUEST_READONLY),
    GCSR_OFF_FLAGS(PRCFG3, CSRFL_GUEST_READONLY),
    GCSR_OFF_ARRAY(SAVE, 0),
    GCSR_OFF_ARRAY(SAVE, 1),
    GCSR_OFF_ARRAY(SAVE, 2),
    GCSR_OFF_ARRAY(SAVE, 3),
    GCSR_OFF_ARRAY(SAVE, 4),
    GCSR_OFF_ARRAY(SAVE, 5),
    GCSR_OFF_ARRAY(SAVE, 6),
    GCSR_OFF_ARRAY(SAVE, 7),
    GCSR_OFF_ARRAY(SAVE, 8),
    GCSR_OFF_ARRAY(SAVE, 9),
    GCSR_OFF_ARRAY(SAVE, 10),
    GCSR_OFF_ARRAY(SAVE, 11),
    GCSR_OFF_ARRAY(SAVE, 12),
    GCSR_OFF_ARRAY(SAVE, 13),
    GCSR_OFF_ARRAY(SAVE, 14),
    GCSR_OFF_ARRAY(SAVE, 15),
    GCSR_OFF(TID),
    GCSR_OFF_FLAGS(TCFG, CSRFL_IO),
    GCSR_OFF_FLAGS(TVAL, CSRFL_GUEST_READONLY | CSRFL_IO),
    GCSR_OFF(CNTC),
    GCSR_OFF_FUNCS(TICLR, CSRFL_IO, NULL, NULL),
    GCSR_OFF(LLBCTL),
    GCSR_GSPR(IMPCTL1),
    GCSR_GSPR(IMPCTL2),
    GCSR_OFF(TLBRENTRY),
    GCSR_OFF(TLBRBADV),
    GCSR_OFF(TLBRERA),
    GCSR_OFF(TLBRSAVE),
    GCSR_OFF(TLBRELO0),
    GCSR_OFF(TLBRELO1),
    GCSR_OFF(TLBREHI),
    GCSR_OFF(TLBRPRMD),
    GCSR_GSPR(MERRCTL),
    GCSR_GSPR(MERRINFO1),
    GCSR_GSPR(MERRINFO2),
    GCSR_GSPR(MERRENTRY),
    GCSR_GSPR(MERRERA),
    GCSR_GSPR(MERRSAVE),
    GCSR_GSPR(CTAG),
    GCSR_OFF_ARRAY(DMW, 0),
    GCSR_OFF_ARRAY(DMW, 1),
    GCSR_OFF_ARRAY(DMW, 2),
    GCSR_OFF_ARRAY(DMW, 3),
    GCSR_GSPR(DBG),
    GCSR_GSPR(DERA),
    GCSR_GSPR(DSAVE),
    GCSR_GSPR(GTLBC),
    GCSR_GSPR(TRGP),
    GCSR_GSPR(GSTAT),
    GCSR_GSPR(GCFG),
    GCSR_GSPR(GINTC),
    GCSR_GSPR(GCNTC),
};

static bool check_plv(DisasContext *ctx)
{
    if (ctx->plv == MMU_PLV_USER) {
        generate_exception(ctx, EXCCODE_IPE);
        return true;
    }
    return false;
}

static const CSRInfo *get_csr(unsigned csr_num)
{
    const CSRInfo *csr;

    if (csr_num >= ARRAY_SIZE(csr_info)) {
        return NULL;
    }
    csr = &csr_info[csr_num];
    if (csr->offset == 0) {
        return NULL;
    }
    return csr;
}

static const CSRInfo *get_gcsr(unsigned csr_num)
{
    const CSRInfo *csr;

    if (csr_num >= ARRAY_SIZE(csr_info)) {
        return NULL;
    }
    csr = &gcsr_info[csr_num];
    if (csr->offset == 0) {
        return NULL;
    }
    return csr;
}

static bool check_csr_flags(DisasContext *ctx, const CSRInfo *csr, bool write)
{
    if ((csr->flags & CSRFL_READONLY) && write) {
        return false;
    }

    if ((csr->flags & CSRFL_GUEST_READONLY) && ctx->guest_mode && write) {
        return false;
    }

    if ((csr->flags & CSRFL_IO) && translator_io_start(&ctx->base)) {
        ctx->base.is_jmp = DISAS_EXIT_UPDATE;
    } else if ((csr->flags & CSRFL_EXITTB) && write) {
        ctx->base.is_jmp = DISAS_EXIT_UPDATE;
    }
    return true;
}

static bool trans_csrrd(DisasContext *ctx, arg_csrrd *a)
{
    TCGv dest;
    const CSRInfo *csr;

    if (check_plv(ctx)) {
        return false;
    }
    if (ctx->guest_mode) {
        csr = get_gcsr(a->csr);
    } else {
        csr = get_csr(a->csr);
    }
    if (csr == NULL) {
        /* CSR is undefined: read as 0. */
        dest = tcg_constant_tl(0);
    } else {
        check_csr_flags(ctx, csr, false);
        dest = gpr_dst(ctx, a->rd, EXT_NONE);
        if (csr->readfn) {
            csr->readfn(dest, tcg_env);
        } else {
            tcg_gen_ld_tl(dest, tcg_env, csr->offset);
        }
    }
    gen_set_gpr(a->rd, dest, EXT_NONE);
    return true;
}

static bool trans_csrwr(DisasContext *ctx, arg_csrwr *a)
{
    TCGv dest, src1;
    const CSRInfo *csr;

    if (check_plv(ctx)) {
        return false;
    }
    if (ctx->guest_mode) {
        csr = get_gcsr(a->csr);
    } else {
        csr = get_csr(a->csr);
    }
    if (csr == NULL) {
        /* CSR is undefined: write ignored, read old_value as 0. */
        gen_set_gpr(a->rd, tcg_constant_tl(0), EXT_NONE);
        return true;
    }
    if (!check_csr_flags(ctx, csr, true)) {
        /* CSR is readonly: trap. */
        return false;
    }
    src1 = gpr_src(ctx, a->rd, EXT_NONE);
    if (csr->writefn) {
        dest = gpr_dst(ctx, a->rd, EXT_NONE);
        csr->writefn(dest, tcg_env, src1);
    } else {
        dest = tcg_temp_new();
        tcg_gen_ld_tl(dest, tcg_env, csr->offset);
        tcg_gen_st_tl(src1, tcg_env, csr->offset);
    }
    gen_set_gpr(a->rd, dest, EXT_NONE);
    return true;
}

static bool trans_csrxchg(DisasContext *ctx, arg_csrxchg *a)
{
    TCGv src1, mask, oldv, newv, temp;
    const CSRInfo *csr;

    if (check_plv(ctx)) {
        return false;
    }
    if (ctx->guest_mode) {
        csr = get_gcsr(a->csr);
    } else {
        csr = get_csr(a->csr);
    }
    if (csr == NULL) {
        /* CSR is undefined: write ignored, read old_value as 0. */
        gen_set_gpr(a->rd, tcg_constant_tl(0), EXT_NONE);
        return true;
    }

    if (!check_csr_flags(ctx, csr, true)) {
        /* CSR is readonly: trap. */
        return false;
    }

    src1 = gpr_src(ctx, a->rd, EXT_NONE);
    mask = gpr_src(ctx, a->rj, EXT_NONE);
    oldv = tcg_temp_new();
    newv = tcg_temp_new();
    temp = tcg_temp_new();

    if (csr->readfn) {
        csr->readfn(oldv, tcg_env);
    } else {
        tcg_gen_ld_tl(oldv, tcg_env, csr->offset);
    }
    tcg_gen_and_tl(newv, src1, mask);
    tcg_gen_andc_tl(temp, oldv, mask);
    tcg_gen_or_tl(newv, newv, temp);

    if (csr->writefn) {
        csr->writefn(oldv, tcg_env, newv);
    } else {
        tcg_gen_st_tl(newv, tcg_env, csr->offset);
    }
    gen_set_gpr(a->rd, oldv, EXT_NONE);
    return true;
}

static bool gen_iocsrrd(DisasContext *ctx, arg_rr *a,
                        void (*func)(TCGv, TCGv_ptr, TCGv))
{
    TCGv dest = gpr_dst(ctx, a->rd, EXT_NONE);
    TCGv src1 = gpr_src(ctx, a->rj, EXT_NONE);

    if (ctx->guest_mode) {
        gen_helper_gspr(tcg_env);
        ctx->base.is_jmp = DISAS_NORETURN;
        return true;
    }

    if (check_plv(ctx)) {
        return false;
    }
    func(dest, tcg_env, src1);
    return true;
}

static bool gen_iocsrwr(DisasContext *ctx, arg_rr *a,
                        void (*func)(TCGv_ptr, TCGv, TCGv))
{
    TCGv val = gpr_src(ctx, a->rd, EXT_NONE);
    TCGv addr = gpr_src(ctx, a->rj, EXT_NONE);

    if (ctx->guest_mode) {
        gen_helper_gspr(tcg_env);
        ctx->base.is_jmp = DISAS_NORETURN;
        return true;
    }

    if (check_plv(ctx)) {
        return false;
    }
    func(tcg_env, addr, val);
    return true;
}

TRANS(iocsrrd_b, IOCSR, gen_iocsrrd, gen_helper_iocsrrd_b)
TRANS(iocsrrd_h, IOCSR, gen_iocsrrd, gen_helper_iocsrrd_h)
TRANS(iocsrrd_w, IOCSR, gen_iocsrrd, gen_helper_iocsrrd_w)
TRANS(iocsrrd_d, IOCSR, gen_iocsrrd, gen_helper_iocsrrd_d)
TRANS(iocsrwr_b, IOCSR, gen_iocsrwr, gen_helper_iocsrwr_b)
TRANS(iocsrwr_h, IOCSR, gen_iocsrwr, gen_helper_iocsrwr_h)
TRANS(iocsrwr_w, IOCSR, gen_iocsrwr, gen_helper_iocsrwr_w)
TRANS(iocsrwr_d, IOCSR, gen_iocsrwr, gen_helper_iocsrwr_d)

static void check_mmu_idx(DisasContext *ctx)
{
    if (ctx->mem_idx != MMU_DA_IDX) {
        tcg_gen_movi_tl(cpu_pc, ctx->base.pc_next + 4);
        ctx->base.is_jmp = DISAS_EXIT;
    }
}

static bool trans_tlbsrch(DisasContext *ctx, arg_tlbsrch *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    gen_helper_tlbsrch(tcg_env);
    return true;
}

static bool trans_tlbrd(DisasContext *ctx, arg_tlbrd *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    gen_helper_tlbrd(tcg_env);
    return true;
}

static bool trans_tlbwr(DisasContext *ctx, arg_tlbwr *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    gen_helper_tlbwr(tcg_env);
    check_mmu_idx(ctx);
    return true;
}

static bool trans_tlbfill(DisasContext *ctx, arg_tlbfill *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    gen_helper_tlbfill(tcg_env);
    check_mmu_idx(ctx);
    return true;
}

static bool trans_tlbclr(DisasContext *ctx, arg_tlbclr *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    gen_helper_tlbclr(tcg_env);
    check_mmu_idx(ctx);
    return true;
}

static bool trans_tlbflush(DisasContext *ctx, arg_tlbflush *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    gen_helper_tlbflush(tcg_env);
    check_mmu_idx(ctx);
    return true;
}

static bool trans_invtlb(DisasContext *ctx, arg_invtlb *a)
{
    TCGv rj = gpr_src(ctx, a->rj, EXT_NONE);
    TCGv rk = gpr_src(ctx, a->rk, EXT_NONE);

    if (check_plv(ctx)) {
        return false;
    }

    if (!avail_LVZ(ctx) && (a->imm > 0x6)) return false;

    switch (a->imm) {
    case 0x0:
    case 0x1:
        gen_helper_invtlb_all(tcg_env, rj, tcg_constant_i32(a->imm), tcg_constant_i32(0));
        break;
    case 0x2:
        gen_helper_invtlb_all_g(tcg_env, rj, tcg_constant_i32(1), tcg_constant_i32(0));
        break;
    case 0x3:
        gen_helper_invtlb_all_g(tcg_env, rj, tcg_constant_i32(0), tcg_constant_i32(0));
        break;
    case 0x4:
        gen_helper_invtlb_all_asid(tcg_env, rj, tcg_constant_i32(0));
        break;
    case 0x5:
        gen_helper_invtlb_page_asid(tcg_env, rj, rk, tcg_constant_i32(0));
        break;
    case 0x6:
        gen_helper_invtlb_page_asid_or_g(tcg_env, rj, rk, tcg_constant_i32(0));
        break;
    case 0x9:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15:
    case 0x16:
        gen_helper_invtlb_all(tcg_env, rj, tcg_constant_i32(1), tcg_constant_i32(1));
        break;
    case 0xA:
        gen_helper_invtlb_all_g(tcg_env, rj, tcg_constant_i32(1), tcg_constant_i32(1));
        break;
    case 0xB:
        gen_helper_invtlb_all_g(tcg_env, rj, tcg_constant_i32(0), tcg_constant_i32(1));
        break;
    case 0xC:
        gen_helper_invtlb_all_asid(tcg_env, rj, tcg_constant_i32(1));
        break;
    case 0xD:
        gen_helper_invtlb_page_asid(tcg_env, rj, rk, tcg_constant_i32(1));
        break;
    case 0xE:
        gen_helper_invtlb_page_asid_or_g(tcg_env, rj, rk, tcg_constant_i32(1));
        break;

    default:
        return false;
    }
    ctx->base.is_jmp = DISAS_STOP;
    return true;
}

static bool trans_cacop(DisasContext *ctx, arg_cacop *a)
{
    /* Treat the cacop as a nop */
    if (check_plv(ctx)) {
        return false;
    }
    return true;
}

static bool trans_ldpte(DisasContext *ctx, arg_ldpte *a)
{
    TCGv_i32 mem_idx = tcg_constant_i32(ctx->mem_idx);
    TCGv src1 = gpr_src(ctx, a->rj, EXT_NONE);

    if (!avail_LSPW(ctx)) {
        return true;
    }

    if (check_plv(ctx)) {
        return false;
    }
    gen_helper_ldpte(tcg_env, src1, tcg_constant_tl(a->imm), mem_idx);
    return true;
}

static bool trans_lddir(DisasContext *ctx, arg_lddir *a)
{
    TCGv_i32 mem_idx = tcg_constant_i32(ctx->mem_idx);
    TCGv src = gpr_src(ctx, a->rj, EXT_NONE);
    TCGv dest = gpr_dst(ctx, a->rd, EXT_NONE);

    if (!avail_LSPW(ctx)) {
        return true;
    }

    if (check_plv(ctx)) {
        return false;
    }
    gen_helper_lddir(dest, tcg_env, src, tcg_constant_tl(a->imm), mem_idx);
    return true;
}

static bool trans_ertn(DisasContext *ctx, arg_ertn *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    gen_helper_ertn(tcg_env);
    ctx->base.is_jmp = DISAS_EXIT;
    return true;
}

static bool trans_dbcl(DisasContext *ctx, arg_dbcl *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    if (ctx->guest_mode) {
        gen_helper_gspr(tcg_env);
        ctx->base.is_jmp = DISAS_NORETURN;
        return true;
    }
    generate_exception(ctx, EXCCODE_DBP);
    return true;
}

static bool trans_idle(DisasContext *ctx, arg_idle *a)
{
    if (check_plv(ctx)) {
        return false;
    }

    if (ctx->guest_mode) {
        gen_helper_gspr(tcg_env);
        ctx->base.is_jmp = DISAS_NORETURN;
        return true;
    }

    tcg_gen_movi_tl(cpu_pc, ctx->base.pc_next + 4);
    gen_helper_idle(tcg_env);
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
}

/* LoongArch LVZ (Virtualization) Instructions */

static bool trans_gcsrrd(DisasContext *ctx, arg_gcsrrd *a)
{
    TCGv dest;
    const CSRInfo *csr;

    if (check_plv(ctx)) {
        return false;
    }
    
    /* Check if LVZ feature is enabled */
    if (!avail_LVZ(ctx) || ctx->guest_mode) {
        return false;
    }
    csr = get_gcsr(a->csr);
    if (csr == NULL) {
        /* CSR is undefined: read as 0. */
        dest = tcg_constant_tl(0);
    } else {
        check_csr_flags(ctx, csr, false);
        dest = gpr_dst(ctx, a->rd, EXT_NONE);
        if ((csr->flags & CSRFL_GSPR)) {
            tcg_gen_movi_tl(dest, 0);
        } else if (csr->readfn) {
            csr->readfn(dest, tcg_env);
        } else {
            tcg_gen_ld_tl(dest, tcg_env, csr->offset);
        }
    }
    gen_set_gpr(a->rd, dest, EXT_NONE);
    return true;
}

static bool trans_gcsrwr(DisasContext *ctx, arg_gcsrwr *a)
{

    TCGv dest, src1;
    const CSRInfo *csr;

    if (check_plv(ctx)) {
        return false;
    }
    /* Check if LVZ feature is enabled */
    if (!avail_LVZ(ctx) || ctx->guest_mode) {
        return false;
    }
    csr = get_gcsr(a->csr);
    if (csr == NULL) {
        /* CSR is undefined: write ignored, read old_value as 0. */
        gen_set_gpr(a->rd, tcg_constant_tl(0), EXT_NONE);
        return true;
    }
    if (!check_csr_flags(ctx, csr, true)) {
        /* CSR is readonly: trap. */
        return false;
    }
    src1 = gpr_src(ctx, a->rd, EXT_NONE);
    dest = tcg_temp_new();
    if ((csr->flags & CSRFL_GSPR)) {
        tcg_gen_movi_tl(dest, 0);
    } else if (csr->writefn) {
        csr->writefn(dest, tcg_env, src1);
    } else {
        tcg_gen_ld_tl(dest, tcg_env, csr->offset);
        tcg_gen_st_tl(src1, tcg_env, csr->offset);
    }
    gen_set_gpr(a->rd, dest, EXT_NONE);
    return true;
}

static bool trans_gcsrxchg(DisasContext *ctx, arg_gcsrxchg *a)
{
    TCGv src1, mask, oldv, newv, temp;
    const CSRInfo *csr;

    if (check_plv(ctx)) {
        return false;
    }
    /* Check if LVZ feature is enabled */
    if (!avail_LVZ(ctx) || ctx->guest_mode) {
        return false;
    }
    csr = get_gcsr(a->csr);
    if (csr == NULL) {
        /* CSR is undefined: write ignored, read old_value as 0. */
        gen_set_gpr(a->rd, tcg_constant_tl(0), EXT_NONE);
        return true;
    }

    if (!check_csr_flags(ctx, csr, true)) {
        /* CSR is readonly: trap. */
        return false;
    }

    src1 = gpr_src(ctx, a->rd, EXT_NONE);
    mask = gpr_src(ctx, a->rj, EXT_NONE);
    oldv = tcg_temp_new();
    newv = tcg_temp_new();
    temp = tcg_temp_new();

    if ((csr->flags & CSRFL_GSPR)) {
        tcg_gen_movi_tl(oldv, 0);
    } else if (csr->readfn) {
        csr->readfn(oldv, tcg_env);
    } else {
        tcg_gen_ld_tl(oldv, tcg_env, csr->offset);
    }
    tcg_gen_and_tl(newv, src1, mask);
    tcg_gen_andc_tl(temp, oldv, mask);
    tcg_gen_or_tl(newv, newv, temp);


    if ((csr->flags & CSRFL_GSPR)) {
        tcg_gen_movi_tl(oldv, 0);
    } if (csr->writefn) {
        csr->writefn(oldv, tcg_env, newv);
    } else {
        tcg_gen_st_tl(newv, tcg_env, csr->offset);
    }
    gen_set_gpr(a->rd, oldv, EXT_NONE);
    return true;
}

static bool trans_gtlbclr(DisasContext *ctx, arg_gtlbclr *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    
    /* Check if LVZ feature is enabled */
    if (!avail_LVZ(ctx)) {
        return false;
    }
    
    /* Clear guest TLB instruction */
    gen_helper_gtlbclr(tcg_env);
    check_mmu_idx(ctx);
    return true;
}

static bool trans_gtlbflush(DisasContext *ctx, arg_gtlbflush *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    
    /* Check if LVZ feature is enabled */
    if (!avail_LVZ(ctx)) {
        return false;
    }
    
    /* Flush guest TLB instruction */
    gen_helper_gtlbflush(tcg_env);
    check_mmu_idx(ctx);
    return true;
}

static bool trans_gtlbsrch(DisasContext *ctx, arg_gtlbsrch *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    
    /* Check if LVZ feature is enabled */
    if (!avail_LVZ(ctx)) {
        return false;
    }
    
    /* Search guest TLB instruction */
    gen_helper_gtlbsrch(tcg_env);
    return true;
}

static bool trans_gtlbrd(DisasContext *ctx, arg_gtlbrd *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    
    /* Check if LVZ feature is enabled */
    if (!avail_LVZ(ctx)) {
        return false;
    }
    
    /* Read guest TLB instruction */
    gen_helper_gtlbrd(tcg_env);
    return true;
}

static bool trans_gtlbwr(DisasContext *ctx, arg_gtlbwr *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    
    /* Check if LVZ feature is enabled */
    if (!avail_LVZ(ctx)) {
        return false;
    }
    
    /* Write guest TLB instruction */
    gen_helper_gtlbwr(tcg_env);
    check_mmu_idx(ctx);
    return true;
}

static bool trans_gtlbfill(DisasContext *ctx, arg_gtlbfill *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    
    /* Check if LVZ feature is enabled */
    if (!avail_LVZ(ctx)) {
        return false;
    }
    
    /* Fill guest TLB instruction */
    gen_helper_gtlbfill(tcg_env);
    check_mmu_idx(ctx);
    return true;
}

static bool trans_hvcl(DisasContext *ctx, arg_hvcl *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    
    /* Check if LVZ feature is enabled */
    if (!avail_LVZ(ctx)) {
        return false;
    }
    
    /* Hypervisor call instruction */
    gen_helper_hvcl(tcg_env, tcg_constant_i32(a->imm));
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
}

#endif
