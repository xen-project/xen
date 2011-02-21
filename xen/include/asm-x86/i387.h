/*
 * include/asm-i386/i387.h
 *
 * Copyright (C) 1994 Linus Torvalds
 *
 * Pentium III FXSR, SSE support
 * General FPU state handling cleanups
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

#ifndef __ASM_I386_I387_H
#define __ASM_I386_I387_H

#include <xen/types.h>
#include <xen/percpu.h>

struct vcpu;

extern unsigned int xsave_cntxt_size;
extern u64 xfeature_mask;

void xsave_init(void);
int xsave_alloc_save_area(struct vcpu *v);
void xsave_free_save_area(struct vcpu *v);
bool_t xsave_enabled(const struct vcpu *v);

#define XSAVE_AREA_MIN_SIZE (512 + 64) /* FP/SSE + XSAVE.HEADER */
#define XSTATE_FP       (1ULL << 0)
#define XSTATE_SSE      (1ULL << 1)
#define XSTATE_YMM      (1ULL << 2)
#define XSTATE_LWP      (1ULL << 62) /* AMD lightweight profiling */
#define XSTATE_FP_SSE   (XSTATE_FP | XSTATE_SSE)
#define XCNTXT_MASK     (XSTATE_FP | XSTATE_SSE | XSTATE_YMM | XSTATE_LWP)
#define XSTATE_YMM_OFFSET  XSAVE_AREA_MIN_SIZE
#define XSTATE_YMM_SIZE    256
#define XSAVEOPT        (1 << 0)

struct xsave_struct
{
    struct { char x[512]; } fpu_sse;         /* FPU/MMX, SSE */

    struct {
        u64 xstate_bv;
        u64 reserved[7];
    } xsave_hdr;                            /* The 64-byte header */

    struct { char x[XSTATE_YMM_SIZE]; } ymm; /* YMM */
    char   data[];                           /* Future new states */
} __attribute__ ((packed, aligned (64)));

#define XCR_XFEATURE_ENABLED_MASK   0

#ifdef CONFIG_X86_64
#define REX_PREFIX "0x48, "
#else
#define REX_PREFIX
#endif

DECLARE_PER_CPU(uint64_t, xcr0);

static inline void xsetbv(u32 index, u64 xfeatures)
{
    u32 hi = xfeatures >> 32;
    u32 lo = (u32)xfeatures;

    asm volatile (".byte 0x0f,0x01,0xd1" :: "c" (index),
            "a" (lo), "d" (hi));
}

static inline void set_xcr0(u64 xfeatures)
{
    this_cpu(xcr0) = xfeatures;
    xsetbv(XCR_XFEATURE_ENABLED_MASK, xfeatures);
}

static inline uint64_t get_xcr0(void)
{
    return this_cpu(xcr0);
}

extern void setup_fpu(struct vcpu *v);
extern void save_init_fpu(struct vcpu *v);

#endif /* __ASM_I386_I387_H */
