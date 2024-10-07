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

/* Byte offset of the stored word size within the FXSAVE area/portion. */
#define FPU_WORD_SIZE_OFFSET 511

struct ix87_env {
    uint16_t fcw, _res0;
    uint16_t fsw, _res1;
    uint16_t ftw, _res2;
    uint32_t fip;
    uint16_t fcs;
    uint16_t fop;
    uint32_t fdp;
    uint16_t fds, _res6;
};

void vcpu_restore_fpu_nonlazy(struct vcpu *v, bool need_stts);
void vcpu_restore_fpu_lazy(struct vcpu *v);
void vcpu_save_fpu(struct vcpu *v);
void save_fpu_enable(void);
int vcpu_init_fpu(struct vcpu *v);
void vcpu_destroy_fpu(struct vcpu *v);

/*
 * Restore v's FPU to power-on reset values
 *
 * @param v vCPU containing the FPU
 */
void vcpu_reset_fpu(struct vcpu *v);

/*
 * Load x87/SSE state into v's FPU
 *
 * Overrides the XSAVE header to set the state components to be x87 and SSE.
 *
 * @param v    vCPU containing the FPU
 * @param data 512-octet blob for x87/SSE state
 */
void vcpu_setup_fpu(struct vcpu *v, const void *data);
#endif /* __ASM_I386_I387_H */
