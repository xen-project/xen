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

void vcpu_restore_fpu_eager(struct vcpu *v);
void vcpu_restore_fpu_lazy(struct vcpu *v);
void vcpu_save_fpu(struct vcpu *v);

int vcpu_init_fpu(struct vcpu *v);
void vcpu_destroy_fpu(struct vcpu *v);
#endif /* __ASM_I386_I387_H */
