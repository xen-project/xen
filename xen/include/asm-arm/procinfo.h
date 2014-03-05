/*
 * include/asm-arm/procinfo.h
 *
 * Bamvor Jian Zhang <bjzhang@suse.com>
 * Copyright (c) 2013 SUSE
 *
 * base on linux/arch/arm/include/asm/procinfo.h
 * Copyright (C) 1996-1999 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __ASM_ARM_PROCINFO_H
#define __ASM_ARM_PROCINFO_H

#include <xen/sched.h>

struct processor {
    /* Initialize specific processor register for the new VPCU*/
    void (*vcpu_initialise)(struct vcpu *v);
};

struct proc_info_list {
    unsigned int        cpu_val;
    unsigned int        cpu_mask;
    void                (*cpu_init)(void);
    struct processor    *processor;
};

const __init struct proc_info_list *lookup_processor_type(void);

void __init processor_setup(void);
void processor_vcpu_initialise(struct vcpu *v);

#endif
