/*
 * xen/arch/arm/vtimer.h
 *
 * ARM Virtual Timer emulation support
 *
 * Ian Campbell <ian.campbell@citrix.com>
 * Copyright (c) 2011 Citrix Systems.
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

#ifndef __ARCH_ARM_VTIMER_H__
#define __ARCH_ARM_VTIMER_H__

extern int domain_vtimer_init(struct domain *d);
extern int vcpu_vtimer_init(struct vcpu *v);
extern int vtimer_emulate(struct cpu_user_regs *regs, union hsr hsr);
extern int virt_timer_save(struct vcpu *v);
extern int virt_timer_restore(struct vcpu *v);
extern void vcpu_timer_destroy(struct vcpu *v);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
