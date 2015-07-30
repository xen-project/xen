/*
 * Alternate p2m HVM
 * Copyright (c) 2014, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _X86_ALTP2M_H
#define _X86_ALTP2M_H

#include <xen/types.h>
#include <xen/sched.h>         /* for struct vcpu, struct domain */
#include <asm/hvm/vcpu.h>      /* for vcpu_altp2m */

/* Alternate p2m HVM on/off per domain */
static inline bool_t altp2m_active(const struct domain *d)
{
    return d->arch.altp2m_active;
}

/* Alternate p2m VCPU */
void altp2m_vcpu_initialise(struct vcpu *v);
void altp2m_vcpu_destroy(struct vcpu *v);
void altp2m_vcpu_reset(struct vcpu *v);

#endif /* _X86_ALTP2M_H */

