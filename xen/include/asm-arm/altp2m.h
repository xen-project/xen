/*
 * Alternate p2m
 *
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

#ifndef __ASM_ARM_ALTP2M_H
#define __ASM_ARM_ALTP2M_H

#include <xen/sched.h>

/* Alternate p2m on/off per domain */
static inline bool altp2m_active(const struct domain *d)
{
    /* Not implemented on ARM. */
    return false;
}

/* Alternate p2m VCPU */
static inline uint16_t altp2m_vcpu_idx(const struct vcpu *v)
{
    /* Not implemented on ARM, should not be reached. */
    BUG();
    return 0;
}

#endif /* __ASM_ARM_ALTP2M_H */
