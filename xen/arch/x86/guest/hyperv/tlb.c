/******************************************************************************
 * arch/x86/guest/hyperv/tlb.c
 *
 * Support for TLB management using hypercalls
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2020 Microsoft.
 */

#include <xen/cpumask.h>
#include <xen/errno.h>

#include "private.h"

int hyperv_flush_tlb(const cpumask_t *mask, const void *va,
                     unsigned int flags)
{
    return -EOPNOTSUPP;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
