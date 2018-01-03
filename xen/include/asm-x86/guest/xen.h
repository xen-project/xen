/******************************************************************************
 * asm-x86/guest/xen.h
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */

#ifndef __X86_GUEST_XEN_H__
#define __X86_GUEST_XEN_H__

#include <xen/types.h>

#ifdef CONFIG_XEN_GUEST

extern bool xen_guest;

void probe_hypervisor(void);
void hypervisor_setup(void);
int hypervisor_alloc_unused_page(mfn_t *mfn);
int hypervisor_free_unused_page(mfn_t mfn);

#else

#define xen_guest 0

static inline void probe_hypervisor(void) {};
static inline void hypervisor_setup(void)
{
    ASSERT_UNREACHABLE();
}

#endif /* CONFIG_XEN_GUEST */
#endif /* __X86_GUEST_XEN_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
