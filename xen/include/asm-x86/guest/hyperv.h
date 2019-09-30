/******************************************************************************
 * asm-x86/guest/hyperv.h
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
 * Copyright (c) 2019 Microsoft.
 */

#ifndef __X86_GUEST_HYPERV_H__
#define __X86_GUEST_HYPERV_H__

#ifdef CONFIG_HYPERV_GUEST

#include <asm/guest/hypervisor.h>

const struct hypervisor_ops *hyperv_probe(void);

#else

static inline const struct hypervisor_ops *hyperv_probe(void) { return NULL; }

#endif /* CONFIG_HYPERV_GUEST */
#endif /* __X86_GUEST_HYPERV_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
