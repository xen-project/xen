/*
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
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright IBM Corp. 2006, 2007
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _XEN_ASM_INIT_H
#define _XEN_ASM_INIT_H

struct cpu_user_regs;
typedef void (*hcall_handler_t)(struct cpu_user_regs *regs);

typedef struct {
    unsigned long number;
    hcall_handler_t handler;
} init_hcall_t;
extern init_hcall_t __init_hcall_start, __init_hcall_end;

#define __init_papr_hcall(nr, fn) \
    static init_hcall_t __init_hcall_##fn __init_hcall \
    = { .number = nr, .handler = fn }

#define __init_hcall  \
    __attribute_used__ __attribute__ ((__section__ (".init_hcall.init")))

#endif /* _XEN_ASM_INIT_H */
