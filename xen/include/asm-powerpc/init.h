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
 * Copyright (C) IBM Corp. 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _XEN_ASM_INIT_H
#define _XEN_ASM_INIT_H

/*
 * Mark functions and data as being only used at initialization
 * or exit time.
 */
#define __init       \
    __attribute__ ((__section__ (".init.text")))
#define __exit       \
    __attribute_used__ __attribute__ ((__section__(".text.exit")))
#define __initdata   \
    __attribute__ ((__section__ (".init.data")))
#define __exitdata   \
    __attribute_used__ __attribute__ ((__section__ (".data.exit")))
#define __initsetup  \
    __attribute_used__ __attribute__ ((__section__ (".setup.init")))
#define __init_call  \
    __attribute_used__ __attribute__ ((__section__ (".initcall.init")))
#define __exit_call  \
    __attribute_used__ __attribute__ ((__section__ (".exitcall.exit")))

struct cpu_user_regs;
typedef void (*hcall_handler_t)(struct cpu_user_regs *regs);

typedef struct {
    unsigned long number;
    hcall_handler_t handler;
} inithcall_t;
extern inithcall_t __inithcall_start, __inithcall_end;

#define __init_papr_hcall(nr, fn) \
    static inithcall_t __inithcall_##fn __init_hcall \
    = { .number = nr, .handler = fn }

#define __init_hcall  \
    __attribute_used__ __attribute__ ((__section__ (".inithcall.text")))

#endif /* _XEN_ASM_INIT_H */
