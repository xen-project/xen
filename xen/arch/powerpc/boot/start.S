/*
 * Copyright (C) 2005 Jimi Xenidis <jimix@watson.ibm.com>, IBM Corporation
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */

#include <asm/config.h>
#include <asm/processor.h>
#include <asm/page.h>

    .globl _start
_start:
    /* load up the stack */
    SET_REG_TO_LABEL(r1, cpu0_stack)

    /* call the init function */
    LOADADDR(r21,__start_xen_ppc)

#ifdef __PPC64__
    ld r2, 8(r21)
    ld r21, 0(r21)
#endif
    mtctr r21
    bctrl
    /* should never return */
    trap

    /* Note! GDB 6.3 makes the very stupid assumption that PC > SP means we are
     * in a Linux signal trampoline, and it begins groping for a struct
     * rt_sigframe on the stack. Naturally, this fails miserably for our
     * backtrace. To work around this behavior, we must make certain that our
     * stack is always above our text, e.g. in the data section. */
    .data /* DO NOT REMOVE; see GDB note above */
    .align 4
cpu0_stack_bottom:
    .space STACK_SIZE
cpu0_stack:
    .space STACK_FRAME_OVERHEAD
