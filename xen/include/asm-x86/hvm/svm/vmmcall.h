/*
 * vmmcall.h: VMMCALL instruction support
 *
 * Travis Betak, travis.betak@amd.com
 * Copyright (c) 2005, AMD Corporation.
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

#ifndef __ASM_X86_HVM_SVM_VMMCALL_H__
#define __ASM_X86_HVM_SVM_VMMCALL_H__

/* VMMCALL command fields */
#define VMMCALL_CODE_CPL_MASK     0x60000000
#define VMMCALL_CODE_MBZ_MASK     0x1FFF0000
#define VMMCALL_CODE_COMMAND_MASK 0x0000FFFF

#define MAKE_VMMCALL_CODE(cpl,func) ((cpl << 29) | (func) | 0x80000000)

/* CPL=0 VMMCALL Requests */
#define VMMCALL_RESET_TO_REALMODE   MAKE_VMMCALL_CODE(0,1)

/* CPL=3 VMMCALL Requests */
#define VMMCALL_DEBUG           MAKE_VMMCALL_CODE(3,1)

/* return the cpl required for the vmmcall cmd */
static inline int get_vmmcall_cpl(int cmd)
{
    return (cmd & VMMCALL_CODE_CPL_MASK) >> 29;
}

#endif /* __ASM_X86_HVM_SVM_VMMCALL_H__ */
