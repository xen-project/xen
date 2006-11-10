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
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef __PPC_64_CONFIG_H__
#define __PPC_64_CONFIG_H__

#define CONFIG_L1_CACHE_SHIFT 7

/* 288 bytes below the stack pointer must be preserved by interrupt handlers */
#define STACK_VOLATILE_AREA     288
/* size of minimum stack frame; C code can write into the caller's stack */
#define STACK_FRAME_OVERHEAD    112

#define STACK_ORDER 2
#define STACK_SIZE  (PAGE_SIZE << STACK_ORDER)

#define NUM_SLB_ENTRIES 64
#define NUM_FPRS 32
#define HAS_FLOAT 1
#define HAS_VMX 1

#endif
