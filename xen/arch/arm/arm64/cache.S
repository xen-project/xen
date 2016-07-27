/*
 * Cache maintenance
 *
 * Copyright (C) 2001 Deep Blue Solutions Ltd.
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 1996-2000 Russell King
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/alternative.h>

/*
 * dcache_line_size - get the minimum D-cache line size from the CTR register.
 */
	.macro	dcache_line_size, reg, tmp
	mrs	\tmp, ctr_el0			// read CTR
	ubfm	\tmp, \tmp, #16, #19		// cache line size encoding
	mov	\reg, #4			// bytes per word
	lsl	\reg, \reg, \tmp		// actual cache line size
	.endm

/*
 *	__flush_dcache_area(kaddr, size)
 *
 *	Ensure that the data held in the page kaddr is written back to the
 *	page in question.
 *
 *	- kaddr   - kernel address
 *	- size    - size in question
 */
ENTRY(__flush_dcache_area)
	dcache_line_size x2, x3
	add	x1, x0, x1
	sub	x3, x2, #1
	bic	x0, x0, x3
1:	dc	civac, x0			// clean & invalidate D line / unified line
	add	x0, x0, x2
	cmp	x0, x1
	b.lo	1b
	dsb	sy
	ret
ENDPROC(__flush_dcache_area)
