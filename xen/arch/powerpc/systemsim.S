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

_GLOBAL(systemsim_callthru)
	.long 0x000eaeb0
	blr

_GLOBAL(systemsim_write)
	mr	r5, r4
	mr	r4, r3
	li	r3, 0		# Write console code
	
	li	r6, 0
	/* need to fix return value */
	mflr	r7
	bl	_ENTRY(systemsim_callthru)
	mtlr	r7
	mr	r3, r5
	blr

_GLOBAL(systemsim_memset)
	mr	r6, r5
	mr	r5, r4
	mr	r4, r3
	li	r3, 0x47	# memset
	/* need to fix return value */
	mflr	r7
	bl	_ENTRY(systemsim_callthru)
	mtlr	r7
	mr	r3, r4
	blr

_GLOBAL(systemsim_memcpy)
	mr	r6, r5
	mr	r5, r4
	mr	r4, r3
	li	r3, 0x45 # memcpy
	/* need to fix return value */
	mflr	r7
	bl	_ENTRY(systemsim_callthru)
	mtlr	r7
	mr	r3, r4
	blr

	
