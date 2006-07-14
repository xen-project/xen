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
 */
#include <asm/config.h>
#include <asm/processor.h>

/* 
 * sval
 * rh_leap(uval nargs, uval nrets, uval args[], uval rets[], uval ba,
 *		 rh_func_t f)
 *    We need to deal with f actually bein a function descriptor, we can
 *    assume that TOC is correct.
 */	

	
_GLOBAL(io_leap)	
_GLOBAL(leap)
	## r8 contains the base address for everyone
	add	r8,r8,r7 	# add
	ld	r8, 0(r8)	# get the entry point
	add	r8,r8,r7 	# add
	mtctr	r8		#     and
	bctr			#         leap
	/* never get here */
