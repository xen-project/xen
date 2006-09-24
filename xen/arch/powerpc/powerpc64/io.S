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
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 *          Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <asm/config.h>
#include <asm/processor.h>
#include <asm/percpu.h>

/* Xen runs in real mode (i.e. untranslated, MMU disabled). This avoids TLB
 * flushes and also makes it easy to access all domains' memory. However, on
 * PowerPC real mode accesses are cacheable, which is good for general
 * performance, but not good when trying to do IO.
 *
 * POWER4 and PowerPC 970 have a bit (RM_CI: Real Mode Cache Inhibit) in HID4
 * which disables the data cache when running in real mode. Unfortunately, to
 * change RM_CI we need to go through a fairly complicated set of instructions,
 * make the access, then re-enable it...
 */

/* Not all useful assemblers understand 'tlbiel'.
 * 'addr' is a GPR containing the address being accessed.
 */
.macro tlbiel addr
	.long 0x7c000224 | (\addr << 11)
.endm

.macro DISABLE_DCACHE addr
	mfmsr r8
	/* disable interrupts */
	li r6, 0
	ori r6, r6, MSR_EE
	andc r5, r8, r6
	mtmsr r5

	/* set HID4.RM_CI */
	mfspr r9, SPRN_HID4
	li r6, 0x100
	sldi r6, r6, 32
	or r5, r9, r6
	tlbiel \addr /* invalidate the ERAT entry */
	sync
	mtspr SPRN_HID4, r5
	isync

	/* Mark the processor as "in CI mode" */
	mfspr r5, SPRN_PIR
	li r6, MCK_CPU_STAT_CI
	stb r6, MCK_CPU_STAT_BASE(r5)
	sync
.endm

.macro ENABLE_DCACHE addr
	/* re-zero HID4.RM_CI */
	tlbiel \addr /* invalidate the ERAT entry */
	sync
	mtspr SPRN_HID4, r9
	isync

	/* Mark the processor as "out of CI mode" */
	mfspr r5, SPRN_PIR
	li r6, 0
	stb r6, MCK_CPU_STAT_BASE(r5)
	sync
	
	/* re-enable interrupts */
	mtmsr r8
.endm

/* The following assembly cannot use r8 or r9 since they hold original
 * values of msr and hid4 repectively
 */
#undef r8
#define r8 do_not_use_r8
#undef r9
#define r9 do_not_use_r9

/* XXX remove isyncs */

_GLOBAL(in_8)
	DISABLE_DCACHE r3
	lbz r4,0(r3)
	twi 0,r4,0
	isync
	ENABLE_DCACHE r3
	mr r3, r4
	blr

_GLOBAL(out_8)
	DISABLE_DCACHE r3
	stb r4,0(r3)
	sync
	ENABLE_DCACHE r3
	blr

_GLOBAL(in_32)
	DISABLE_DCACHE r3
	lwz r4,0(r3)
	twi 0,r4,0
	isync
	ENABLE_DCACHE r3
	mr r3, r4
	blr

_GLOBAL(out_32)
	DISABLE_DCACHE r3
	stw r4,0(r3)
	sync
	ENABLE_DCACHE r3
	blr

_GLOBAL(in_le16)
	DISABLE_DCACHE r3
	lhbrx r4,0,r3
	twi 0,r4,0
	isync
	ENABLE_DCACHE r3
	mr r3, r4
	blr

_GLOBAL(out_le16)
	DISABLE_DCACHE r3
	sthbrx r4,0,r3
	sync
	ENABLE_DCACHE r3
	blr

_GLOBAL(in_le32)
	DISABLE_DCACHE r3
	lwbrx r4,0,r3
	twi 0,r4,0
	isync
	ENABLE_DCACHE r3
	mr r3, r4
	blr

_GLOBAL(out_le32)
	DISABLE_DCACHE r3
	stwbrx r4,0,r3
	sync
	ENABLE_DCACHE r3
	blr
