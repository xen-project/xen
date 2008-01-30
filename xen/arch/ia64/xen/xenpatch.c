/******************************************************************************
 * xenpatch.c
 * Copyright (c) 2006 Silicon Graphics Inc.
 *         Jes Sorensen <jes@sgi.com>
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
 * Parts of this based on code from arch/ia64/kernel/patch.c
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <asm/xensystem.h>
#include <asm/intrinsics.h>

/*
 * This was adapted from code written by Tony Luck:
 *
 * The 64-bit value in a "movl reg=value" is scattered between the two words of the bundle
 * like this:
 *
 * 6  6         5         4         3         2         1
 * 3210987654321098765432109876543210987654321098765432109876543210
 * ABBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCCCDEEEEEFFFFFFFFFGGGGGGG
 *
 * CCCCCCCCCCCCCCCCCCxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 * xxxxAFFFFFFFFFEEEEEDxGGGGGGGxxxxxxxxxxxxxBBBBBBBBBBBBBBBBBBBBBBB
 */
static u64
get_imm64 (u64 insn_addr)
{
	u64 *p = (u64 *) (insn_addr & -16);	/* mask out slot number */

	return ( (p[1] & 0x0800000000000000UL) << 4)  | /*A*/
		((p[1] & 0x00000000007fffffUL) << 40) | /*B*/
		((p[0] & 0xffffc00000000000UL) >> 24) | /*C*/
		((p[1] & 0x0000100000000000UL) >> 23) | /*D*/
		((p[1] & 0x0003e00000000000UL) >> 29) | /*E*/
		((p[1] & 0x07fc000000000000UL) >> 43) | /*F*/
		((p[1] & 0x000007f000000000UL) >> 36);  /*G*/
}

/* Patch instruction with "val" where "mask" has 1 bits. */
void
ia64_patch (u64 insn_addr, u64 mask, u64 val)
{
	u64 m0, m1, v0, v1, b0, b1, *b = (u64 *) (insn_addr & -16);
#define insn_mask ((1UL << 41) - 1)
	unsigned long shift;

	b0 = b[0]; b1 = b[1];
	/* 5 bits of template, then 3 x 41-bit instructions */
	shift = 5 + 41 * (insn_addr % 16);
	if (shift >= 64) {
		m1 = mask << (shift - 64);
		v1 = val << (shift - 64);
	} else {
		m0 = mask << shift; m1 = mask >> (64 - shift);
		v0 = val  << shift; v1 = val >> (64 - shift);
		b[0] = (b0 & ~m0) | (v0 & m0);
	}
	b[1] = (b1 & ~m1) | (v1 & m1);
}

void
ia64_patch_imm64 (u64 insn_addr, u64 val)
{
	/* The assembler may generate offset pointing to either slot 1
	   or slot 2 for a long (2-slot) instruction, occupying slots 1
	   and 2.  */
  	insn_addr &= -16UL;
	ia64_patch(insn_addr + 2, 0x01fffefe000UL,
		   (((val & 0x8000000000000000UL) >> 27) | /* bit 63 -> 36 */
		    ((val & 0x0000000000200000UL) <<  0) | /* bit 21 -> 21 */
		    ((val & 0x00000000001f0000UL) <<  6) | /* bit 16 -> 22 */
		    ((val & 0x000000000000ff80UL) << 20) | /* bit  7 -> 27 */
		    ((val & 0x000000000000007fUL) << 13)  /* bit  0 -> 13 */));
	ia64_patch(insn_addr + 1, 0x1ffffffffffUL, val >> 22);
}

/*
 * Add more patch points in seperate functions as appropriate
 */

static void __init xen_patch_frametable_miss(u64 offset)
{
#ifdef CONFIG_VIRTUAL_FRAME_TABLE
	extern char frametable_miss;
	u64 addr, val;

	addr = (u64)&frametable_miss;
	val = get_imm64(addr) + offset;
	ia64_patch_imm64(addr, val);
	ia64_fc(addr);
#endif
}

/*
 * We need sometimes to load the physical address of a kernel
 * object.  Often we can convert the virtual address to physical
 * at execution time, but sometimes (either for performance reasons
 * or during error recovery) we cannot to this.  Patch the marked
 * bundles to load the physical address.
 */
void __init
ia64_patch_vtop (unsigned long start, unsigned long end)
{
	s32 *offp = (s32 *)start;
	u64 ip;

	while (offp < (s32 *)end) {
		ip = (u64)offp + *offp;

		/* replace virtual address with corresponding physical address */
		ia64_patch_imm64(ip, ia64_tpa(get_imm64(ip)));
		ia64_fc((void *)ip);
		++offp;
	}
	ia64_sync_i();
	ia64_srlz_i();
}

void __init xen_patch_kernel(void)
{
	extern unsigned long xen_pstart;
	unsigned long patch_offset;

	patch_offset = xen_pstart - (KERNEL_START - PAGE_OFFSET);

	printk("Xen patching physical address access by offset: "
	       "0x%lx\n", patch_offset);

	xen_patch_frametable_miss(patch_offset);

	ia64_sync_i();
	ia64_srlz_i();
}
