/*
 *  bootsect.S
 *
 *  This is setup.S from the linux 2.6.9 source code,
 *  with heavy cuts and changes for mbootpack
 *  November 2004 Tim Deegan <tjd21@cl.cam.ac.uk>
 *
 *  
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 *  02111-1307, USA.
 *
 * $Id: setup.S,v 1.4 2005/03/23 10:39:03 tjd21 Exp $
 *
 */
	
#include "mbootpack.h"
		
/*
 *	setup.S		Copyright (C) 1991, 1992 Linus Torvalds
 *
 * setup.s is responsible for getting the system data from the BIOS,
 * and putting them into the appropriate places in system memory.
 * both setup.s and system has been loaded by the bootblock.
 *
 * This code asks the bios for memory/disk/other parameters, and
 * puts them in a "safe" place: 0x90000-0x901FF, ie where the
 * boot-block used to be. It is then up to the protected mode
 * system to read them from there before the area is overwritten
 * for buffer-blocks.
 *
 * Move PS/2 aux init code to psaux.c
 * (troyer@saifr00.cfsat.Honeywell.COM) 03Oct92
 *
 * some changes and additional features by Christoph Niemann,
 * March 1993/June 1994 (Christoph.Niemann@linux.org)
 *
 * add APM BIOS checking by Stephen Rothwell, May 1994
 * (sfr@canb.auug.org.au)
 *
 * High load stuff, initrd support and position independency
 * by Hans Lermen & Werner Almesberger, February 1996
 * <lermen@elserv.ffm.fgan.de>, <almesber@lrc.epfl.ch>
 *
 * Video handling moved to video.S by Martin Mares, March 1996
 * <mj@k332.feld.cvut.cz>
 *
 * Extended memory detection scheme retwiddled by orc@pell.chi.il.us (david
 * parsons) to avoid loadlin confusion, July 1997
 *
 * Transcribed from Intel (as86) -> AT&T (gas) by Chris Noe, May 1999.
 * <stiker@northlink.com>
 *
 * Fix to work around buggy BIOSes which dont use carry bit correctly
 * and/or report extended memory in CX/DX for e801h memory size detection 
 * call.  As a result the kernel got wrong figures.  The int15/e801h docs
 * from Ralf Brown interrupt list seem to indicate AX/BX should be used
 * anyway.  So to avoid breaking many machines (presumably there was a reason
 * to orginally use CX/DX instead of AX/BX), we do a kludge to see
 * if CX/DX have been changed in the e801 call and if so use AX/BX .
 * Michael Miller, April 2001 <michaelm@mjmm.org>
 *
 * New A20 code ported from SYSLINUX by H. Peter Anvin. AMD Elan bugfixes
 * by Robert Schwebel, December 2001 <robert@schwebel.de>
 */

/*
#include <linux/config.h>
#include <asm/segment.h>
#include <linux/version.h>
#include <linux/compile.h>
#include <asm/boot.h>
#include <asm/e820.h>
#include <asm/page.h>
*/

/* Definitions that should have come from these includes */
#define DEF_INITSEG     0x9000
#define DEF_SYSSEG      0x1000
#define DEF_SETUPSEG    0x9020
#define DEF_SYSSIZE     0x7F00
#define NORMAL_VGA      0xffff
#define EXTENDED_VGA    0xfffe
#define ASK_VGA         0xfffd
#define GDT_ENTRY_BOOT_CS	2
#define __BOOT_CS		(GDT_ENTRY_BOOT_CS * 8)
#define GDT_ENTRY_BOOT_DS	(GDT_ENTRY_BOOT_CS + 1)
#define __BOOT_DS		(GDT_ENTRY_BOOT_DS * 8)
#define __PAGE_OFFSET           (0xC0000000)
#define E820MAP 0x2d0           /* our map */
#define E820MAX 32              /* number of entries in E820MAP */
#define E820NR  0x1e8           /* # entries in E820MAP */
#define E820_RAM        1
#define E820_RESERVED   2
#define E820_ACPI       3 /* usable as RAM once ACPI tables have been read */
#define E820_NVS        4
#define __BIG_KERNEL__
	
		
/* Signature words to ensure LILO loaded us right */
#define SIG1	0xAA55
#define SIG2	0x5A5A
	
INITSEG  = DEF_INITSEG		# 0x9000, we move boot here, out of the way
SYSSEG   = DEF_SYSSEG		# 0x1000, system loaded at 0x10000 (65536).
SETUPSEG = DEF_SETUPSEG		# 0x9020, this is the current segment
				# ... and the former contents of CS

DELTA_INITSEG = SETUPSEG - INITSEG	# 0x0020

.code16
.globl _start, begtext, begdata, begbss, endtext, enddata, endbss

.text
begtext:
.data
begdata:
.bss
begbss:
.text

_start:
start:
	jmp	trampoline

# This is the setup header, and it must start at %cs:2 (old 0x9020:2)

		.ascii	"HdrS"		# header signature
		.word	0x0203		# header version number (>= 0x0105)
					# or else old loadlin-1.5 will fail)
realmode_swtch:	.word	0, 0		# default_switch, SETUPSEG
start_sys_seg:	.word	SYSSEG
		.word	kernel_version	# pointing to kernel version string
					# above section of header is compatible
					# with loadlin-1.5 (header v1.5). Don't
					# change it.

type_of_loader:	.byte	0		# = 0, old one (LILO, Loadlin,
					#      Bootlin, SYSLX, bootsect...)
					# See Documentation/i386/boot.txt for
					# assigned ids
	
# flags, unused bits must be zero (RFU) bit within loadflags
loadflags:
LOADED_HIGH	= 1			# If set, the kernel is loaded high
CAN_USE_HEAP	= 0x80			# If set, the loader also has set
					# heap_end_ptr to tell how much
					# space behind setup.S can be used for
					# heap purposes.
					# Only the loader knows what is free
#ifndef __BIG_KERNEL__
		.byte	0
#else
		.byte	LOADED_HIGH
#endif

setup_move_size: .word  0x8000		# size to move, when setup is not
					# loaded at 0x90000. We will move setup 
					# to 0x90000 then just before jumping
					# into the kernel. However, only the
					# loader knows how much data behind
					# us also needs to be loaded.

/* N.B. these next addresses are entirely ignored by this code -- it
 * assumes it was loaded with the 32bit code at 0x100000, and doesn't 
 * touch the ramdisk. */
code32_start:				# here loaders can put a different
					# start address for 32-bit code.
#ifndef __BIG_KERNEL__
		.long	0x1000		#   0x1000 = default for zImage
#else
		.long	0x100000	# 0x100000 = default for big kernel
#endif

ramdisk_image:	.long	0		# address of loaded ramdisk image
					# Here the loader puts the 32-bit
					# address where it loaded the image.
					# This only will be read by the kernel.

ramdisk_size:	.long	0		# its size in bytes

bootsect_kludge:
		.long	0		# obsolete

heap_end_ptr:	.word	modelist+1024	# (Header version 0x0201 or later)
					# space from here (exclusive) down to
					# end of setup code can be used by setup
					# for local heap purposes.

pad1:		.word	0
cmd_line_ptr:	.long 0			# (Header version 0x0202 or later)
					# If nonzero, a 32-bit pointer
					# to the kernel command line.
					# The command line should be
					# located between the start of
					# setup and the end of low
					# memory (0xa0000), or it may
					# get overwritten before it
					# gets read.  If this field is
					# used, there is no longer
					# anything magical about the
					# 0x90000 segment; the setup
					# can be located anywhere in
					# low memory 0x10000 or higher.

ramdisk_max:	.long (-__PAGE_OFFSET-(512 << 20)-1) & 0x7fffffff
					# (Header version 0x0203 or later)
					# The highest safe address for
					# the contents of an initrd

/* Add more known locations: the image builder will overwrite
 * these with the entry point and MBI location for the multiboot kernel.
 * These offsets *must* match the definitions in buildimage.c  */

entry_address:	.long 0		# This will be offset 0x30 (0x230 from b'sect)
mbi_address:	.long 0		# This will be offset 0x34

/* Storage space for the size of memory */
highmem_size:	.long 0
		
trampoline:	call	start_of_setup
		.space	1024
# End of setup header #####################################################

start_of_setup:
# Bootlin depends on this being done early
	movw	$0x01500, %ax
	movb	$0x81, %dl
	int	$0x13

#ifdef SAFE_RESET_DISK_CONTROLLER
# Reset the disk controller.
	movw	$0x0000, %ax
	movb	$0x80, %dl
	int	$0x13
#endif

# Set %ds = %cs, we know that SETUPSEG = %cs at this point
	movw	%cs, %ax		# aka SETUPSEG
	movw	%ax, %ds
	
# Check signature at end of setup	
	cmpw	$SIG1, setup_sig1
	jne	bad_sig

	cmpw	$SIG2, setup_sig2
	jne	bad_sig

	jmp	good_sig1

# Routine to print asciiz string at ds:si
prtstr:
	lodsb
	andb	%al, %al
	jz	fin

	call	prtchr
	jmp	prtstr

fin:	ret

# Space printing
prtsp2:	call	prtspc		# Print double space
prtspc:	movb	$0x20, %al	# Print single space (note: fall-thru)

# Part of above routine, this one just prints ascii al
prtchr:	pushw	%ax
	pushw	%cx
	movw	$7,%bx
	movw	$0x01, %cx
	movb	$0x0e, %ah
	int	$0x10
	popw	%cx
	popw	%ax
	ret

beep:	movb	$0x07, %al
	jmp	prtchr
	
no_sig_mess: .string	"No setup signature found ..."

good_sig1:
	jmp	good_sig

# We now have to find the rest of the setup code/data
bad_sig:
	movw	%cs, %ax			# SETUPSEG
	subw	$DELTA_INITSEG, %ax		# INITSEG
	movw	%ax, %ds
	xorb	%bh, %bh
	movb	(497), %bl			# get setup sect from bootsect
	subw	$4, %bx				# LILO loads 4 sectors of setup
	shlw	$8, %bx				# convert to words (1sect=2^8 words)
	movw	%bx, %cx
	shrw	$3, %bx				# convert to segment
	addw	$SYSSEG, %bx
	movw	%bx, %cs:start_sys_seg
# Move rest of setup code/data to here
	movw	$2048, %di			# four sectors loaded by LILO
	subw	%si, %si
	pushw	%cs
	popw	%es
	movw	$SYSSEG, %ax
	movw	%ax, %ds
	rep
	movsw
	movw	%cs, %ax			# aka SETUPSEG
	movw	%ax, %ds
	cmpw	$SIG1, setup_sig1
	jne	no_sig

	cmpw	$SIG2, setup_sig2
	jne	no_sig

	jmp	good_sig

no_sig:
	lea	no_sig_mess, %si
	call	prtstr

no_sig_loop:
	hlt
	jmp	no_sig_loop

mb_hello_mess1:
	.string	"mboot"
	
good_sig:
	lea	mb_hello_mess1, %si
	call	prtstr

	movw	%cs, %ax			# aka SETUPSEG
	subw	$DELTA_INITSEG, %ax 		# aka INITSEG
	movw	%ax, %ds
# Check if an old loader tries to load a big-kernel
	testb	$LOADED_HIGH, %cs:loadflags	# Do we have a big kernel?
	jz	loader_ok			# No, no danger for old loaders.

	cmpb	$0, %cs:type_of_loader 		# Do we have a loader that
						# can deal with us?
	jnz	loader_ok			# Yes, continue.

	pushw	%cs				# No, we have an old loader,
	popw	%ds				# die. 
	lea	loader_panic_mess, %si
	call	prtstr

	jmp	no_sig_loop

loader_panic_mess: .string "Wrong loader, giving up..."

loader_ok:
	
# Get memory size (extended mem, kB)

/* We'll be storing this in highmem_size, to be copied to the mbi */

# Try three different memory detection schemes.  First, try
# e820h, which lets us assemble a memory map, then try e801h,
# which returns a 32-bit memory size, and finally 88h, which
# returns 0-64m

	xorl	%edx, %edx
	xorl	%eax, %eax
	movl	%eax, (0x1e0)
	movl	%eax, highmem_size
	movb	%al, (E820NR)
	
# method E820H:
# the memory map from hell.  e820h returns memory classified into
# a whole bunch of different types, and allows memory holes and
# everything.  We scan through this memory map and build a list
# of the first 32 memory areas, which we return at [E820MAP].
# This is documented at http://www.acpi.info/, in the ACPI 2.0 specification.

#define SMAP  0x534d4150

meme820:
	xorl	%ebx, %ebx			# continuation counter
	movw	$E820MAP, %di			# point into the whitelist
						# so we can have the bios
						# directly write into it.

jmpe820:
	movl	$0x0000e820, %eax		# e820, upper word zeroed
	movl	$SMAP, %edx			# ascii 'SMAP'
	movl	$20, %ecx			# size of the e820rec
	pushw	%ds				# data record.
	popw	%es
	int	$0x15				# make the call
	jc	bail820				# fall to e801 if it fails

	cmpl	$SMAP, %eax			# check the return is `SMAP'
	jne	bail820				# fall to e801 if it fails

#	cmpl	$1, 16(%di)			# is this usable memory?
#	jne	again820

	# If this is usable memory, we save it by simply advancing %di by
	# sizeof(e820rec).
	#
good820:
	movb	(E820NR), %al			# up to 32 entries
	cmpb	$E820MAX, %al
	jnl	bail820

	incb	(E820NR)
	movw	%di, %ax
	addw	$20, %ax
	movw	%ax, %di
again820:
	cmpl	$0, %ebx			# check to see if
	jne	jmpe820				# %ebx is set to EOF	

/* Multiboot spec says high mem should be the address of the first
 * upper memory hole, minus 1 MB */
	xorl	%ebx, %ebx
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	movw	$E820MAP, %di			# Start at the beginning
calc_highmem_loop:
	cmpl	$1, 16(%di)			# is it usable memory?
	jnz	calc_highmem_next
	cmpl	$0, 4(%di)			# is base < 4GB?
	jnz	calc_highmem_next
	cmpl	$0x100000, 0(%di)		# is base <= 1MB?
	jg	calc_highmem_next
	movl	8(%di), %ecx			# Calculate base+length
	shrl	$10, %ecx			# in kilobytes
	movl	12(%di), %edx
	shll	$22, %edx
	orl	%edx, %ecx
	movl	0(%di), %edx
	shrl	$10, %edx
	addl	%edx, %ecx
	subl	$1024, %ecx			# - 1 MB
	cmpl	%cs:highmem_size, %ecx
	jl	calc_highmem_next
	movl	%ecx, %cs:highmem_size
calc_highmem_next:
	add	$1, %bl
	add	$20, %di
	cmp	%bl, (E820NR)
	je	calc_highmem_done
	jmp	calc_highmem_loop
calc_highmem_done:
			
bail820:

# method E801H:
# memory size is in 1k chunksizes, to avoid confusing loadlin.

meme801:
	stc					# fix to work around buggy
	xorw	%cx,%cx				# BIOSes which dont clear/set
	xorw	%dx,%dx				# carry on pass/error of
						# e801h memory size call
						# or merely pass cx,dx though
						# without changing them.
	movw	$0xe801, %ax
	int	$0x15
	jc	mem88

	cmpw	$0x0, %cx			# Kludge to handle BIOSes
	jne	e801usecxdx			# which report their extended
	cmpw	$0x0, %dx			# memory in AX/BX rather than
	jne	e801usecxdx			# CX/DX.  The spec I have read
	movw	%ax, %cx			# seems to indicate AX/BX 
	movw	%bx, %dx			# are more reasonable anyway...

e801usecxdx:
	andl	$0xffff, %edx			# clear sign extend
	shll	$6, %edx			# and go from 64k to 1k chunks
	andl	$0xffff, %ecx			# clear sign extend
	addl	%ecx, %edx

	cmpl	%cs:highmem_size, %edx		# store extended mem size
	jl	mem88				# if it's bigger than
	movl	%edx, %cs:highmem_size		# what we already have
	
# Ye Olde Traditional Methode.  Returns the memory size (up to 16mb or
# 64mb, depending on the bios) in ax.
mem88:
	movb	$0x88, %ah
	int	$0x15

	andl	$0xffff, %eax			# clear sign extend
	cmpl	%cs:highmem_size, %eax		# store extended mem size
	jl	have_memsize			# if it's bigger than
	movl	%eax, %cs:highmem_size		# what we already have

have_memsize:
	
/* Culled: HDD probes, APM, speedstep */

# Now we want to move to protected mode ...
	cmpw	$0, %cs:realmode_swtch
	jz	rmodeswtch_normal

	lcall	*%cs:realmode_swtch

	jmp	rmodeswtch_end

rmodeswtch_normal:
        pushw	%cs
	call	default_switch

rmodeswtch_end:

/* Culled: code to take the 32bit entry address from the loader */
/* Culled: code to relocate non-bzImage kernels */
	
	# then we load the segment descriptors
	movw	%cs, %ax			# aka SETUPSEG
	movw	%ax, %ds
		
# Check whether we need to be downward compatible with version <=201
	cmpl	$0, cmd_line_ptr
	jne	end_move_self		# loader uses version >=202 features
	cmpb	$0x20, type_of_loader
	je	end_move_self		# bootsect loader, we know of it

# Boot loader doesnt support boot protocol version 2.02.
# If we have our code not at 0x90000, we need to move it there now.
# We also then need to move the params behind it (commandline)
# Because we would overwrite the code on the current IP, we move
# it in two steps, jumping high after the first one.
	movw	%cs, %ax
	cmpw	$SETUPSEG, %ax
	je	end_move_self

	cli					# make sure we really have
						# interrupts disabled !
						# because after this the stack
						# should not be used
	subw	$DELTA_INITSEG, %ax		# aka INITSEG
	movw	%ss, %dx
	cmpw	%ax, %dx
	jb	move_self_1

	addw	$INITSEG, %dx
	subw	%ax, %dx			# this will go into %ss after
						# the move
move_self_1:
	movw	%ax, %ds
	movw	$INITSEG, %ax			# real INITSEG
	movw	%ax, %es
	movw	%cs:setup_move_size, %cx
	std					# we have to move up, so we use
						# direction down because the
						# areas may overlap
	movw	%cx, %di
	decw	%di
	movw	%di, %si
	subw	$move_self_here+0x200, %cx
	rep
	movsb
	ljmp	$SETUPSEG, $move_self_here

move_self_here:
	movw	$move_self_here+0x200, %cx
	rep
	movsb
	movw	$SETUPSEG, %ax
	movw	%ax, %ds
	movw	%dx, %ss
end_move_self:					# now we are at the right place

#
# Enable A20.  This is at the very best an annoying procedure.
# A20 code ported from SYSLINUX 1.52-1.63 by H. Peter Anvin.
# AMD Elan bug fix by Robert Schwebel.
#

#if defined(CONFIG_X86_ELAN)
	movb $0x02, %al			# alternate A20 gate
	outb %al, $0x92			# this works on SC410/SC520
a20_elan_wait:
	call a20_test
	jz a20_elan_wait
	jmp a20_done
#endif


A20_TEST_LOOPS		=  32		# Iterations per wait
A20_ENABLE_LOOPS	= 255		# Total loops to try		


#ifndef CONFIG_X86_VOYAGER
a20_try_loop:

	# First, see if we are on a system with no A20 gate.
a20_none:
	call	a20_test
	jnz	a20_done

	# Next, try the BIOS (INT 0x15, AX=0x2401)
a20_bios:
	movw	$0x2401, %ax
	pushfl					# Be paranoid about flags
	int	$0x15
	popfl

	call	a20_test
	jnz	a20_done

	# Try enabling A20 through the keyboard controller
#endif /* CONFIG_X86_VOYAGER */
a20_kbc:
	call	empty_8042

#ifndef CONFIG_X86_VOYAGER
	call	a20_test			# Just in case the BIOS worked
	jnz	a20_done			# but had a delayed reaction.
#endif

	movb	$0xD1, %al			# command write
	outb	%al, $0x64
	call	empty_8042

	movb	$0xDF, %al			# A20 on
	outb	%al, $0x60
	call	empty_8042

#ifndef CONFIG_X86_VOYAGER
	# Wait until a20 really *is* enabled; it can take a fair amount of
	# time on certain systems; Toshiba Tecras are known to have this
	# problem.
a20_kbc_wait:
	xorw	%cx, %cx
a20_kbc_wait_loop:
	call	a20_test
	jnz	a20_done
	loop	a20_kbc_wait_loop

	# Final attempt: use "configuration port A"
a20_fast:
	inb	$0x92, %al			# Configuration Port A
	orb	$0x02, %al			# "fast A20" version
	andb	$0xFE, %al			# don't accidentally reset
	outb	%al, $0x92

	# Wait for configuration port A to take effect
a20_fast_wait:
	xorw	%cx, %cx
a20_fast_wait_loop:
	call	a20_test
	jnz	a20_done
	loop	a20_fast_wait_loop

	# A20 is still not responding.  Try frobbing it again.
	# 
	decb	(a20_tries)
	jnz	a20_try_loop
	
	movw	$a20_err_msg, %si
	call	prtstr

a20_die:
	hlt
	jmp	a20_die

a20_tries:
	.byte	A20_ENABLE_LOOPS

a20_err_msg:
	.ascii	"linux: fatal error: A20 gate not responding!"
	.byte	13, 10, 0

	# If we get here, all is good
a20_done:


#endif /* CONFIG_X86_VOYAGER */

/* Another print, to show protected mode and A20 are OK */

	jmp	mb_hello_mess2_end
mb_hello_mess2:
	.string "pack "	
mb_hello_mess2_end:	
	lea	mb_hello_mess2, %si
	call	prtstr
	
# set up gdt and idt
/*	lidt	idt_48				# load idt with 0,0 */
/* Multiboot kernels must set up their own IDT:	leave this for now, 
 * so we can print diagnostics */
	
	xorl	%eax, %eax			# Compute gdt_base
	movw	%ds, %ax			# (Convert %ds:gdt to a linear ptr)
	shll	$4, %eax
	addl	$gdt, %eax
	movl	%eax, (gdt_48+2)
	lgdt	gdt_48				# load gdt with whatever is
						# appropriate
	
# make sure any possible coprocessor is properly reset..
	xorw	%ax, %ax
	outb	%al, $0xf0
	call	delay

	outb	%al, $0xf1
	call	delay

	
# well, that went ok, I hope. Now we mask all interrupts - the rest
# is done in init_IRQ().
	movb	$0xFF, %al			# mask all interrupts for now
	outb	%al, $0xA1
	call	delay
	
	movb	$0xFB, %al			# mask all irq's but irq2 which
	outb	%al, $0x21			# is cascaded

# Well, that certainly wasn't fun :-(. Hopefully it works, and we don't
# need no steenking BIOS anyway (except for the initial loading :-).
# The BIOS-routine wants lots of unnecessary data, and it's less
# "interesting" anyway. This is how REAL programmers do it.

/* Tailor the jump below so the target is the 32bit trampoline code */

	xorl	%eax, %eax			# Calculate
	movw    %cs, %ax			# the linear
        shll    $4, %eax			# address of
        addl    $trampoline32, %eax		# %cs:trampoline32
	movl	%eax, %cs:code32		# Stick it into the jmpi

	/* Load a 32-bit pointer to the entry address into %ecx */
	xorl	%ecx, %ecx			# Calculate
	movw    %cs, %cx			# the linear
        shll    $4, %ecx			# address of
        addl    $entry_address, %ecx		# %cs:entry_address

# Well, now's the time to actually move into protected mode.

	lea	mb_ready_mess, %si
	call	prtstr
	
/* May as well load this IDT now */
	lidt	idt_48

	xorl	%eax, %eax
	movw	$1, %ax				# protected mode (PE) bit
	lmsw	%ax				# This is it!
	jmp	flush_instr
flush_instr:	
	
	/* Set up segment registers */
	movw	$__BOOT_DS, %dx
	movw	%dx, %ds
	movw	%dx, %es
	movw	%dx, %fs
	movw	%dx, %gs
	movw	%dx, %ss

	/* Trampoline expects this in %eax */
	movl	%ecx, %eax
	
	/* Jump to the 32-bit trampoline */

# NOTE: For high loaded big kernels we need a
#	jmpi    0x100000,__BOOT_CS
#
#	but we yet haven't reloaded the CS register, so the default size 
#	of the target offset still is 16 bit.
#       However, using an operand prefix (0x66), the CPU will properly
#	take our 48 bit far pointer. (INTeL 80386 Programmer's Reference
#	Manual, Mixing 16-bit and 32-bit code, page 16-6)

	.byte 0x66, 0xea			# prefix + jmpi-opcode
code32:	.long	0x1000				# will be set to trampoline32
						# by code above.
	.word	__BOOT_CS

# Here's a bunch of information about your current kernel..

kernel_version:	 .string "mbootpack changeling bzImage"
mb_ready_mess:	
		.ascii MBOOTPACK_VERSION_STRING
		.ascii "\r\n"
		.byte 0

# This is the default real mode switch routine.
# to be called just before protected mode transition
default_switch:
	cli					# no interrupts allowed !
	movb	$0x80, %al			# disable NMI for bootup
						# sequence
	outb	%al, $0x70
	lret


#ifndef CONFIG_X86_VOYAGER
# This routine tests whether or not A20 is enabled.  If so, it
# exits with zf = 0.
#
# The memory address used, 0x200, is the int $0x80 vector, which
# should be safe.

A20_TEST_ADDR = 4*0x80

a20_test:
	pushw	%cx
	pushw	%ax
	xorw	%cx, %cx
	movw	%cx, %fs			# Low memory
	decw	%cx
	movw	%cx, %gs			# High memory area
	movw	$A20_TEST_LOOPS, %cx
	movw	%fs:(A20_TEST_ADDR), %ax
	pushw	%ax
a20_test_wait:
	incw	%ax
	movw	%ax, %fs:(A20_TEST_ADDR)
	call	delay				# Serialize and make delay constant
	cmpw	%gs:(A20_TEST_ADDR+0x10), %ax
	loope	a20_test_wait

	popw	%fs:(A20_TEST_ADDR)
	popw	%ax
	popw	%cx
	ret	

#endif /* CONFIG_X86_VOYAGER */

# This routine checks that the keyboard command queue is empty
# (after emptying the output buffers)
#
# Some machines have delusions that the keyboard buffer is always full
# with no keyboard attached...
#
# If there is no keyboard controller, we will usually get 0xff
# to all the reads.  With each IO taking a microsecond and
# a timeout of 100,000 iterations, this can take about half a
# second ("delay" == outb to port 0x80). That should be ok,
# and should also be plenty of time for a real keyboard controller
# to empty.
#

empty_8042:
	pushl	%ecx
	movl	$100000, %ecx

empty_8042_loop:
	decl	%ecx
	jz	empty_8042_end_loop

	call	delay

	inb	$0x64, %al			# 8042 status port
	testb	$1, %al				# output buffer?
	jz	no_output

	call	delay
	inb	$0x60, %al			# read it
	jmp	empty_8042_loop

no_output:
	testb	$2, %al				# is input buffer full?
	jnz	empty_8042_loop			# yes - loop
empty_8042_end_loop:
	popl	%ecx
	ret

# Read the cmos clock. Return the seconds in al
gettime:
	pushw	%cx
	movb	$0x02, %ah
	int	$0x1a
	movb	%dh, %al			# %dh contains the seconds
	andb	$0x0f, %al
	movb	%dh, %ah
	movb	$0x04, %cl
	shrb	%cl, %ah
	aad
	popw	%cx
	ret

# Delay is needed after doing I/O
delay:
	outb	%al,$0x80
	ret

# Descriptor tables
#
# NOTE: The intel manual says gdt should be sixteen bytes aligned for
# efficiency reasons.  However, there are machines which are known not
# to boot with misaligned GDTs, so alter this at your peril!  If you alter
# GDT_ENTRY_BOOT_CS (in asm/segment.h) remember to leave at least two
# empty GDT entries (one for NULL and one reserved).
#
# NOTE:	On some CPUs, the GDT must be 8 byte aligned.  This is
# true for the Voyager Quad CPU card which will not boot without
# This directive.  16 byte aligment is recommended by intel.
#


/* The boot-time code segment is set at the jmpi above */
/* Dont change this without checking everything still matches  */

	.align 16
gdt:
	.fill GDT_ENTRY_BOOT_CS,8,0

	.word	0xFFFF				# 4Gb - (0x100000*0x1000 = 4Gb)
	.word	0				# base address = 0
	.word	0x9A00				# code read/exec
	.word	0x00CF				# granularity = 4096, 386
						#  (+5th nibble of limit)

	.word	0xFFFF				# 4Gb - (0x100000*0x1000 = 4Gb)
	.word	0				# base address = 0
	.word	0x9200				# data read/write
	.word	0x00CF				# granularity = 4096, 386
						#  (+5th nibble of limit)
gdt_end:
	.align	4
	
	.word	0				# alignment byte
idt_48:
	.word	0				# idt limit = 0
	.word	0, 0				# idt base = 0L

	.word	0				# alignment byte
gdt_48:
	.word	gdt_end - gdt - 1		# gdt limit
	.word	0, 0				# gdt base (filled in later)

# Include video setup & detection code

/* #include "video.S" */

.code32
trampoline32:
	/* Here, %eax = 32-bit pointer to entry_address */

	/* Check if the bootloader gave us a (non-empty) command line */
	movl	-8(%eax), %ebx			# cmd_line_ptr
	cmpl	$0, %ebx
	je	no_cmd_line
	cmpb	$0, 0(%ebx)
	je	no_cmd_line

	/* Find the MBI command line */
	movl    %eax, %ecx			# &entry_address
	addl	$(begtext-entry_address), %ecx	# --> start of setup
	subl    $0x9200, %ecx			# --> reloc offset
	movl	%ecx, %esi			# (copy offset)
	movl	%ecx, %ebx			# (copy offset)
	addl	4(%eax), %ecx			# --> current addr of MBI
	addl	16(%ecx), %ebx			# --> cur. addr of MB cmdline

	/* Overwrite the built-in MBI kernel command line */
	movl	-8(%eax), %ecx
	movl	$0, %edi

	/* Give the kernel a 'self' word, that linux doesn't get */
	movw	$0x202E, 0(%ebx)			# '. '
	addl	$0x2, %ebx
	
cmd_line_copy:	
	movb	(%ecx, %edi), %dl
	movb	%dl, (%ebx, %edi)
	inc	%edi
	cmp	$CMD_LINE_SPACE-3, %edi 
	je	cmd_line_copy_end

	cmpb	$0x0, %dl
	jne	cmd_line_copy
cmd_line_copy_end:
	movb	$0x0, (%ebx, %edi)
	subl	$0x2, %ebx
	
	/* Look for '--' in the kernel command line */
cmd_line_scan:
	inc	%ebx
	cmpb	$0x0, 0(%ebx)
	je	no_cmd_line
	cmpl	$0x202D2D20, 0(%ebx)		# ' -- '
	jne	cmd_line_scan

	/* Found it: terminate kernel's command line */
	movb	$0x0, 0(%ebx)
	inc	%ebx
	/* Relocate address to where it will be moved to */
	subl	%esi, %ebx
	
	/* Is there a module 0? */
	movl	%esi, %ecx			# Reloc offset
	addl	4(%eax), %ecx			# --> current addr of MBI
	cmpl	$0x0, 20(%ecx)			# (check module count)
	je	no_cmd_line
	/* Overwrite module 0's command line */
	movl	%esi, %edx			# Reloc offset
	addl	24(%ecx), %edx			# --> cur. add. of Module 0
	movl	%ebx, 8(%edx)			# --> blat mod. 0's cmdline
no_cmd_line:


	/* Relocate the MBI from after the setup code to its proper home
	 * between the MBI pointer and 0xa000 */
	movl    %eax, %ecx			# &entry_address
	addl	$(begtext-entry_address), %ecx	# --> start of setup
	subl    $0x9200, %ecx			# --> reloc offset
	addl	4(%eax), %ecx			# --> current addr of MBI
	
	movl	$0xa000, %ebx			# End of MBI
	subl	4(%eax), %ebx			# --> size of MBI
	movl	%ebx, %edi
	
	movl	4(%eax), %ebx	                # Destination of MBI
	
mbi_copy:
	dec	%edi
	movb	(%ecx, %edi), %dl
	movb	%dl, (%ebx, %edi)
	cmp	$0x0, %edi
	jne	mbi_copy	
	
	/* Copy memory size into MBI structure */
	movl	4(%eax), %ebx	                # MBI pointer
	movl	8(%eax), %ecx			# highmem_size
	movl	%ecx, 8(%ebx)			# --> mbi.mem_upper
	movl	$0x280, %ecx
	movl	%ecx, 4(%ebx)			# --> mbi.mem_lower
	/* Set the MB_INFO_MEMORY bit */
	orl	$1, 0(%ebx)

	/* Recover the MBI pointer into %ebx */
	movl	4(%eax), %ebx	                # MBI pointer
	/* Extract the load address into %ecx */
	movl	0(%eax), %ecx
	/* Let the kernel know we're a multiboot loader */
	movl	$0x2BADB002, %eax
	/* Jump to the kernel address supplied */
	jmp	*%ecx

# Setup signature -- must be last
setup_sig1:	.word	SIG1
setup_sig2:	.word	SIG2

# After this point, there is some free space which is used by the video mode
# handling code to store the temporary mode table (not used by the kernel).

modelist:

.text
endtext:
.data
enddata:
.bss
endbss:
