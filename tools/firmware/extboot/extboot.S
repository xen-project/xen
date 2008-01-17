/*
 * Extended Boot Option ROM
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Copyright IBM Corporation, 2007
 *   Authors: Anthony Liguori <aliguori@us.ibm.com>
 */

.code16
.text
	.global _start
_start:
	.short 0xaa55
	.byte (_end - _start) / 512

	push %ax
	push %bx
	push %cx
	push %dx
	push %ds

	/* setup ds so we can access the IVT */
	xor %ax, %ax
	mov %ax, %ds

	/* save old int 19 at int 2b */
	mov $(0x19 * 4), %bx
	mov 0(%bx), %ax
	mov 2(%bx), %cx

	mov $(0x2b * 4), %bx
	mov %ax, 0(%bx)
	mov %cx, 2(%bx)

	/* install our int 19 handler */
	mov $(0x19 * 4), %bx
	mov $int19_handler, %ax
	mov %ax, 0(%bx)
	mov %cs, 2(%bx)

	pop %ds
	pop %dx
	pop %cx
	pop %bx
	pop %ax
	lret

int19_handler:
	push %ax
	push %bx
	push %cx
	push %dx
	push %ds

	movw $0x404, %dx
	inb %dx, %al
	cmp $1, %al
	jne 1f

	/* hook int13 */
	/* setup ds to access IVT */
	xor %ax, %ax
	mov %ax, %ds

	/* save old int 13 to int 2c */
	mov $(0x13 * 4), %bx
	mov 0(%bx), %ax
	mov 2(%bx), %cx

	mov $(0x2c * 4), %bx
	mov %ax, 0(%bx)
	mov %cx, 2(%bx)

	/* install our int 13 handler */
	mov $(0x13 * 4), %bx
	mov $int13_handler, %ax

	mov %ax, 0(%bx)
	mov %cs, 2(%bx)

1:	pop %ds
	pop %dx
	pop %cx
	pop %bx
	pop %ax
	int $0x2b

#define FLAGS_CF	0x01

.macro clc
	push %ax
	pushf
	pop %ax
	and $(~FLAGS_CF), %ax
	push %ax
	popf
	pop %ax
.endm

.macro stc
	push %ax
	pushf
	pop %ax
	or $(FLAGS_CF), %ax
	push %ax
	popf
	pop %ax
.endm

/* we clobber %bx */
.macro alloca size
	push %ds
	push %bp
	mov %sp, %bp  /* remember the current stack position */

	mov %ss, %bx
	mov %bx, %ds

	sub \size, %sp
	and $(~0x0F), %sp
	mov %sp, %bx

	push %bp
	mov 0(%bp), %bp
.endm

/* we clobber %bp */
.macro allocbpa size
	mov %sp, %bp  /* remember the current stack position */
	sub \size, %sp
	and $(~0x0F), %sp
	push %bp
	mov %sp, %bp
	add $2, %bp
.endm

.macro freea
	pop %sp
	add $2, %sp
	pop %ds
.endm

.macro freebpa
	pop %sp
.endm

.macro dump reg
	push %ax
	push %dx

	mov \reg, %ax
	mov $0x406, %dx
	outw %ax, %dx

	pop %dx
	pop %ax
.endm

.macro callout value
	push %bp
	push %bx
	mov %sp, %bp
	alloca $16
	push %ax
	push %dx

	mov %ax, 0(%bx)     /* ax */
	mov 0(%bp), %ax     /* bx */
	mov %ax, 2(%bx)
	mov %cx, 4(%bx)     /* cx */
	mov %dx, 6(%bx)     /* dx */
	mov %si, 8(%bx)     /* si */
	mov %ds, 10(%bx)    /* ds */
	mov %es, 12(%bx)    /* ds */
	movw \value, 14(%bx) /* value */

	mov %bx, %ax
	shr $4, %ax
	mov %ds, %dx
	add %dx, %ax

	mov $0x407, %dx
	outw %ax, %dx

	pop %dx
	pop %ax
	freea
	pop %bx
	pop %bp
.endm

send_command:
	push %bp
	mov %sp, %bp
	push %ax
	push %bx
	push %dx

	mov 4(%bp), %ax
	shr $4, %ax
	and $0x0FFF, %ax
	mov %ss, %bx
	add %bx, %ax

	mov $0x405, %dx
	outw %ax, %dx

	pop %dx
	pop %bx
	pop %ax
	pop %bp

	push %ax
	mov 2(%bx), %ax
	pop %ax

	ret

add32:  /* lo, hi, lo, hi */
	push %bp
	mov %sp, %bp

	movw 4(%bp), %cx  /* hi */
	movw 6(%bp), %dx  /* lo */

	add  10(%bp), %dx
	jnc 1f
	add $1, %cx
1:	add 8(%bp), %cx

	pop %bp
	ret

mul32:  /* lo,      hi,     lo,     hi */
	/* 10(%bp), 8(%bp), 6(%bp), 4(%bp) */
	push %bp
	mov %sp, %bp
	push %ax
	push %bx

	xor %cx, %cx
	xor %dx, %dx

	/* for (i = 0; i < 16;) */
	xor %bx, %bx
0:
	cmp $16, %bx
	jge 2f

	mov 6(%bp), %ax
	and $1, %ax
	cmp $1, %ax
	jne 1f
	push 10(%bp)
	push 8(%bp)
	push %dx
	push %cx
	call add32
	add $8, %sp
1:
	shlw $1, 8(%bp)
	movw 10(%bp), %ax
	and $0x8000, %ax
	cmp $0x8000, %ax
	jne 1f
	orw $1, 8(%bp)
1:
	shlw $1, 10(%bp)
	shrw $1, 6(%bp)

	/* i++) { */
	add $1, %bx
	jmp 0b

2:
	pop %bx
	pop %ax
	pop %bp
	ret

disk_reset:
	movb $0, %ah
	clc
	ret

/* this really should be a function, not a macro but i'm lazy */
.macro read_write_disk_sectors cmd
	push %ax
	push %bx
	push %cx
	push %dx
	push %si

	push %bp
	sub $10, %sp
	mov %sp, %bp

	/* save nb_sectors */
	mov %al, 6(%bp)
	movb $0, 7(%bp)

	/* save buffer */
	mov %bx, 8(%bp)

	/* cylinders */
	xor %ax, %ax
	mov %cl, %al
	shl $2, %ax
	and $0x300, %ax
	mov %ch, %al
	mov %ax, 0(%bp)

	/* heads */
	xor %ax, %ax
	mov %dh, %al
	mov %ax, 2(%bp)

	/* sectors - 1 */
	xor %ax, %ax
	mov %cl, %al
	and $0x3F, %al
	sub $1, %ax
	mov %ax, 4(%bp)

	alloca $8

	movw $0, 0(%bx) /* read c,h,s */
	push %bx
	call send_command
	add $2, %sp

	mov 6(%bx), %ax /* total_sectors */
	mov 2(%bp), %si /* *= heads */
	mul %si
	add 4(%bp), %ax /* += sectors - 1 */

	push 4(%bx) /* total_heads */
	push $0
	push 6(%bx) /* total_sectors */
	push $0
	call mul32
	add $8, %sp

	push 0(%bp) /* cylinders */
	push $0
	push %dx
	push %cx
	call mul32
	add $8, %sp

	add %ax, %dx
	jnc 1f
	add $1, %cx
1:
	freea

	alloca $16

	movw \cmd, 0(%bx) /* read */
	movw 6(%bp), %ax /* nb_sectors */
	movw %ax, 2(%bx)
	movw %es, 4(%bx) /* segment */
	movw 8(%bp), %ax /* offset */
	mov %ax, 6(%bx)
	movw %dx, 8(%bx) /* sector */
	movw %cx, 10(%bx)
	movw $0, 12(%bx)
	movw $0, 14(%bx)

	push %bx
	call send_command
	add $2, %sp

	freea

	add $10, %sp
	pop %bp

	pop %si
	pop %dx
	pop %cx
	pop %bx
	pop %ax

	mov $0, %ah
	clc
	ret
.endm

read_disk_sectors:
	read_write_disk_sectors $0x01

write_disk_sectors:
	read_write_disk_sectors $0x02

read_disk_drive_parameters:
	push %bx

	/* allocate memory for packet, pointer gets returned in bx */
	alloca $8

	/* issue command */
	movw $0, 0(%bx) /* cmd = 0, read c,h,s */
	push %bx
	call send_command
	add $2, %sp

	/* normalize sector value */
	movb 6(%bx), %cl
	andb $0x3F, %cl
	movb %cl, 6(%bx)

	/* normalize cylinders */
	subw $2, 2(%bx)

	/* normalize heads */
	subw $1, 4(%bx)

	/* return code */
	mov $0, %ah

	/* cylinders */
	movb 2(%bx), %ch
	movb 3(%bx), %cl
	shlb $6, %cl
	andb $0xC0, %cl

	/* sectors */
	orb 6(%bx), %cl

	/* heads */
	movb 4(%bx), %dh

	/* drives */
	movb $1, %dl

	/* status */
	mov $0, %ah

	freea

	pop %bx

	/* do this last since it's the most sensitive */
	clc
	ret

alternate_disk_reset:
	movb $0, %ah
	clc
	ret

read_disk_drive_size:
	push %bx
	alloca $8

	movw $0, 0(%bx) /* cmd = 0, read c,h,s */
	push %bx
	call send_command
	add $2, %sp

	/* cylinders - 1 to cx:dx */
	mov 2(%bx), %dx
	xor %cx, %cx
	sub $1, %dx

	/* heads */
	push 4(%bx)
	push $0
	push %dx
	push %cx
	call mul32
	add $8, %sp

	/* sectors */
	push 6(%bx)
	push $0
	push %dx
	push %cx
	call mul32
	add $8, %sp

	/* status */
	mov $3, %ah

	freea
	pop %bx

	clc
	ret

check_if_extensions_present:
	mov $0x30, %ah
	mov $0xAA55, %bx
	mov $0x07, %cx
	clc
	ret

.macro extended_read_write_sectors cmd
	cmpb $10, 0(%si)
	jg 1f
	mov $1, %ah
	stc
	ret
1:
	push %ax
	push %bp
	allocbpa $16

	movw \cmd, 0(%bp) /* read */
	movw 2(%si), %ax   /* nb_sectors */
	movw %ax, 2(%bp)
	movw 4(%si), %ax   /* offset */
	movw %ax, 6(%bp)
	movw 6(%si), %ax   /* segment */
	movw %ax, 4(%bp)
	movw 8(%si), %ax   /* block */
	movw %ax, 8(%bp)
	movw 10(%si), %ax
	movw %ax, 10(%bp)
	movw 12(%si), %ax
	movw %ax, 12(%bp)
	movw 14(%si), %ax
	movw %ax, 14(%bp)

	push %bp
	call send_command
	add $2, %sp

	freebpa
	pop %bp
	pop %ax

	mov $0, %ah
	clc
	ret
.endm

extended_read_sectors:
	extended_read_write_sectors $0x01

extended_write_sectors:
	extended_read_write_sectors $0x02

get_extended_drive_parameters:
	mov $1, %ah
	stc
	ret

terminate_disk_emulation:
	mov $1, %ah
	stc
	ret

int13_handler:
	cmp $0x80, %dl
	je 1f
	int $0x2c
	iret
1:
	cmp $0x0, %ah
	jne 1f
	call disk_reset
	iret
1:
	cmp $0x2, %ah
	jne 1f
	call read_disk_sectors
	iret
1:
	cmp $0x8, %ah
	jne 1f
	call read_disk_drive_parameters
	iret
1:
	cmp $0x15, %ah
	jne 1f
	call read_disk_drive_size
	iret
1:
	cmp $0x41, %ah
	jne 1f
	call check_if_extensions_present
	iret
1:
	cmp $0x42, %ah
	jne 1f
	call extended_read_sectors
	iret
1:
	cmp $0x48, %ah
	jne 1f
	call get_extended_drive_parameters
	iret
1:
	cmp $0x4b, %ah
	jne 1f
	call terminate_disk_emulation
	iret
1:
	cmp $0x0d, %ah
	jne 1f
	call alternate_disk_reset
	iret
1:
	cmp $0x03, %ah
	jne 1f
	call write_disk_sectors
	iret
1:
	cmp $0x43, %ah
	jne 1f
	call extended_write_sectors
	iret
1:
	int $0x18  /* boot failed */
	iret

.align 512, 0
_end:
