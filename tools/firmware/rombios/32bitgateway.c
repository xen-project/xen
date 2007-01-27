/*
 *  Implementation of a gateway into 32bit space. Stub functions
 *  can be called from Bochs BIOS which call functions with a compatible
 *  signature in 32bit space. All interrupts are disabled while in
 *  32 bit mode.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

/*
 * Note:
 *  BCC's ABI does not require to preserve any 16bit registers ax, bx, cs, dx
 *  by a called function. So these registers need not be preserved while
 *  calling a function in 32bit space, either.
 *
 *  When bcc calls a function with 16bit parameters it pushes 2 bytes onto
 *  the stack for such a parameter. GCC, however, expects 32bit parameters
 *  (4 bytes) even for uint16_t, so casting to 32bit from bcc is a good idea.
 */

#define SEGMENT_OFFSET  0xf0000
#define REAL_MODE_CODE_SEGMENT  0xf000

#define START_PM_CODE  USE32
#define END_PM_CODE    USE16

/* definition of used code/data segment descriptors */
#define PM_NORMAL_CS (gdt_entry_pm_cs       - gdt_base)
#define PM_16BIT_CS  (gdt_entry_pm_16bit_cs - gdt_base)
#define PM_32BIT_DS  (gdt_entry_pm_32bit_ds - gdt_base)

  ASM_START

    ; Switch into protected mode to allow access to 32 bit addresses.
    ; This function allows switching into protected mode.
    ; (the specs says big real mode, but that will not work)
    ;
    ; preserves all registers and prepares cs, ds, es, ss for usage
    ; in protected mode; while in prot.mode interrupts remain disabled
switch_to_protmode:
    cli

    ; have to fix the stack for proper return address in 32 bit mode
    push WORD #(REAL_MODE_CODE_SEGMENT>>12)	;extended return address
    push bp					;pop@A1
    mov bp, sp
    push eax					;pop@A2
    mov eax, 2[bp]				; fix return address
    rol eax, #16
    mov 2[bp], eax

    mov eax, esp
    ror eax, #16				; hi(esp)

    push bx					; preserve before function call
    push cx
    push dx

    push ax					; prepare stack for
    push es					; call
    push ds
    push cs
    push ss
    call _store_segment_registers
    add sp, #10					; pop ax,es-ss

    pop dx					; restore after function call
    pop cx
    pop bx

    ; calculate protected-mode esp from ss:sp
    and esp, #0xffff
    xor eax, eax
    mov ax, ss
    rol eax, #4
    add eax, esp
    mov esp, eax

    seg cs
    lgdt my_gdtdesc				; switch to own table

    mov eax, cr0
    or	al, #0x1				; protected mode 'on'
    mov cr0, eax

    jmpf DWORD (SEGMENT_OFFSET | switch_to_protmode_goon_1), #PM_NORMAL_CS

    START_PM_CODE

switch_to_protmode_goon_1:
    mov ax, #PM_32BIT_DS			; 32 bit segment that allows
    mov ds, ax					; to reach all 32 bit
    mov es, ax					; addresses
    mov ss, ax

    pop eax					;@A2
    pop bp					;@A1
    ret

    END_PM_CODE



    .align 16
gdt_base:
    ; see Intel SW Dev. Manuals section 3.4.5, Volume 3 for meaning of bits
    .word 0,0
    .byte 0,0,0,0

gdt_entry_pm_cs:
    ; 32 bit code segment for protected mode
    .word 0xffff, 0x0000
    .byte 0x00, 0x9a, 0xcf, 0x00

gdt_entry_pm_16bit_cs:
    ; temp. 16 bit code segment used while in protected mode
    .word 0xffff, 0x0000
    .byte SEGMENT_OFFSET >> 16, 0x9a, 0x0, 0x0

gdt_entry_pm_32bit_ds:
    ; (32 bit) data segment (r/w) reaching all possible areas in 32bit memory
    ; 4kb granularity
    .word 0xffff, 0x0000
    .byte 0x0, 0x92, 0xcf, 0x0
gdt_entry_end:

my_gdtdesc:
    .word (gdt_entry_end - gdt_base) - 1
    .long gdt_base | SEGMENT_OFFSET


realmode_gdtdesc:				;to be used in real mode
    .word 0xffff
    .long 0x0



switch_to_realmode:
    ; Implementation of switching from protected mode to real mode
    ; restores all registers and prepares cs, es, ds, ss to be used
    ; in real mode
    START_PM_CODE

    ; need to fix up the stack to return in 16 bit mode
    ; currently the 32 bit return address is on the stack
    push bp					;pop@A1
    mov bp, sp
    push eax					;pop@X

    mov eax, [bp]				; return address low 16bits
                  				; and 'bp' are being moved
    mov 2[bp], eax

    pop eax					;@X
    add sp, #2					; adjust stack for 'lost' bytes

    push eax					;pop@1
    push bx					;pop@2
    push si					;pop@3

    call _ebda_ss_offset32			; get the offset of the ss
    mov bx, ax					; entry within the ebda.

    jmpf switch_to_realmode_goon_1, #PM_16BIT_CS

    END_PM_CODE

switch_to_realmode_goon_1:
    mov eax, cr0
    and al, #0xfe				; protected mode 'off'
    mov cr0, eax

    jmpf switch_to_realmode_goon_2, #REAL_MODE_CODE_SEGMENT

switch_to_realmode_goon_2:

    ; get orig. 'ss' without using the stack (no 'call'!)
    xor eax, eax			; clear upper 16 bits (and lower)
    mov ax, #0x40			; where is the ebda located?
    mov ds, ax
    mov si, #0xe
    seg ds
    mov ax, [si]			; ax = segment of ebda

    mov ds, ax				; segment of ebda
    seg ds
    mov ax, [bx]			; stack segment - bx has been set above
    mov ss, ax

    ; from esp and ss calculate real-mode sp
    rol eax, #4
    sub esp, eax

    push dx				;preserve before call(s)
    push cx
    push bx

    call _get_register_ds		; get orig. 'ds'
    mov ds, ax
    call _get_register_es		; get orig. 'es'
    mov es, ax
    call _get_register_esp_hi		; fix the upper 16 bits of esp
    ror esp, #16
    mov sp, ax
    rol esp, #16

    pop bx
    pop cx
    pop dx

    seg cs
    lgdt realmode_gdtdesc

    sti						; allow interrupts

    pop si					;@3
    pop bx					;@2
    pop eax					;@1
    pop bp					;@A1

    ret

    ASM_END

/*
 * Helper function to get the offset of the reg_ss within the ebda struct
 * Only 'C' can tell the offset.
 */
Bit16u
ebda_ss_offset32()
{
    ASM_START
    START_PM_CODE				// need to have this
    ASM_END					// compiled for protected mode
    return &EbdaData->upcall.reg_ss;		// 'C' knows the offset!
    ASM_START
    END_PM_CODE
    ASM_END
}

/*
 * Two often-used functions
 */
Bit16u
read_word_from_ebda(offset)
    Bit16u offset;
{
	Bit16u ebda_seg = read_word(0x0040, 0x000E);
	return read_word(ebda_seg, offset);
}

Bit32u
read_dword_from_ebda(offset)
    Bit16u offset;
{
	Bit16u ebda_seg = read_word(0x0040, 0x000E);
	return read_dword(ebda_seg, offset);
}

/*
 * Store registers in the EBDA; used to keep the registers'
 * content in a well-defined place during protected mode execution
 */
  void
store_segment_registers(ss, cs, ds, es, esp_hi)
  Bit16u ss, cs, ds, es, esp_hi;
{
	Bit16u ebda_seg = read_word(0x0040, 0x000E);
	write_word(ebda_seg, &EbdaData->upcall.reg_ss, ss);
	write_word(ebda_seg, &EbdaData->upcall.reg_cs, cs);
	write_word(ebda_seg, &EbdaData->upcall.reg_ds, ds);
	write_word(ebda_seg, &EbdaData->upcall.reg_es, es);
	write_word(ebda_seg, &EbdaData->upcall.esp_hi, esp_hi);
}


  void
store_returnaddress(retaddr)
   Bit16u retaddr;
{
	Bit16u ebda_seg = read_word(0x0040, 0x000E);
	write_word(ebda_seg, &EbdaData->upcall.retaddr, retaddr);
}

Bit16u
get_returnaddress()
{
	return read_word_from_ebda(&EbdaData->upcall.retaddr);
}

/*
 * get the segment register 'cs' value from the EBDA
 */
Bit16u
get_register_cs()
{
	return read_word_from_ebda(&EbdaData->upcall.reg_cs);
}

/*
 * get the segment register 'ds' value from the EBDA
 */
Bit16u
get_register_ds()
{
	return read_word_from_ebda(&EbdaData->upcall.reg_ds);
}

/*
 * get the segment register 'es' value from the EBDA
 */
Bit16u
get_register_es()
{
	return read_word_from_ebda(&EbdaData->upcall.reg_es);
}

/*
 * get the upper 16 bits of the esp from the EBDA
 */
Bit16u
get_register_esp_hi()
{
	return read_word_from_ebda(&EbdaData->upcall.esp_hi);
}



/********************************************************/


ASM_START

Upcall:
	; do the upcall into 32 bit space
	; clear the stack frame so that 32 bit space sees all the parameters
	; on the stack as if they were prepared for it
	; ---> take the 16 bit return address off the stack and remember it
	;
	; Input:
	; bx: index of function to call
	; Ouput:
	; dx, ax: 32 bit result of call (even if 'void' is expected)

	push bp				;pop @1
	mov bp, sp
	push si				;pop @2

	mov ax, 2[bp]			; 16 bit return address
	push ax
	call _store_returnaddress	; store away
	pop ax

	rol bx, #2
	mov si, #jmptable
	seg cs
	mov eax, dword ptr [si+bx]	; address to call from table

	pop si				;@2
	pop bp				;@1

	add sp, #2			; remove 16bit return address from stack

	call switch_to_protmode
	START_PM_CODE

	call eax			; call 32bit function
	push eax			; preserve result

	call switch_to_realmode		; back to realmode
	END_PM_CODE

	pop eax				; get result

	push word 0x0000		; placeholder for 16 bit return address
	push bp
	mov bp,sp
	push eax			; preserve work register

	call _get_returnaddress
	mov 2[bp], ax			; 16bit return address onto stack

	pop eax
	pop bp

	ror eax, #16			; result into dx/ax
	mov dx, ax			; hi(res) -> dx
	ror eax, #16

	ret


/* macro for functions to declare their call into 32bit space */
MACRO DoUpcall
	mov bx, #?1
	jmp Upcall
MEND


ASM_END

#include "32bitprotos.h"
#include "32bitgateway.h"

#include "tcgbios.c"
