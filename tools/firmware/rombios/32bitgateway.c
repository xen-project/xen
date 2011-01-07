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
 * Copyright (c) 2008, Citrix Systems, Inc.
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 * Author: Keir Fraser <keir@xen.org>
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

/* At most 32 bytes in argument list to a 32-bit function. */
#define MAX_ARG_BYTES 32

#define REAL_MODE_CODE_OFFSET  0xf0000

/* Definitions of code/data segment descriptors. */
#define PM_32BIT_CS  (gdt_entry_pm_32bit_cs - gdt_base)
#define PM_16BIT_CS  (gdt_entry_pm_16bit_cs - gdt_base)
#define PM_32BIT_DS  (gdt_entry_pm_32bit_ds - gdt_base)
#define PM_16BIT_DS  (gdt_entry_pm_16bit_ds - gdt_base)

    .align 16
gdt_base:
    .word 0,0
    .byte 0,0,0,0
gdt_entry_pm_32bit_cs:
    .word 0xffff, 0x0000
    .byte 0x00, 0x9b, 0xcf, 0x00
gdt_entry_pm_16bit_cs:
    .word 0xffff, 0x0000
    .byte REAL_MODE_CODE_OFFSET >> 16, 0x9b, 0x8f, 0x0
gdt_entry_pm_32bit_ds:
    .word 0xffff, 0x0000
    .byte 0x0, 0x93, 0xcf, 0x0
gdt_entry_pm_16bit_ds:
    .word 0xffff, 0x0000
    .byte 0x0, 0x93, 0x8f, 0x0
gdt_entry_end:

protmode_gdtdesc:
    .word (gdt_entry_end - gdt_base) - 1
    .long gdt_base | REAL_MODE_CODE_OFFSET

realmode_gdtdesc:
    .word 0xffff
    .long 0x0

Upcall:
    ; Do an upcall into 32 bit space
    ;
    ; Input:
    ; bx: index of function to call
    ; Ouput:
    ; dx, ax: 32 bit result of call (even if 'void' is expected)

    ; Save caller state, stack frame offsets listed below
#define esp_off     0
#define ss_off      4
#define es_off      6
#define ds_off      8
#define flags_off   10
#define retaddr_off 12
#define args_off    14
    pushf
    cli
    push ds
    push es
    push ss
    push esp

    ; Calculate protected-mode esp from ss:sp
    and esp, #0xffff
    xor eax, eax
    mov ax, ss
    shl eax, #4
    add esp, eax

    ; Switch to protected mode
    seg cs
    lgdt protmode_gdtdesc
    mov eax, cr0
    or al, #0x1  ; protected mode on
    mov cr0, eax
    jmpf DWORD (REAL_MODE_CODE_OFFSET|upcall1), #PM_32BIT_CS
upcall1:
    USE32
    mov ax, #PM_32BIT_DS
    mov ds, ax
    mov es, ax
    mov ss, ax

    ; Marshal arguments and call 32-bit function
    mov ecx, #MAX_ARG_BYTES/4
upcall2:
    push MAX_ARG_BYTES-4+args_off[esp]
    loop upcall2
    mov eax, [BIOS_INFO_PHYSICAL_ADDRESS + BIOSINFO_OFF_bios32_entry]
    call eax
    add esp, #MAX_ARG_BYTES
    mov ecx, eax  ; Result in ecx

    ; Restore real-mode stack pointer
    xor eax, eax
    mov ax, ss_off[esp]
    mov bx, ax    ; Real-mode ss in bx
    shl eax, 4
    sub esp, eax

    ; Return to real mode
    jmpf upcall3, #PM_16BIT_CS
upcall3:
    USE16
    mov ax, #PM_16BIT_DS
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, cr0
    and al, #0xfe ; protected mode off
    mov cr0, eax
    jmpf upcall4, #REAL_MODE_CODE_OFFSET>>4
upcall4:
    seg cs
    lgdt realmode_gdtdesc

    ; Restore real-mode ss
    mov ss, bx

    ; Convert result into dx:ax format
    mov eax, ecx
    ror eax, #16
    mov dx, ax
    ror eax, #16

    ; Restore caller state and return
    pop esp
    pop bx ; skip ss
    pop es
    pop ds
    popf
    ret

MACRO DoUpcall
    mov bx, #?1
    jmp Upcall
MEND

#define X(idx, ret, fn, args...) _ ## fn: DoUpcall(idx)
#include "32bitprotos.h"
#undef X
