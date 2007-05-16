/*
 * GPR context switch between host and guest.
 * Used by IO-port-access emulation stub.
 *
 * Copyright (c) 2006, Novell, Inc.
 */

#include <xen/config.h>
#include <asm/asm_defns.h>

ENTRY(host_to_guest_gpr_switch)
        movl  (%esp), %ecx
        movl  %eax, (%esp)
        movl  UREGS_edx(%eax), %edx
        pushl %ebx
        movl  UREGS_ebx(%eax), %ebx
        pushl %ebp
        movl  UREGS_ebp(%eax), %ebp
        pushl %esi
        movl  UREGS_esi(%eax), %esi
        pushl %edi
        movl  UREGS_edi(%eax), %edi
        pushl $guest_to_host_gpr_switch
        pushl %ecx
        movl  UREGS_ecx(%eax), %ecx
        movl  UREGS_eax(%eax), %eax
        ret

ENTRY(guest_to_host_gpr_switch)
        pushl %edx
        movl  5*4(%esp), %edx
        movl  %eax, UREGS_eax(%edx)
        popl  UREGS_edx(%edx)
        movl  %edi, UREGS_edi(%edx)
        popl  %edi
        movl  %esi, UREGS_esi(%edx)
        popl  %esi
        movl  %ebp, UREGS_ebp(%edx)
        popl  %ebp
        movl  %ebx, UREGS_ebx(%edx)
        popl  %ebx
        movl  %ecx, UREGS_ecx(%edx)
        popl  %ecx
        ret
