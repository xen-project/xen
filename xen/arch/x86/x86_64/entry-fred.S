/* SPDX-License-Identifier: GPL-2.0-or-later */

        .file "x86_64/entry-fred.S"

#include <asm/asm_defns.h>
#include <asm/page.h>
#include <asm/processor.h>

        .section .text.entry, "ax", @progbits

        /* The Ring3 entry point is required to be 4k aligned. */

FUNC(entry_FRED_R3, 4096)
        PUSH_AND_CLEAR_GPRS

        mov     %rsp, %rdi
        call    entry_from_pv

#ifdef CONFIG_PV
        GET_STACK_END(14)
        movq    STACK_CPUINFO_FIELD(current_vcpu)(%r14), %rbx

        jmp     test_all_events
#else
        BUG     /* Not Reached */
#endif
END(entry_FRED_R3)

FUNC(eretu_exit_to_guest)
        /*
         * PV guests aren't aware of FRED.  If Xen in IDT mode would have used
         * a SYSRET instruction, preserve the legacy behaviour for %rcx/%r11
         */
        testb   $TRAP_syscall >> 8, UREGS_entry_vector + 1(%rsp)

        POP_GPRS /* Preserves flags */

        cmovnz  EFRAME_rip(%rsp), %rcx
        cmovnz  EFRAME_eflags(%rsp), %r11

        /*
         * Exceptions here are handled by redirecting either to
         * entry_FRED_R3() (for an error to be passed to the guest), or to
         * eretu_error_dom_crash() (for a Xen error handling guest state).
         */
LABEL(eretu, 0)
        eretu
END(eretu_exit_to_guest)

FUNC(eretu_error_dom_crash)
        PUSH_AND_CLEAR_GPRS
        sti
        call    asm_domain_crash_synchronous  /* Does not return */
END(eretu_error_dom_crash)

        /* The Ring0 entrypoint is at Ring3 + 0x100. */
        .org entry_FRED_R3 + 0x100, 0xcc

FUNC_LOCAL(entry_FRED_R0, 0)
        PUSH_AND_CLEAR_GPRS

        mov     %rsp, %rdi
        call    entry_from_xen

        POP_GPRS
        erets
END(entry_FRED_R0)
