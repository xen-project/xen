/* SPDX-License-Identifier: GPL-2.0-or-later */

        .file "x86_64/entry-fred.S"

#include <asm/asm_defns.h>
#include <asm/page.h>

        .section .text.entry, "ax", @progbits

        /* The Ring3 entry point is required to be 4k aligned. */

FUNC(entry_FRED_R3, 4096)
        PUSH_AND_CLEAR_GPRS

        mov     %rsp, %rdi
        call    entry_from_pv

        POP_GPRS
        eretu
END(entry_FRED_R3)

        /* The Ring0 entrypoint is at Ring3 + 0x100. */
        .org entry_FRED_R3 + 0x100, 0xcc

FUNC_LOCAL(entry_FRED_R0, 0)
        PUSH_AND_CLEAR_GPRS

        mov     %rsp, %rdi
        call    entry_from_xen

        POP_GPRS
        erets
END(entry_FRED_R0)
