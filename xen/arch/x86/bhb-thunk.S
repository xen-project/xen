/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Branch History Injection clearing sequences.
 *
 * https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/branch-history-injection.html
 *
 * Copyright (c) 2023, 2024 XenServer.
 */
        .file __FILE__

#include <asm/asm_defns.h>

        .section .text.entry, "ax", @progbits

/*
 * Clear the Branch History Buffer using a TSX Abort.
 *
 * Any TSX Abort has a side effect of clearing the BHB, even when TSX is
 * disabled for e.g. TAA mitigation reasons.
 */
FUNC(clear_bhb_tsx)
        .byte 0xc7, 0xf8; .long 1f - 0f /* xbegin 1f */
0:      .byte 0xc6, 0xf8, 0             /* xabort $0 */
        int3
1:
        ret
END(clear_bhb_tsx)

/*
 * Clear the Branch History Buffer using the software sequence.
 *
 * Clobbers: %eax, %ecx
 *
 * This executes a specific number of taken branches, sufficient to displace
 * all prior entries in the history tracker, therefore removing prior
 * influence on subsequent BTB lookups.
 *
 * Structurally, it looks like this:
 *
 *   call 1
 *     call 2
 *       ... 5x jmp loop
 *       call 2
 *         ... 5x jmp loop
 *         ... 5x call2's deep
 *
 *         ret
 *       ret
 *     ret
 *   ret
 *
 * The CALL/RETs are necessary to prevent the Loop Stream Detector from
 * interfering.  The alignment is for performance and not safety.
 *
 * The "short" sequence (5 and 5) is for CPUs prior to Alder Lake / Sapphire
 * Rapids (i.e. Cores prior to Golden Cove and/or Gracemont).
 *
 * The "long" sequence (12 and 7) is for Alder Lake / Sapphire Rapids
 * (i.e. Golden Cove and/or Gracemont cores).  However, such CPUs are expected
 * to use BHI_DIS_S in preference.
 */
FUNC(clear_bhb_loops)
        ALTERNATIVE "mov $5, %ecx", "mov $12, %ecx", X86_SPEC_BHB_LOOPS_LONG

        call    1f
        jmp     5f
        int3

        .align 64
1:      call    2f
        ret
        int3

        .align 64
2:      ALTERNATIVE "mov $5, %eax", "mov $7, %eax", X86_SPEC_BHB_LOOPS_LONG

3:      jmp     4f
        int3

4:      sub     $1, %eax
        jnz     3b

        sub     $1, %ecx
        jnz     1b

        ret
5:
        /*
         * The Intel sequence has an LFENCE here.  The purpose is to ensure
         * that all prior branches have executed, before dispatching a
         * subsequent indirect branch.
         *
         * Xen's SPEC_CTRL_ENTRY_* blocks have safety LFENCEs at the end when
         * protections are active, which suffices for this purpose.
         */

        ret
END(clear_bhb_loops)
