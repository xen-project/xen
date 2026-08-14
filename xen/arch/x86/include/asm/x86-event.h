/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * x86-event.h
 *
 * Helper definitions for event handling, which aren't prescribed by the
 * architecture itself.
 */

#ifndef X86_X86_EVENT_H
#define X86_X86_EVENT_H

#ifdef __XEN__
# include <xen/types.h>
#else
# include <stdint.h>
#endif

#define X86_EVENT_NO_EC (-1)        /* No error code. */

struct x86_event {
    int16_t       vector;
    uint8_t       type;         /* X86_ET_* */
    uint8_t       insn_len;     /* Instruction length */
    int32_t       error_code;   /* X86_EVENT_NO_EC if n/a */

    /*
     * As per the FRED spec.
     *
     * A subset of uses occur in IDT mode as well:
     * - #PF: CR2
     * - #DB: PENDING_DBG (new DR6 bits with positive polarity)
     * - #NM: XFD_ERR (AMX)
     */
    unsigned long data;
};

#endif /* X86_X86_EVENT_H */
