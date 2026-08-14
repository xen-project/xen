/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * x86-types.h
 *
 * Type definitions and basic helpers which are more or less directly
 * describing aspects of the architecture.
 */

#ifndef X86_X86_TYPES_H
#define X86_X86_TYPES_H

#ifdef __XEN__
# include <xen/types.h>
#else
# include <stdint.h>
#endif

/*
 * x86 Segments.
 *
 * Various areas of code rely on this order (general purpose before system,
 * tr at the beginning of system).
 */
enum x86_segment {
    /* General purpose.  Matches the SReg3 encoding in opcode/ModRM bytes. */
    x86_seg_es,
    x86_seg_cs,
    x86_seg_ss,
    x86_seg_ds,
    x86_seg_fs,
    x86_seg_gs,
    /* System: Valid to use for implicit table references. */
    x86_seg_tr,
    x86_seg_ldtr,
    x86_seg_gdtr,
    x86_seg_idtr,
    /* No Segment: For (system/normal) accesses which are already linear. */
    x86_seg_sys,
    x86_seg_none
};

static inline bool is_x86_user_segment(enum x86_segment seg)
{
    unsigned int idx = seg;

    return idx <= x86_seg_gs;
}
static inline bool is_x86_system_segment(enum x86_segment seg)
{
    return seg >= x86_seg_tr && seg < x86_seg_none;
}

/*
 * Full state of a segment register (visible and hidden portions).
 * Chosen to match the format of an AMD SVM VMCB.
 */
struct segment_register {
    uint16_t   sel;
    union {
        uint16_t attr;
        struct {
            uint16_t type:4;
            uint16_t s:   1;
            uint16_t dpl: 2;
            uint16_t p:   1;
            uint16_t avl: 1;
            uint16_t l:   1;
            uint16_t db:  1;
            uint16_t g:   1;
            uint16_t pad: 4;
        };
    };
    uint32_t   limit;
    uint64_t   base;
};

#endif /* X86_X86_TYPES_H */
