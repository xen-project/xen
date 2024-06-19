/******************************************************************************
 * guest_access.h
 * 
 * Copyright (c) 2006, K A Fraser
 */

#ifndef __ASM_X86_GUEST_ACCESS_H__
#define __ASM_X86_GUEST_ACCESS_H__

#include <asm/uaccess.h>
#include <asm/paging.h>
#include <asm/hvm/support.h>
#include <asm/hvm/guest_access.h>

/* Raw access functions: no type checking. */
#define raw_copy_to_guest(dst, src, len)        \
    (is_hvm_vcpu(current) ?                     \
     copy_to_user_hvm((dst), (src), (len)) :    \
     copy_to_guest_pv(dst, src, len))
#define raw_copy_from_guest(dst, src, len)      \
    (is_hvm_vcpu(current) ?                     \
     copy_from_user_hvm((dst), (src), (len)) :  \
     copy_from_guest_pv(dst, src, len))
#define raw_clear_guest(dst,  len)              \
    (is_hvm_vcpu(current) ?                     \
     clear_user_hvm((dst), (len)) :             \
     clear_guest_pv(dst, len))
#define __raw_copy_to_guest(dst, src, len)      \
    (is_hvm_vcpu(current) ?                     \
     copy_to_user_hvm((dst), (src), (len)) :    \
     __copy_to_guest_pv(dst, src, len))
#define __raw_copy_from_guest(dst, src, len)    \
    (is_hvm_vcpu(current) ?                     \
     copy_from_user_hvm((dst), (src), (len)) :  \
     __copy_from_guest_pv(dst, src, len))

/*
 * Pre-validate a guest handle.
 * Allows use of faster __copy_* functions.
 */
#define guest_handle_okay(hnd, nr)                      \
    (paging_mode_external(current->domain) ||           \
     array_access_ok((hnd).p, (nr), sizeof(*(hnd).p)))
#define guest_handle_subrange_okay(hnd, first, last)    \
    (paging_mode_external(current->domain) ||           \
     array_access_ok((unsigned long)(hnd).p + (first) * sizeof(*(hnd).p), \
                     (last)-(first)+1,                  \
                     sizeof(*(hnd).p)))

#endif /* __ASM_X86_GUEST_ACCESS_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
