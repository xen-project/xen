/******************************************************************************
 * guest_access.h
 * 
 * Copyright (c) 2006, K A Fraser
 */

#ifndef __ASM_X86_GUEST_ACCESS_H__
#define __ASM_X86_GUEST_ACCESS_H__

#include <asm/uaccess.h>
#include <asm/shadow.h>
#include <asm/hvm/support.h>
#include <asm/hvm/guest_access.h>

/* Is the guest handle a NULL reference? */
#define guest_handle_is_null(hnd)        ((hnd).p == NULL)

/* Offset the given guest handle into the array it refers to. */
#define guest_handle_add_offset(hnd, nr) ((hnd).p += (nr))

/* Cast a guest handle to the specified type of handle. */
#define guest_handle_cast(hnd, type) ({         \
    type *_x = (hnd).p;                         \
    (XEN_GUEST_HANDLE(type)) { _x };            \
})

#define guest_handle_from_ptr(ptr, type)        \
    ((XEN_GUEST_HANDLE(type)) { (type *)ptr })

/*
 * Copy an array of objects to guest context via a guest handle,
 * specifying an offset into the guest array.
 */
#define copy_to_guest_offset(hnd, off, ptr, nr) ({      \
    typeof(ptr) _x = (hnd).p;                           \
    const typeof(ptr) _y = (ptr);                       \
    is_hvm_vcpu(current) ?                              \
    copy_to_user_hvm(_x+(off), _y, sizeof(*_x)*(nr)) :  \
    copy_to_user(_x+(off), _y, sizeof(*_x)*(nr));       \
})

/*
 * Copy an array of objects from guest context via a guest handle,
 * specifying an offset into the guest array.
 */
#define copy_from_guest_offset(ptr, hnd, off, nr) ({    \
    const typeof(ptr) _x = (hnd).p;                     \
    typeof(ptr) _y = (ptr);                             \
    is_hvm_vcpu(current) ?                              \
    copy_from_user_hvm(_y, _x+(off), sizeof(*_x)*(nr)) :\
    copy_from_user(_y, _x+(off), sizeof(*_x)*(nr));     \
})

/* Copy sub-field of a structure to guest context via a guest handle. */
#define copy_field_to_guest(hnd, ptr, field) ({         \
    typeof(&(ptr)->field) _x = &(hnd).p->field;         \
    const typeof(&(ptr)->field) _y = &(ptr)->field;     \
    is_hvm_vcpu(current) ?                              \
    copy_to_user_hvm(_x, _y, sizeof(*_x)) :             \
    copy_to_user(_x, _y, sizeof(*_x));                  \
})

/* Copy sub-field of a structure from guest context via a guest handle. */
#define copy_field_from_guest(ptr, hnd, field) ({       \
    const typeof(&(ptr)->field) _x = &(hnd).p->field;   \
    typeof(&(ptr)->field) _y = &(ptr)->field;           \
    is_hvm_vcpu(current) ?                              \
    copy_from_user_hvm(_y, _x, sizeof(*_x)) :           \
    copy_from_user(_y, _x, sizeof(*_x));                \
})

/*
 * Pre-validate a guest handle.
 * Allows use of faster __copy_* functions.
 */
#define guest_handle_okay(hnd, nr)                      \
    (shadow_mode_external(current->domain) ||           \
     array_access_ok((hnd).p, (nr), sizeof(*(hnd).p)))

#define __copy_to_guest_offset(hnd, off, ptr, nr) ({    \
    typeof(ptr) _x = (hnd).p;                           \
    const typeof(ptr) _y = (ptr);                       \
    is_hvm_vcpu(current) ?                              \
    copy_to_user_hvm(_x+(off), _y, sizeof(*_x)*(nr)) :  \
    __copy_to_user(_x+(off), _y, sizeof(*_x)*(nr));     \
})

#define __copy_from_guest_offset(ptr, hnd, off, nr) ({  \
    const typeof(ptr) _x = (hnd).p;                     \
    typeof(ptr) _y = (ptr);                             \
    is_hvm_vcpu(current) ?                              \
    copy_from_user_hvm(_y, _x+(off),sizeof(*_x)*(nr)) : \
    __copy_from_user(_y, _x+(off), sizeof(*_x)*(nr));   \
})

#define __copy_field_to_guest(hnd, ptr, field) ({       \
    typeof(&(ptr)->field) _x = &(hnd).p->field;         \
    const typeof(&(ptr)->field) _y = &(ptr)->field;     \
    is_hvm_vcpu(current) ?                              \
    copy_to_user_hvm(_x, _y, sizeof(*_x)) :             \
    __copy_to_user(_x, _y, sizeof(*_x));                \
})

#define __copy_field_from_guest(ptr, hnd, field) ({     \
    const typeof(&(ptr)->field) _x = &(hnd).p->field;   \
    typeof(&(ptr)->field) _y = &(ptr)->field;           \
    is_hvm_vcpu(current) ?                              \
    copy_from_user_hvm(_y, _x, sizeof(*_x)) :           \
    __copy_from_user(_y, _x, sizeof(*_x));              \
})

#endif /* __ASM_X86_GUEST_ACCESS_H__ */
