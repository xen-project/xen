/******************************************************************************
 * guest_access.h
 * 
 * Copyright (x) 2006, K A Fraser
 */

#ifndef __XEN_GUEST_ACCESS_H__
#define __XEN_GUEST_ACCESS_H__

#include <asm/guest_access.h>
#include <xen/types.h>
#include <public/xen.h>

/* Is the guest handle a NULL reference? */
#define guest_handle_is_null(hnd)        ((hnd).p == NULL)

/* Offset the given guest handle into the array it refers to. */
#define guest_handle_add_offset(hnd, nr) ((hnd).p += (nr))
#define guest_handle_subtract_offset(hnd, nr) ((hnd).p -= (nr))

/*
 * Cast a guest handle (either XEN_GUEST_HANDLE or XEN_GUEST_HANDLE_PARAM)
 * to the specified type of XEN_GUEST_HANDLE_PARAM.
 */
#define guest_handle_cast(hnd, type) ({         \
    type *_x = (hnd).p;                         \
    (XEN_GUEST_HANDLE_PARAM(type)) { _x };      \
})
/* Same for casting to a const type. */
#define guest_handle_const_cast(hnd, type) ({      \
    const type *p_ = (hnd).p;                      \
    (XEN_GUEST_HANDLE_PARAM(const_##type)) { p_ }; \
})

/* Cast a XEN_GUEST_HANDLE to XEN_GUEST_HANDLE_PARAM */
#define guest_handle_to_param(hnd, type) ({                  \
    typeof((hnd).p) _x = (hnd).p;                            \
    XEN_GUEST_HANDLE_PARAM(type) _y = { _x };                \
    /*                                                       \
     * type checking: make sure that the pointers inside     \
     * XEN_GUEST_HANDLE and XEN_GUEST_HANDLE_PARAM are of    \
     * the same type, then return hnd.                       \
     */                                                      \
    (void)(&_x == &_y.p);                                    \
    _y;                                                      \
})

#define guest_handle_for_field(hnd, type, fld)          \
    ((XEN_GUEST_HANDLE(type)) { &(hnd).p->fld })

#define guest_handle_from_ptr(ptr, type)        \
    ((XEN_GUEST_HANDLE_PARAM(type)) { (type *)ptr })
#define const_guest_handle_from_ptr(ptr, type)  \
    ((XEN_GUEST_HANDLE_PARAM(const_##type)) { (const type *)ptr })

/*
 * Copy an array of objects to guest context via a guest handle,
 * specifying an offset into the guest array.
 */
#define copy_to_guest_offset(hnd, off, ptr, nr) ({      \
    const typeof(*(ptr)) *_s = (ptr);                   \
    char (*_d)[sizeof(*_s)] = (void *)(hnd).p;          \
    /* Check that the handle is not for a const type */ \
    void *__maybe_unused _t = (hnd).p;                  \
    (void)((hnd).p == _s);                              \
    raw_copy_to_guest(_d+(off), _s, sizeof(*_s)*(nr));  \
})

/*
 * Clear an array of objects in guest context via a guest handle,
 * specifying an offset into the guest array.
 */
#define clear_guest_offset(hnd, off, nr) ({    \
    void *_d = (hnd).p;                        \
    raw_clear_guest(_d+(off), nr);             \
})

/*
 * Copy an array of objects from guest context via a guest handle,
 * specifying an offset into the guest array.
 */
#define copy_from_guest_offset(ptr, hnd, off, nr) ({    \
    const typeof(*(ptr)) *_s = (hnd).p;                 \
    typeof(*(ptr)) *_d = (ptr);                         \
    raw_copy_from_guest(_d, _s+(off), sizeof(*_d)*(nr));\
})

/* Copy sub-field of a structure to guest context via a guest handle. */
#define copy_field_to_guest(hnd, ptr, field) ({         \
    const typeof(&(ptr)->field) _s = &(ptr)->field;     \
    void *_d = &(hnd).p->field;                         \
    (void)(&(hnd).p->field == _s);                      \
    raw_copy_to_guest(_d, _s, sizeof(*_s));             \
})

/* Copy sub-field of a structure from guest context via a guest handle. */
#define copy_field_from_guest(ptr, hnd, field) ({       \
    const typeof(&(ptr)->field) _s = &(hnd).p->field;   \
    typeof(&(ptr)->field) _d = &(ptr)->field;           \
    raw_copy_from_guest(_d, _s, sizeof(*_d));           \
})

#define copy_to_guest(hnd, ptr, nr)                     \
    copy_to_guest_offset(hnd, 0, ptr, nr)

#define copy_from_guest(ptr, hnd, nr)                   \
    copy_from_guest_offset(ptr, hnd, 0, nr)

#define clear_guest(hnd, nr)                            \
    clear_guest_offset(hnd, 0, nr)

/*
 * The __copy_* functions should only be used after the guest handle has
 * been pre-validated via guest_handle_okay() and
 * guest_handle_subrange_okay().
 */

#define __copy_to_guest_offset(hnd, off, ptr, nr) ({        \
    const typeof(*(ptr)) *_s = (ptr);                       \
    char (*_d)[sizeof(*_s)] = (void *)(hnd).p;              \
    /* Check that the handle is not for a const type */     \
    void *__maybe_unused _t = (hnd).p;                      \
    (void)((hnd).p == _s);                                  \
    __raw_copy_to_guest(_d + (off), _s, sizeof(*_s) * (nr));\
})

#define __clear_guest_offset(hnd, off, nr) ({    \
    void *_d = (hnd).p;                          \
    __raw_clear_guest(_d + (off), nr);           \
})

#define __copy_from_guest_offset(ptr, hnd, off, nr) ({          \
    const typeof(*(ptr)) *_s = (hnd).p;                         \
    typeof(*(ptr)) *_d = (ptr);                                 \
    __raw_copy_from_guest(_d, _s + (off), sizeof (*_d) * (nr)); \
})

#define __copy_field_to_guest(hnd, ptr, field) ({       \
    const typeof(&(ptr)->field) _s = &(ptr)->field;     \
    void *_d = &(hnd).p->field;                         \
    (void)(&(hnd).p->field == _s);                      \
    __raw_copy_to_guest(_d, _s, sizeof(*_s));           \
})

#define __copy_field_from_guest(ptr, hnd, field) ({     \
    const typeof(&(ptr)->field) _s = &(hnd).p->field;   \
    typeof(&(ptr)->field) _d = &(ptr)->field;           \
    __raw_copy_from_guest(_d, _s, sizeof(*_d));         \
})

#define __copy_to_guest(hnd, ptr, nr)                   \
    __copy_to_guest_offset(hnd, 0, ptr, nr)

#define __copy_from_guest(ptr, hnd, nr)                 \
    __copy_from_guest_offset(ptr, hnd, 0, nr)

#define __clear_guest(hnd, nr)                          \
    __clear_guest_offset(hnd, 0, nr)

char *safe_copy_string_from_guest(XEN_GUEST_HANDLE(char) u_buf,
                                  size_t size, size_t max_size);

#endif /* __XEN_GUEST_ACCESS_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
