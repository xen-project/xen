#ifndef __ASM_ARM_GUEST_ACCESS_H__
#define __ASM_ARM_GUEST_ACCESS_H__

#include <xen/guest_access.h>
#include <xen/errno.h>

/* Guests have their own comlete address space */
#define access_ok(addr,size) (1)

#define array_access_ok(addr,count,size) \
    (likely(count < (~0UL/size)) && access_ok(addr,count*size))

unsigned long raw_copy_to_guest(void *to, const void *from, unsigned len);
unsigned long raw_copy_to_guest_flush_dcache(void *to, const void *from,
                                             unsigned len);
unsigned long raw_copy_from_guest(void *to, const void *from, unsigned len);
unsigned long raw_clear_guest(void *to, unsigned len);

#define __raw_copy_to_guest raw_copy_to_guest
#define __raw_copy_from_guest raw_copy_from_guest
#define __raw_clear_guest raw_clear_guest

/* Remainder copied from x86 -- could be common? */

/* Is the guest handle a NULL reference? */
#define guest_handle_is_null(hnd)        ((hnd).p == NULL)

/* Offset the given guest handle into the array it refers to. */
#define guest_handle_add_offset(hnd, nr) ((hnd).p += (nr))
#define guest_handle_subtract_offset(hnd, nr) ((hnd).p -= (nr))

/* Cast a guest handle (either XEN_GUEST_HANDLE or XEN_GUEST_HANDLE_PARAM)
 * to the specified type of XEN_GUEST_HANDLE_PARAM. */
#define guest_handle_cast(hnd, type) ({         \
    type *_x = (hnd).p;                         \
    (XEN_GUEST_HANDLE_PARAM(type)) { _x };            \
})

/* Cast a XEN_GUEST_HANDLE to XEN_GUEST_HANDLE_PARAM */
#define guest_handle_to_param(hnd, type) ({                  \
    typeof((hnd).p) _x = (hnd).p;                            \
    XEN_GUEST_HANDLE_PARAM(type) _y = { _x };                \
    /* type checking: make sure that the pointers inside     \
     * XEN_GUEST_HANDLE and XEN_GUEST_HANDLE_PARAM are of    \
     * the same type, then return hnd */                     \
    (void)(&_x == &_y.p);                                    \
    _y;                                                      \
})


/* Cast a XEN_GUEST_HANDLE_PARAM to XEN_GUEST_HANDLE */
#define guest_handle_from_param(hnd, type) ({               \
    typeof((hnd).p) _x = (hnd).p;                           \
    XEN_GUEST_HANDLE(type) _y = { _x };                     \
    /* type checking: make sure that the pointers inside    \
     * XEN_GUEST_HANDLE and XEN_GUEST_HANDLE_PARAM are of   \
     * the same type, then return hnd */                    \
    (void)(&_x == &_y.p);                                   \
    _y;                                                     \
})

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
    ((void)((hnd).p == (ptr)));                         \
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
    ((void)(&(hnd).p->field == &(ptr)->field));         \
    raw_copy_to_guest(_d, _s, sizeof(*_s));             \
})

/* Copy sub-field of a structure from guest context via a guest handle. */
#define copy_field_from_guest(ptr, hnd, field) ({       \
    const typeof(&(ptr)->field) _s = &(hnd).p->field;   \
    typeof(&(ptr)->field) _d = &(ptr)->field;           \
    raw_copy_from_guest(_d, _s, sizeof(*_d));           \
})

/*
 * Pre-validate a guest handle.
 * Allows use of faster __copy_* functions.
 */
/* All ARM guests are paging mode external and hence safe */
#define guest_handle_okay(hnd, nr) (1)
#define guest_handle_subrange_okay(hnd, first, last) (1)

#define __copy_to_guest_offset(hnd, off, ptr, nr) ({    \
    const typeof(*(ptr)) *_s = (ptr);                   \
    char (*_d)[sizeof(*_s)] = (void *)(hnd).p;          \
    ((void)((hnd).p == (ptr)));                         \
    __raw_copy_to_guest(_d+(off), _s, sizeof(*_s)*(nr));\
})

#define __clear_guest_offset(hnd, off, ptr, nr) ({      \
    __raw_clear_guest(_d+(off), nr);  \
})

#define __copy_from_guest_offset(ptr, hnd, off, nr) ({  \
    const typeof(*(ptr)) *_s = (hnd).p;                 \
    typeof(*(ptr)) *_d = (ptr);                         \
    __raw_copy_from_guest(_d, _s+(off), sizeof(*_d)*(nr));\
})

#define __copy_field_to_guest(hnd, ptr, field) ({       \
    const typeof(&(ptr)->field) _s = &(ptr)->field;     \
    void *_d = &(hnd).p->field;                         \
    ((void)(&(hnd).p->field == &(ptr)->field));         \
    __raw_copy_to_guest(_d, _s, sizeof(*_s));           \
})

#define __copy_field_from_guest(ptr, hnd, field) ({     \
    const typeof(&(ptr)->field) _s = &(hnd).p->field;   \
    typeof(&(ptr)->field) _d = &(ptr)->field;           \
    __raw_copy_from_guest(_d, _s, sizeof(*_d));         \
})

#endif /* __ASM_ARM_GUEST_ACCESS_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
