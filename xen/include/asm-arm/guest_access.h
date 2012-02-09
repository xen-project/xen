#ifndef __ASM_ARM_GUEST_ACCESS_H__
#define __ASM_ARM_GUEST_ACCESS_H__

#include <xen/guest_access.h>
#include <xen/errno.h>

/* Guests have their own comlete address space */
#define access_ok(addr,size) (1)

#define array_access_ok(addr,count,size) \
    (likely(count < (~0UL/size)) && access_ok(addr,count*size))

unsigned long raw_copy_to_guest(void *to, const void *from, unsigned len);
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

/* Cast a guest handle to the specified type of handle. */
#define guest_handle_cast(hnd, type) ({         \
    type *_x = (hnd).p;                         \
    (XEN_GUEST_HANDLE(type)) { _x };            \
})

#define guest_handle_from_ptr(ptr, type)        \
    ((XEN_GUEST_HANDLE(type)) { (type *)ptr })
#define const_guest_handle_from_ptr(ptr, type)  \
    ((XEN_GUEST_HANDLE(const_##type)) { (const type *)ptr })

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
#define clear_guest_offset(hnd, off, ptr, nr) ({      \
    raw_clear_guest(_d+(off), nr);  \
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
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
