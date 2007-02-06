/******************************************************************************
 * compat.h
 */

#ifndef __XEN_COMPAT_H__
#define __XEN_COMPAT_H__

#include <xen/config.h>

#ifdef CONFIG_COMPAT

#include <xen/types.h>
#include <asm/compat.h>
#include <compat/xlat.h>

#define __DEFINE_COMPAT_HANDLE(name, type) \
    typedef struct { \
        compat_ptr_t c; \
        type *_[0] __attribute__((__packed__)); \
    } __compat_handle_ ## name

#define DEFINE_COMPAT_HANDLE(name)   __DEFINE_COMPAT_HANDLE(name, name)
#define COMPAT_HANDLE(name)          __compat_handle_ ## name

/* Is the compat handle a NULL reference? */
#define compat_handle_is_null(hnd)        ((hnd).c == 0)

/* Offset the given compat handle into the array it refers to. */
#define compat_handle_add_offset(hnd, nr)                            \
    ((hnd).c += (nr) * sizeof(**(hnd)._))

/* Cast a compat handle to the specified type of handle. */
#define compat_handle_cast(chnd, type) ({                            \
    type *_x = (__typeof__(**(chnd)._) *)(full_ptr_t)(chnd).c;       \
    (XEN_GUEST_HANDLE(type)) { _x };                                 \
})

#define guest_from_compat_handle(ghnd, chnd)                         \
    set_xen_guest_handle(ghnd,                                       \
                         (__typeof__(**(chnd)._) *)(full_ptr_t)(chnd).c)

/*
 * Copy an array of objects to guest context via a compat handle,
 * specifying an offset into the guest array.
 */
#define copy_to_compat_offset(hnd, off, ptr, nr) ({                  \
    const typeof(ptr) _x = (typeof(**(hnd)._) *)(full_ptr_t)(hnd).c; \
    const typeof(*(ptr)) *const _y = (ptr);                          \
    copy_to_user(_x + (off), _y, sizeof(*_x) * (nr));                \
})

/*
 * Copy an array of objects from guest context via a compat handle,
 * specifying an offset into the guest array.
 */
#define copy_from_compat_offset(ptr, hnd, off, nr) ({                \
    const typeof(ptr) _x = (typeof(**(hnd)._) *)(full_ptr_t)(hnd).c; \
    const typeof(ptr) _y = (ptr);                                    \
    copy_from_user(_y, _x + (off), sizeof(*_x) * (nr));              \
})

#define copy_to_compat(hnd, ptr, nr)                                 \
    copy_to_compat_offset(hnd, 0, ptr, nr)

#define copy_from_compat(ptr, hnd, nr)                               \
    copy_from_compat_offset(ptr, hnd, 0, nr)

/* Copy sub-field of a structure to guest context via a compat handle. */
#define copy_field_to_compat(hnd, ptr, field) ({                     \
    typeof((ptr)->field) *const _x = &((typeof(**(hnd)._) *)(full_ptr_t)(hnd).c)->field; \
    const typeof((ptr)->field) *const _y = &(ptr)->field;            \
    copy_to_user(_x, _y, sizeof(*_x));                               \
})

/* Copy sub-field of a structure from guest context via a compat handle. */
#define copy_field_from_compat(ptr, hnd, field) ({                   \
    typeof((ptr)->field) *const _x = &((typeof(**(hnd)._) *)(full_ptr_t)(hnd).c)->field; \
    typeof((ptr)->field) *const _y = &(ptr)->field;                  \
    copy_from_user(_y, _x, sizeof(*_x));                             \
})

/*
 * Pre-validate a guest handle.
 * Allows use of faster __copy_* functions.
 */
#define compat_handle_okay(hnd, nr)                                  \
    compat_array_access_ok((void *)(full_ptr_t)(hnd).c, (nr), sizeof(**(hnd)._))

#define __copy_to_compat_offset(hnd, off, ptr, nr) ({                \
    const typeof(ptr) _x = (typeof(**(hnd)._) *)(full_ptr_t)(hnd).c; \
    const typeof(*(ptr)) *const _y = (ptr);                          \
    __copy_to_user(_x + (off), _y, sizeof(*_x) * (nr));              \
})

#define __copy_from_compat_offset(ptr, hnd, off, nr) ({              \
    const typeof(ptr) _x = (typeof(**(hnd)._) *)(full_ptr_t)(hnd).c; \
    const typeof(ptr) _y = (ptr);                                    \
    __copy_from_user(_y, _x + (off), sizeof(*_x) * (nr));            \
})

#define __copy_to_compat(hnd, ptr, nr)                               \
    __copy_to_compat_offset(hnd, 0, ptr, nr)

#define __copy_from_compat(ptr, hnd, nr)                             \
    __copy_from_compat_offset(ptr, hnd, 0, nr)

#define __copy_field_to_compat(hnd, ptr, field) ({                   \
    typeof((ptr)->field) *const _x = &((typeof(**(hnd)._) *)(full_ptr_t)(hnd).c)->field; \
    const typeof((ptr)->field) *const _y = &(ptr)->field;            \
    __copy_to_user(_x, _y, sizeof(*_x));                             \
})

#define __copy_field_from_compat(ptr, hnd, field) ({                 \
    typeof((ptr)->field) *const _x = &((typeof(**(hnd)._) *)(full_ptr_t)(hnd).c)->field; \
    typeof((ptr)->field) *const _y = &(ptr)->field;                  \
    __copy_from_user(_y, _x, sizeof(*_x));                           \
})


#define CHECK_TYPE(name) \
    typedef int __checkT ## name[1 - ((xen_ ## name ## _t *)0 != \
                                   (compat_ ## name ## _t *)0) * 2]
#define CHECK_TYPE_(k, n) \
    typedef int __checkT ## k ## _ ## n[1 - ((k xen_ ## n *)0 != \
                                          (k compat_ ## n *)0) * 2]

#define CHECK_SIZE(name) \
    typedef int __checkS ## name[1 - (sizeof(xen_ ## name ## _t) != \
                                   sizeof(compat_ ## name ## _t)) * 2]
#define CHECK_SIZE_(k, n) \
    typedef int __checkS ## k ## _ ## n[1 - (sizeof(k xen_ ## n) != \
                                          sizeof(k compat_ ## n)) * 2]

#define CHECK_FIELD(t, f) \
    typedef int __checkF ## t ## __ ## f[1 - (&((xen_ ## t ## _t *)0)->f != \
                                           &((compat_ ## t ## _t *)0)->f) * 2]
#define CHECK_FIELD_(k, n, f) \
    typedef int __checkF ## k ## _ ## n ## __ ## f[1 - (&((k xen_ ## n *)0)->f != \
                                                     &((k compat_ ## n *)0)->f) * 2]

#define CHECK_SUBFIELD_1(t, f1, f2) \
    typedef int __checkF1 ## t ## __ ## f1 ## __ ## f2 \
                [1 - (&((xen_ ## t ## _t *)0)->f1.f2 != \
                   &((compat_ ## t ## _t *)0)->f1.f2) * 2]
#define CHECK_SUBFIELD_1_(k, n, f1, f2) \
    typedef int __checkF1 ## k ## _ ## n ## __ ## f1 ## __ ## f2 \
                [1 - (&((k xen_ ## n *)0)->f1.f2 != \
                   &((k compat_ ## n *)0)->f1.f2) * 2]

#define CHECK_SUBFIELD_2(t, f1, f2, f3) \
    typedef int __checkF2 ## t ## __ ## f1 ## __ ## f2 ## __ ## f3 \
                [1 - (&((xen_ ## t ## _t *)0)->f1.f2.f3 != \
                   &((compat_ ## t ## _t *)0)->f1.f2.f3) * 2]
#define CHECK_SUBFIELD_2_(k, n, f1, f2, f3) \
    typedef int __checkF2 ## k ## _ ## n ## __ ## f1 ## __ ## f2 ## __ ## f3 \
                [1 - (&((k xen_ ## n *)0)->f1.f2.f3 != \
                   &((k compat_ ## n *)0)->f1.f2.f3) * 2]

extern int compat_disabled;

int hypercall_xlat_continuation(unsigned int *id, unsigned int mask, ...);

/* In-place translation functons: */
struct start_info;
void xlat_start_info(struct start_info *, enum XLAT_start_info_console);
struct vcpu_runstate_info;
void xlat_vcpu_runstate_info(struct vcpu_runstate_info *);

int switch_compat(struct domain *);
int switch_native(struct domain *);

#define BITS_PER_GUEST_LONG(d) (!IS_COMPAT(d) ? BITS_PER_LONG : COMPAT_BITS_PER_LONG)

#else

#define compat_handle_is_null(hnd) 0

#define BITS_PER_GUEST_LONG(d) BITS_PER_LONG

#endif

#endif /* __XEN_COMPAT_H__ */
