/******************************************************************************
 * compat.h
 */

#ifndef __XEN_COMPAT_H__
#define __XEN_COMPAT_H__

#ifdef CONFIG_COMPAT

#include <xen/types.h>
#include <asm/compat.h>
#include <compat/xlat.h>

#define __DEFINE_COMPAT_HANDLE(name, type) \
    typedef struct { \
        compat_ptr_t c; \
        type *_[0] __attribute__((__packed__)); \
    } __compat_handle_ ## name

#define DEFINE_COMPAT_HANDLE(name) \
    __DEFINE_COMPAT_HANDLE(name, name); \
    __DEFINE_COMPAT_HANDLE(const_ ## name, const name)
#define COMPAT_HANDLE(name)          __compat_handle_ ## name

/* NB: it is assumed that if an arch uses the compat layer it does not
 * distinguish handles from parameter handles. */
#define COMPAT_HANDLE_PARAM(name)    __compat_handle_ ## name
/* Is the compat handle a NULL reference? */
#define compat_handle_is_null(hnd)        ((hnd).c == 0)

/* Offset the given compat handle into the array it refers to. */
#define compat_handle_add_offset(hnd, nr)                            \
    ((hnd).c += (nr) * sizeof(**(hnd)._))

/* Cast a compat handle to the specified type of handle. */
#define compat_handle_cast(chnd, type) ({                            \
    type *_x = (__typeof__(**(chnd)._) *)(full_ptr_t)(chnd).c;       \
    (COMPAT_HANDLE(type)) { (full_ptr_t)_x };                        \
})

#define guest_from_compat_handle(ghnd, chnd)                         \
    set_xen_guest_handle(ghnd,                                       \
                         (__typeof__(**(chnd)._) *)(full_ptr_t)(chnd).c)

/*
 * Copy an array of objects to guest context via a compat handle,
 * specifying an offset into the guest array.
 */
#define copy_to_compat_offset(hnd, off, ptr, nr) ({                  \
    const typeof(*(ptr)) *_s = (ptr);                                \
    char (*_d)[sizeof(*_s)] = (void *)(full_ptr_t)(hnd).c;           \
    ((void)((typeof(**(hnd)._) *)(full_ptr_t)(hnd).c == (ptr)));     \
    raw_copy_to_guest(_d + (off), _s, sizeof(*_s) * (nr));           \
})

/*
 * Copy an array of objects from guest context via a compat handle,
 * specifying an offset into the guest array.
 */
#define copy_from_compat_offset(ptr, hnd, off, nr) ({                \
    const typeof(*(ptr)) *_s = (typeof(**(hnd)._) *)(full_ptr_t)(hnd).c; \
    typeof(*(ptr)) *_d = (ptr);                                      \
    raw_copy_from_guest(_d, _s + (off), sizeof(*_d) * (nr));         \
})

#define copy_to_compat(hnd, ptr, nr)                                 \
    copy_to_compat_offset(hnd, 0, ptr, nr)

#define copy_from_compat(ptr, hnd, nr)                               \
    copy_from_compat_offset(ptr, hnd, 0, nr)

/* Copy sub-field of a structure to guest context via a compat handle. */
#define copy_field_to_compat(hnd, ptr, field) ({                     \
    const typeof(&(ptr)->field) _s = &(ptr)->field;                  \
    void *_d = &((typeof(**(hnd)._) *)(full_ptr_t)(hnd).c)->field;   \
    ((void)(&((typeof(**(hnd)._) *)(full_ptr_t)(hnd).c)->field ==    \
            &(ptr)->field));                                         \
    raw_copy_to_guest(_d, _s, sizeof(*_s));                          \
})

/* Copy sub-field of a structure from guest context via a compat handle. */
#define copy_field_from_compat(ptr, hnd, field) ({                   \
    const typeof(&(ptr)->field) _s =                                 \
        &((typeof(**(hnd)._) *)(full_ptr_t)(hnd).c)->field;          \
    typeof(&(ptr)->field) _d = &(ptr)->field;                        \
    raw_copy_from_guest(_d, _s, sizeof(*_d));                        \
})

/*
 * Pre-validate a guest handle.
 * Allows use of faster __copy_* functions.
 */
#define compat_handle_okay(hnd, nr)                                  \
    (paging_mode_external(current->domain) ||                        \
    compat_array_access_ok((void *)(full_ptr_t)(hnd).c, (nr),        \
                           sizeof(**(hnd)._)))

#define __copy_to_compat_offset(hnd, off, ptr, nr) ({                \
    const typeof(*(ptr)) *_s = (ptr);                                \
    char (*_d)[sizeof(*_s)] = (void *)(full_ptr_t)(hnd).c;           \
    ((void)((typeof(**(hnd)._) *)(full_ptr_t)(hnd).c == (ptr)));     \
    __raw_copy_to_guest(_d + (off), _s, sizeof(*_s) * (nr));         \
})

#define __copy_from_compat_offset(ptr, hnd, off, nr) ({              \
    const typeof(*(ptr)) *_s = (typeof(**(hnd)._) *)(full_ptr_t)(hnd).c; \
    typeof(*(ptr)) *_d = (ptr);                                      \
    __raw_copy_from_guest(_d, _s + (off), sizeof(*_d) * (nr));       \
})

#define __copy_to_compat(hnd, ptr, nr)                               \
    __copy_to_compat_offset(hnd, 0, ptr, nr)

#define __copy_from_compat(ptr, hnd, nr)                             \
    __copy_from_compat_offset(ptr, hnd, 0, nr)

#define __copy_field_to_compat(hnd, ptr, field) ({                   \
    const typeof(&(ptr)->field) _s = &(ptr)->field;                  \
    void *_d = &((typeof(**(hnd)._) *)(full_ptr_t)(hnd).c)->field;   \
    ((void)(&((typeof(**(hnd)._) *)(full_ptr_t)(hnd).c)->field ==    \
            &(ptr)->field));                                         \
    __raw_copy_to_guest(_d, _s, sizeof(*_s));                        \
})

#define __copy_field_from_compat(ptr, hnd, field) ({                 \
    const typeof(&(ptr)->field) _s =                                 \
        &((typeof(**(hnd)._) *)(full_ptr_t)(hnd).c)->field;          \
    typeof(&(ptr)->field) _d = &(ptr)->field;                        \
    __raw_copy_from_guest(_d, _s, sizeof(*_d));                      \
})


#define CHECK_NAME(name, tag) __check ## tag ## name
#define CHECK_NAME_(k, n, tag) __check ## tag ## k ## _ ## n

#define CHECK_TYPE(name) \
static inline int CHECK_NAME(name, T)(xen_ ## name ## _t *x, \
                                      compat_ ## name ## _t *c) \
{ \
    return x == c; \
}
#define CHECK_TYPE_(k, n) \
static inline int CHECK_NAME_(k, n, T)(k xen_ ## n *x, \
                                       k compat_ ## n *c) \
{ \
    return x == c; \
}

#define CHECK_SIZE(name) \
    typedef int CHECK_NAME(name, S)[1 - (sizeof(xen_ ## name ## _t) != \
                                         sizeof(compat_ ## name ## _t)) * 2]
#define CHECK_SIZE_(k, n) \
    typedef int CHECK_NAME_(k, n, S)[1 - (sizeof(k xen_ ## n) != \
                                          sizeof(k compat_ ## n)) * 2]

#define CHECK_FIELD_COMMON(name, t, f) \
static inline int name(xen_ ## t ## _t *x, compat_ ## t ## _t *c) \
{ \
    BUILD_BUG_ON(offsetof(xen_ ## t ## _t, f) != \
                 offsetof(compat_ ## t ## _t, f)); \
    return &x->f == &c->f; \
}
#define CHECK_FIELD_COMMON_(k, name, n, f) \
static inline int name(k xen_ ## n *x, k compat_ ## n *c) \
{ \
    BUILD_BUG_ON(offsetof(k xen_ ## n, f) != \
                 offsetof(k compat_ ## n, f)); \
    return &x->f == &c->f; \
}

#define CHECK_FIELD(t, f) \
    CHECK_FIELD_COMMON(CHECK_NAME(t ## __ ## f, F), t, f)
#define CHECK_FIELD_(k, n, f) \
    CHECK_FIELD_COMMON_(k, CHECK_NAME_(k, n ## __ ## f, F), n, f)

#define CHECK_SUBFIELD_1(t, f1, f2) \
    CHECK_FIELD_COMMON(CHECK_NAME(t ## __ ## f1 ## __ ## f2, F1), t, f1.f2)
#define CHECK_SUBFIELD_1_(k, n, f1, f2) \
    CHECK_FIELD_COMMON_(k, CHECK_NAME_(k, n ## __ ## f1 ## __ ## f2, F1), \
                        n, f1.f2)

#define CHECK_SUBFIELD_2(t, f1, f2, f3) \
    CHECK_FIELD_COMMON(CHECK_NAME(t ## __ ## f1 ## __ ## f2 ## __ ## f3, F2), \
                       t, f1.f2.f3)
#define CHECK_SUBFIELD_2_(k, n, f1, f2, f3) \
    CHECK_FIELD_COMMON_(k, CHECK_NAME_(k, n ## __ ## f1 ## __ ## f2 ## __ ## \
                                       f3, F2), n, f1.f2.f3)

/*
 * Translate a native continuation into a compat guest continuation.
 *
 * id: If non-NULL then points to an integer N between 0-5. Will be updated
 * with the value of the N'th argument to the hypercall. The N'th argument must
 * not be subject to translation (i.e. cannot be referenced by @mask below).
 * This option is useful for extracting the "op" argument or similar from the
 * hypercall to enable further xlat processing.
 *
 * nr: Total number of arguments the hypercall has.
 *
 * mask: Specifies which of the hypercall arguments require compat translation.
 * bit 0 indicates that the 0'th argument requires translation, bit 1 indicates
 * that the first argument requires translation and so on. Native and compat
 * values for each translated argument are provided as @varargs (see below).
 *
 * varargs: For each bit which is set in @mask the varargs contain a native
 * value (unsigned long) and a compat value (unsigned int). If the native value
 * and compat value differ and the N'th argument is equal to the native value
 * then that argument is replaced by the compat value. If the native and compat
 * values are equal then no translation takes place. If the N'th argument does
 * not equal the native value then no translation takes place.
 *
 * Any untranslated argument (whether due to not being requested in @mask,
 * native and compat values being equal or N'th argument not equalling native
 * value) must be equal in both native and compat representations (i.e. the
 * native version cannot have any bits > 32 set)
 *
 * Return: Number of arguments which were actually translated.
 */
int hypercall_xlat_continuation(unsigned int *id, unsigned int nr,
                                unsigned int mask, ...);

/* In-place translation functons: */
struct start_info;
void xlat_start_info(struct start_info *, enum XLAT_start_info_console);
struct vcpu_runstate_info;
void xlat_vcpu_runstate_info(struct vcpu_runstate_info *);

int switch_compat(struct domain *);
int switch_native(struct domain *);

#else

#define compat_handle_is_null(hnd) 0

#endif

#endif /* __XEN_COMPAT_H__ */
