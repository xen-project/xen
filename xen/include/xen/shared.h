#ifndef __XEN_SHARED_H__
#define __XEN_SHARED_H__

#include <xen/config.h>

#ifdef CONFIG_COMPAT

#include <compat/xen.h>

typedef union {
    struct shared_info native;
    struct compat_shared_info compat;
} shared_info_t;

#define __shared_info(d, s, field)      (*(!has_32bit_shinfo(d) ?       \
                                           &(s)->native.field :         \
                                           &(s)->compat.field))
#define __shared_info_addr(d, s, field) (!has_32bit_shinfo(d) ?         \
                                         (void *)&(s)->native.field :   \
                                         (void *)&(s)->compat.field)

#define shared_info(d, field)                   \
    __shared_info(d, (d)->shared_info, field)
#define shared_info_addr(d, field)                      \
    __shared_info_addr(d, (d)->shared_info, field)

typedef union {
    struct vcpu_info native;
    struct compat_vcpu_info compat;
} vcpu_info_t;

#define vcpu_info(v, field)      (*(!has_32bit_shinfo((v)->domain) ?    \
                                    &(v)->vcpu_info->native.field :     \
                                    &(v)->vcpu_info->compat.field))
#define vcpu_info_addr(v, field) (!has_32bit_shinfo((v)->domain) ?        \
                                  (void *)&(v)->vcpu_info->native.field : \
                                  (void *)&(v)->vcpu_info->compat.field)

#else

typedef struct shared_info shared_info_t;

#define __shared_info(d, s, field)      ((s)->field)
#define __shared_info_addr(d, s, field) ((void *)&(s)->field)

#define shared_info(d, field)           ((d)->shared_info->field)
#define shared_info_addr(d, field)      ((void *)&(d)->shared_info->field)

typedef struct vcpu_info vcpu_info_t;

#define vcpu_info(v, field)             ((v)->vcpu_info->field)
#define vcpu_info_addr(v, field)        ((void *)&(v)->vcpu_info->field)

#endif

#endif /* __XEN_SHARED_H__ */
