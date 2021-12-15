/******************************************************************************
 * compat.h
 */

#ifdef CONFIG_COMPAT

#define COMPAT_BITS_PER_LONG 32

typedef uint32_t compat_ptr_t;
typedef unsigned long full_ptr_t;

#endif

struct domain;
#ifdef CONFIG_PV32
int switch_compat(struct domain *);
#else
#include <xen/errno.h>
static inline int switch_compat(struct domain *d) { return -EOPNOTSUPP; }
#endif
