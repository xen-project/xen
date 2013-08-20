#ifndef __XEN_STDBOOL_H__
#define __XEN_STDBOOL_H__

#if defined(__OpenBSD__) || defined(__NetBSD__)
#  define bool _Bool
#  define true 1
#  define false 0
#  define __bool_true_false_are_defined   1
#else
#  include <stdbool.h>
#endif

#endif /* __XEN_STDBOOL_H__ */
