#ifndef __XEN_STDARG_H__
#define __XEN_STDARG_H__

#if defined(__OpenBSD__)
#  include "/usr/include/stdarg.h"
#elif defined (__NetBSD__)
   typedef __builtin_va_list va_list;
#  define va_start(ap, last)    __builtin_stdarg_start((ap), (last))
#  define va_end(ap)            __builtin_va_end(ap)
#  define va_arg                __builtin_va_arg
#else
#  include <stdarg.h>
#endif

#endif /* __XEN_STDARG_H__ */
