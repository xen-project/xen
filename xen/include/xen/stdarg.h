#ifndef __XEN_STDARG_H__
#define __XEN_STDARG_H__

#if defined(__OpenBSD__) || defined (__NetBSD__)
   typedef __builtin_va_list va_list;
#  ifdef __GNUC__
#    define __GNUC_PREREQ__(x, y)                                       \
        ((__GNUC__ == (x) && __GNUC_MINOR__ >= (y)) ||                  \
         (__GNUC__ > (x)))
#  else
#    define __GNUC_PREREQ__(x, y)   0
#  endif
#  if !__GNUC_PREREQ__(4, 5)
#    define __builtin_va_start(ap, last)    __builtin_stdarg_start((ap), (last))
#  endif
#  define va_start(ap, last)    __builtin_va_start((ap), (last))
#  define va_end(ap)            __builtin_va_end(ap)
#  define va_arg                __builtin_va_arg
#else
#  include <stdarg.h>
#endif

#endif /* __XEN_STDARG_H__ */
