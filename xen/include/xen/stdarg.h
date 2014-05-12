#ifndef __XEN_STDARG_H__
#define __XEN_STDARG_H__

typedef __builtin_va_list va_list;
#define va_copy(dest, src)    __builtin_va_copy((dest), (src))
#define va_start(ap, last)    __builtin_va_start((ap), (last))
#define va_end(ap)            __builtin_va_end(ap)
#define va_arg                __builtin_va_arg

#endif /* __XEN_STDARG_H__ */
