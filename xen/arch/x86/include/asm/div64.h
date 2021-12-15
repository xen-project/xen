#ifndef __X86_DIV64
#define __X86_DIV64

#include <xen/types.h>

#define do_div(n,base) ({                       \
    uint32_t __base = (base);                   \
    uint32_t __rem;                             \
    __rem = ((uint64_t)(n)) % __base;           \
    (n) = ((uint64_t)(n)) / __base;             \
    __rem;                                      \
})

#endif
