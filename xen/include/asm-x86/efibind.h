#include <xen/types.h>
#if defined(__i386__)
# include <asm/x86_32/efibind.h>
#elif defined(__x86_64__)
# include <asm/x86_64/efibind.h>
#endif
