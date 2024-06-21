#ifndef __LINUX_CACHE_H
#define __LINUX_CACHE_H

#include <asm/cache.h>

#ifndef L1_CACHE_ALIGN
#define L1_CACHE_ALIGN(x) (((x)+(L1_CACHE_BYTES-1))&~(L1_CACHE_BYTES-1))
#endif

#ifndef SMP_CACHE_BYTES
#define SMP_CACHE_BYTES L1_CACHE_BYTES
#endif

#ifndef __cacheline_aligned
#define __cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#endif

#if defined(CONFIG_ARM) || defined(CONFIG_X86) || defined(CONFIG_PPC64)
/* TODO: Phase out the use of this via cache.h */
#define __ro_after_init __section(".data.ro_after_init")
#endif

#endif /* __LINUX_CACHE_H */
