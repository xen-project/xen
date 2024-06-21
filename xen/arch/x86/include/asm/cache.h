/*
 * include/asm-x86/cache.h
 */
#ifndef __ARCH_X86_CACHE_H
#define __ARCH_X86_CACHE_H


/* L1 cache line size */
#define L1_CACHE_SHIFT	(CONFIG_X86_L1_CACHE_SHIFT)
#define L1_CACHE_BYTES	(1 << L1_CACHE_SHIFT)

#ifndef __ASSEMBLY__

void cache_flush(const void *addr, unsigned int size);
void cache_writeback(const void *addr, unsigned int size);

#endif

#endif
