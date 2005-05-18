#ifndef __ASM_MMU_CONTEXT_H
#define __ASM_MMU_CONTEXT_H
//dummy file to resolve non-arch-indep include
#ifdef XEN
#ifndef CONFIG_VTI
#define IA64_REGION_ID_KERNEL 0
#else // CONFIG_VTI
#define IA64_REGION_ID_KERNEL 0x1e0000	/* Start from all 1 in highest 4 bits */
#endif // CONFIG_VTI
#define ia64_rid(ctx,addr)	(((ctx) << 3) | (addr >> 61))

#ifndef __ASSEMBLY__
struct ia64_ctx {
	spinlock_t lock;
	unsigned int next;	/* next context number to use */
	unsigned int limit;	/* next >= limit => must call wrap_mmu_context() */
	unsigned int max_ctx;	/* max. context value supported by all CPUs */
};

extern struct ia64_ctx ia64_ctx;
#endif /* ! __ASSEMBLY__ */
#endif
#endif /* ! __ASM_MMU_CONTEXT_H */
