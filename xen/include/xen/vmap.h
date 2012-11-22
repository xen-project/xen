#if !defined(__XEN_VMAP_H__) && defined(VMAP_VIRT_START)
#define __XEN_VMAP_H__

#include <xen/types.h>

void *vm_alloc(unsigned int nr, unsigned int align);
void vm_free(const void *);

void *__vmap(const unsigned long *mfn, unsigned int granularity,
             unsigned int nr, unsigned int align, unsigned int flags);
void *vmap(const unsigned long *mfn, unsigned int nr);
void vunmap(const void *);

void __iomem *ioremap(paddr_t, size_t);

static inline void iounmap(void __iomem *va)
{
    vunmap((void __force *)va);
}

void vm_init(void);
void *arch_vmap_virt_end(void);

#endif /* __XEN_VMAP_H__ */
