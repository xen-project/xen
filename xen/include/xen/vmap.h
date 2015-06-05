#if !defined(__XEN_VMAP_H__) && defined(VMAP_VIRT_START)
#define __XEN_VMAP_H__

#include <xen/mm.h>
#include <asm/page.h>

void *vm_alloc(unsigned int nr, unsigned int align);
void vm_free(const void *);

void *__vmap(const mfn_t *mfn, unsigned int granularity,
             unsigned int nr, unsigned int align, unsigned int flags);
void *vmap(const mfn_t *mfn, unsigned int nr);
void vunmap(const void *);
void *vmalloc(size_t size);
void *vzalloc(size_t size);
void vfree(void *va);

void __iomem *ioremap(paddr_t, size_t);

static inline void iounmap(void __iomem *va)
{
    unsigned long addr = (unsigned long)(void __force *)va;

    vunmap((void *)(addr & PAGE_MASK));
}

void vm_init(void);
void *arch_vmap_virt_end(void);

#endif /* __XEN_VMAP_H__ */
