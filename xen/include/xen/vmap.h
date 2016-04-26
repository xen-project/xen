#if !defined(__XEN_VMAP_H__) && defined(VMAP_VIRT_START)
#define __XEN_VMAP_H__

#include <xen/mm.h>
#include <asm/page.h>

enum vmap_region {
    VMAP_DEFAULT,
    VMAP_XEN,
    VMAP_REGION_NR,
};

void vm_init_type(enum vmap_region type, void *start, void *end);

void *__vmap(const mfn_t *mfn, unsigned int granularity, unsigned int nr,
             unsigned int align, unsigned int flags, enum vmap_region);
void *vmap(const mfn_t *mfn, unsigned int nr);
void vunmap(const void *);

void *vmalloc(size_t size);
void *vmalloc_xen(size_t size);

void *vzalloc(size_t size);
void vfree(void *va);

void __iomem *ioremap(paddr_t, size_t);

static inline void iounmap(void __iomem *va)
{
    unsigned long addr = (unsigned long)(void __force *)va;

    vunmap((void *)(addr & PAGE_MASK));
}

void *arch_vmap_virt_end(void);
static inline void vm_init(void)
{
    vm_init_type(VMAP_DEFAULT, (void *)VMAP_VIRT_START, arch_vmap_virt_end());
}

#endif /* __XEN_VMAP_H__ */
