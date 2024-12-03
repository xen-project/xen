/*
 * Interface to map physical memory onto contiguous virtual memory areas.
 *
 * Two ranges of linear address space are reserved for this purpose: A general
 * purpose area (VMAP_DEFAULT) and a livepatch-specific area (VMAP_XEN). The
 * latter is used when loading livepatches and the former for everything else.
 */
#ifndef __XEN_VMAP_H__
#define __XEN_VMAP_H__

#include <xen/mm-frame.h>
#include <xen/page-size.h>

/* Identifiers for the linear ranges tracked by vmap */
enum vmap_region {
    /*
     * Region used for general purpose RW mappings. Mapping/allocating memory
     * here can induce extra allocations for the supporting page tables.
     */
    VMAP_DEFAULT,
    /*
     * Region used for loading livepatches. Can't use VMAP_DEFAULT because it
     * must live close to the running Xen image. The caller also ensures all
     * page tables are already in place with adequate PTE flags.
     */
    VMAP_XEN,
    /* Sentinel value for bounds checking */
    VMAP_REGION_NR,
};

/*
 * Runtime initialiser for each vmap region type
 *
 * Must only be called once per vmap region type.
 *
 * @param type  Designation of the region to initialise.
 * @param start Start address of the `type` region.
 * @param end   End address (not inclusive) of the `type` region
 */
void vm_init_type(enum vmap_region type, void *start, void *end);

/*
 * Maps a set of physical ranges onto a single virtual range
 *
 * `mfn` is an array of `nr` physical ranges, each of which is `granularity`
 * pages wide. `type` defines which vmap region to use for the mapping and
 * `flags` is the PTE flags the page table leaves are meant to have.
 *
 * Typically used via the vmap() and vmap_contig() helpers.
 *
 * @param mfn          Array of mfns
 * @param granularity  Number of contiguous pages each mfn represents
 * @param nr           Number of mfns in the `mfn` array
 * @param align        Alignment of the virtual area to map
 * @param flags        PTE flags for the leaves of the PT tree.
 * @param type         Which region to create the mappings on
 * @return Pointer to the mapped area on success; NULL otherwise.
 */
void *__vmap(const mfn_t *mfn, unsigned int granularity, unsigned int nr,
             unsigned int align, unsigned int flags, enum vmap_region type);

/*
 * Map an array of pages contiguously into the VMAP_DEFAULT vmap region
 *
 * @param[in] mfn Pointer to the base of an array of mfns
 * @param[in] nr  Number of mfns in the array
 * @return Pointer to the mapped area on success; NULL otherwise.
 */
void *vmap(const mfn_t *mfn, unsigned int nr);

/*
 * Maps physically contiguous pages onto the VMAP_DEFAULT vmap region
 *
 * @param mfn Base mfn of the physical region
 * @param nr  Number of mfns in the physical region
 * @return Pointer to the mapped area on success; NULL otherwise.
 */
void *vmap_contig(mfn_t mfn, unsigned int nr);

/*
 * Unmaps a range of virtually contiguous memory from one of the vmap regions
 *
 * The system remembers internally how wide the mapping is and unmaps it all.
 * It also can determine the vmap region type from the `va`.
 *
 * @param va Virtual base address of the range to unmap
 */
void vunmap(const void *va);

/*
 * Allocate `size` octets of possibly non-contiguous physical memory and map
 * them contiguously in the VMAP_DEFAULT vmap region
 *
 * @param size Pointer to the base of an array of mfns
 * @return Pointer to the mapped area on success; NULL otherwise.
 */
void *vmalloc(size_t size);

/* Same as vmalloc(), but for the VMAP_XEN vmap region. */
void *vmalloc_xen(size_t size);

/* Same as vmalloc(), but set the contents to zero before returning */
void *vzalloc(size_t size);

/*
 * Unmap and free memory from vmalloc(), vmalloc_xen() or vzalloc()
 *
 * The system remembers internally how wide the allocation is and
 * unmaps/frees it all.
 *
 * @param va Virtual base address of the range to free and unmap
 */
void vfree(void *va);

/*
 * Analogous to vmap_contig(), but for IO memory
 *
 * Unlike vmap_contig(), it ensures architecturally correct cacheability
 * settings are set for the mapped IO memory.
 *
 * @param pa  Physical base address of the MMIO region.
 * @param len Length of the MMIO region in octets.
 * @return Pointer to the mapped area on success; NULL otherwise.
 */
void __iomem *ioremap(paddr_t pa, size_t len);

/* Return the number of pages in the mapping starting at address 'va' */
unsigned int vmap_size(const void *va);

/* Analogous to vunmap(), but for IO memory mapped via ioremap() */
static inline void iounmap(void __iomem *va)
{
    unsigned long addr = (unsigned long)(void __force *)va;

    vunmap((void *)(addr & PAGE_MASK));
}

/* Pointer to 1 octet past the end of the VMAP_DEFAULT virtual area */
void *arch_vmap_virt_end(void);

/* Initialises the VMAP_DEFAULT virtual range */
static inline void vm_init(void)
{
#ifdef CONFIG_HAS_VMAP
    vm_init_type(VMAP_DEFAULT, (void *)VMAP_VIRT_START, arch_vmap_virt_end());
#endif
}

#endif /* __XEN_VMAP_H__ */
