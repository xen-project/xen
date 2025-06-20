#ifndef __XEN_PDX_H__
#define __XEN_PDX_H__

/*
 * PDX (Page inDeX)
 *
 * This file deals with optimisations pertaining to frame table and
 * directmap indexing, A pdx is an index into the frame table, which
 * typically also means an index into the directmap[1]. However, having an
 * identity relationship between mfn and pdx could waste copious amounts of
 * memory in empty frame table entries and page tables. There are some
 * techniques to bring memory wastage down.
 *
 * [1] Some ports apply further modifications to a pdx before indexing the
 *     directmap. This doesn't change the fact that the same compression
 *     present in the frame table is also present in the directmap
 *     whenever said map is present.
 *
 * ## PDX grouping
 *
 * The frame table may have some sparsity even on systems where the memory
 * banks are tightly packed. This is due to system quirks (like the PCI
 * hole) which might introduce several GiB of unused page frame numbers
 * that uselessly waste memory in the frame table. PDX grouping addresses
 * this by keeping a bitmap of the ranges in the frame table containing
 * invalid entries and not allocating backing memory for them.
 *
 * ## PDX mask compression
 *
 * This is a technique to avoid wasting memory on machines known to have
 * split their machine address space in several big discontinuous and highly
 * disjoint chunks.
 *
 * In its uncompressed form the frame table must have book-keeping metadata
 * structures for every page between [0, max_mfn) (whether they are backed
 * by RAM or not), and a similar condition exists for the direct map. We
 * know some systems, however, that have some sparsity in their address
 * space, leading to a lot of wastage in the form of unused frame table
 * entries.
 *
 * This is where compression becomes useful. The idea is to note that if
 * you have several big chunks of memory sufficiently far apart you can
 * ignore the middle part of the address because it will always contain
 * zeroes.
 *
 * i.e:
 *   Consider 2 regions of memory. One starts at 0 while the other starts
 *   at offset 2^off_h. Furthermore, let's assume both regions are smaller
 *   than 2^off_l. This means that all addresses between [2^off_l, 2^off_h)
 *   are invalid and we can assume them to be zero on all valid addresses.
 *
 *                 off_h     off_l
 *                 |         |
 *                 V         V
 *         --------------------------
 *         |HHHHHHH|000000000|LLLLLL| <--- mfn
 *         --------------------------
 *           ^ |
 *           | | (de)compression by adding/removing "useless" zeroes
 *           | V
 *         ---------------
 *         |HHHHHHHLLLLLL| <--- pdx
 *         ---------------
 *
 * This scheme also holds for multiple regions, where HHHHHHH acts as
 * the region identifier and LLLLLL fully contains the span of every
 * region involved.
 */

extern unsigned long max_pdx;

#define PDX_GROUP_COUNT ((1 << PDX_GROUP_SHIFT) / \
                         (ISOLATE_LSB(sizeof(*frame_table))))
extern unsigned long pdx_group_valid[];

/**
 * Mark [smfn, emfn) as allocatable in the frame table
 *
 * @param smfn Start mfn
 * @param emfn End mfn
 */
void set_pdx_range(unsigned long smfn, unsigned long emfn);

/**
 * Invoked to determine if an mfn has an associated valid frame table entry
 *
 * In order for it to be legal it must pass bounds, grouping and
 * compression sanity checks.
 *
 * @param mfn To-be-checked mfn
 * @return True iff all checks pass
 */
bool __mfn_valid(unsigned long mfn);

#define page_to_pdx(pg)  ((pg) - frame_table)
#define pdx_to_page(pdx) gcc11_wrap(frame_table + (pdx))

#define mfn_to_pdx(mfn) pfn_to_pdx(mfn_x(mfn))
#define pdx_to_mfn(pdx) _mfn(pdx_to_pfn(pdx))

#define paddr_to_pdx(pa) pfn_to_pdx(paddr_to_pfn(pa))
#define pdx_to_paddr(px) pfn_to_paddr(pdx_to_pfn(px))

#ifdef CONFIG_PDX_MASK_COMPRESSION

extern unsigned long pfn_pdx_bottom_mask, ma_va_bottom_mask;
extern unsigned int pfn_pdx_hole_shift;
extern unsigned long pfn_hole_mask;
extern unsigned long pfn_top_mask, ma_top_mask;

/**
 * Map pfn to its corresponding pdx
 *
 * @param pfn Frame number
 * @return Obtained pdx after compressing the pfn
 */
static inline unsigned long pfn_to_pdx_xlate(unsigned long pfn)
{
    return (pfn & pfn_pdx_bottom_mask) |
           ((pfn & pfn_top_mask) >> pfn_pdx_hole_shift);
}

/**
 * Map a pdx to its corresponding pfn
 *
 * @param pdx Page index
 * @return Obtained pfn after decompressing the pdx
 */
static inline unsigned long pdx_to_pfn_xlate(unsigned long pdx)
{
    return (pdx & pfn_pdx_bottom_mask) |
           ((pdx << pfn_pdx_hole_shift) & pfn_top_mask);
}

/**
 * Computes the offset into the direct map of an maddr
 *
 * @param ma Machine address
 * @return Offset on the direct map where that
 *         machine address can be accessed
 */
static inline unsigned long maddr_to_directmapoff_xlate(paddr_t ma)
{
    return (((ma & ma_top_mask) >> pfn_pdx_hole_shift) |
            (ma & ma_va_bottom_mask));
}

/**
 * Computes a machine address given a direct map offset
 *
 * @param offset Offset into the direct map
 * @return Corresponding machine address of that virtual location
 */
static inline paddr_t directmapoff_to_maddr_xlate(unsigned long offset)
{
    return ((((paddr_t)offset << pfn_pdx_hole_shift) & ma_top_mask) |
            (offset & ma_va_bottom_mask));
}

#endif /* CONFIG_PDX_MASK_COMPRESSION */

#ifdef CONFIG_PDX_NONE

/* Without PDX compression we can skip some computations */

/* pdx<->pfn == identity */
#define pdx_to_pfn(x) (x)
#define pfn_to_pdx(x) (x)

/* directmap is indexed by by maddr */
#define maddr_to_directmapoff(x) (x)
#define directmapoff_to_maddr(x) (x)

static inline bool pdx_is_region_compressible(paddr_t base,
                                              unsigned long npages)
{
    return true;
}

static inline void pfn_pdx_add_region(paddr_t base, paddr_t size)
{
}

static inline bool pfn_pdx_compression_setup(paddr_t base)
{
    return false;
}

static inline void pfn_pdx_compression_reset(void)
{
}

#else /* !CONFIG_PDX_NONE */

/*
 * Allow each architecture to define its (possibly optimized) versions of the
 * translation functions.
 *
 * Do not use _xlate suffixed functions, always use the non _xlate variants.
 */
#if __has_include(<asm/pdx.h>)
# include <asm/pdx.h>
#else
# define pdx_to_pfn pdx_to_pfn_xlate
# define pfn_to_pdx pfn_to_pdx_xlate
# define maddr_to_directmapoff maddr_to_directmapoff_xlate
# define directmapoff_to_maddr directmapoff_to_maddr_xlate
#endif

/* Shared functions implemented by all PDX compressions. */

/**
 * Validate a region's compatibility with the current compression runtime
 *
 * @param base Base address of the region
 * @param npages Number of PAGE_SIZE-sized pages in the region
 * @return True iff the region can be used with the current compression
 */
bool pdx_is_region_compressible(paddr_t base, unsigned long npages);

/**
 * Register a RAM region with the PFN compression logic.
 *
 * @param base Start of the region in bytes.
 * @param size Length of the region in bytes.
 */
void pfn_pdx_add_region(paddr_t base, paddr_t size);

/**
 * Initializes global variables with information about the compressible
 * range of the current memory regions.
 *
 * @param base address to start compression from.
 * @return True if PDX compression has been enabled.
 */
bool pfn_pdx_compression_setup(paddr_t base);

/**
 * Reset the global variables to it's default values, thus disabling PFN
 * compression.
 */
void pfn_pdx_compression_reset(void);

#endif /* !CONFIG_PDX_NONE */
#endif /* __XEN_PDX_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
