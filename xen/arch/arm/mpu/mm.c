/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sizes.h>
#include <xen/spinlock.h>
#include <xen/types.h>
#include <asm/mpu.h>
#include <asm/mpu/mm.h>
#include <asm/page.h>
#include <asm/sysregs.h>

struct page_info *frame_table;

/* Maximum number of supported MPU memory regions by the EL2 MPU. */
uint8_t __ro_after_init max_mpu_regions;

/*
 * Bitmap xen_mpumap_mask is to record the usage of EL2 MPU memory regions.
 * Bit 0 represents MPU memory region 0, bit 1 represents MPU memory
 * region 1, ..., and so on.
 * If a MPU memory region gets enabled, set the according bit to 1.
 */
DECLARE_BITMAP(xen_mpumap_mask, MAX_MPU_REGION_NR) \
    __cacheline_aligned __section(".data");

/* EL2 Xen MPU memory region mapping table. */
pr_t __cacheline_aligned __section(".data") xen_mpumap[MAX_MPU_REGION_NR];

static DEFINE_SPINLOCK(xen_mpumap_lock);

static void __init __maybe_unused build_assertions(void)
{
    /*
     * Unlike MMU, MPU does not use pages for translation. However, we continue
     * to use PAGE_SIZE to denote 4KB. This is so that the existing memory
     * management based on pages, continue to work for now.
     */
    BUILD_BUG_ON(PAGE_SIZE != SZ_4K);
}

pr_t pr_of_addr(paddr_t base, paddr_t limit, unsigned int flags)
{
    unsigned int attr_idx = PAGE_AI_MASK(flags);
    prbar_t prbar;
    prlar_t prlar;
    pr_t region;

    /* Build up value for PRBAR_EL2. */
    prbar = (prbar_t) {
        .reg = {
#ifdef CONFIG_ARM_64
            .xn_0 = 0,
#endif
            .xn = PAGE_XN_MASK(flags),
            .ap_0 = 0,
            .ro = PAGE_RO_MASK(flags)
        }};

    switch ( attr_idx )
    {
    /*
     * ARM ARM: Shareable, Inner Shareable, and Outer Shareable Normal memory
     * (DDI 0487L.a B2.10.1.1.1 Note section):
     *
     * Because all data accesses to Non-cacheable locations are data coherent
     * to all observers, Non-cacheable locations are always treated as Outer
     * Shareable
     *
     * ARM ARM: Device memory (DDI 0487L.a B2.10.2)
     *
     * All of these memory types have the following properties:
     * [...]
     *  - Data accesses to memory locations are coherent for all observers in
     *    the system, and correspondingly are treated as being Outer Shareable
     */
    case MT_NORMAL_NC:
        /* Fall through */
    case MT_DEVICE_nGnRnE:
        /* Fall through */
    case MT_DEVICE_nGnRE:
        prbar.reg.sh = LPAE_SH_OUTER;
        break;
    default:
        /* Xen mappings are SMP coherent */
        prbar.reg.sh = LPAE_SH_INNER;
        break;
    }

    /* Build up value for PRLAR_EL2. */
    prlar = (prlar_t) {
        .reg = {
#ifdef CONFIG_ARM_64
            .ns = 0,        /* Hyp mode is in secure world */
#endif
            .ai = attr_idx,
            .en = 1,        /* Region enabled */
        }};

    /* Build up MPU memory region. */
    region = (pr_t) {
        .prbar = prbar,
        .prlar = prlar,
    };

    /* Set base address and limit address. */
    pr_set_base(&region, base);
    pr_set_limit(&region, limit);

    return region;
}

int mpumap_contains_region(pr_t *table, uint8_t nr_regions, paddr_t base,
                           paddr_t limit, uint8_t *index)
{
    ASSERT(index);
    *index = INVALID_REGION_IDX;

    /*
     * The caller supplies a half-open interval [base, limit), i.e. limit is the
     * first byte *after* the region. Require limit strictly greater than base,
     * which is necessarily a non-empty region.
     */
    ASSERT(base < limit);

    /*
     * Internally we use inclusive bounds, so convert range to [base, limit-1].
     * The prior assertion guarantees the subtraction will not underflow.
     */
    limit = limit - 1;

    for ( uint8_t i = 0; i < nr_regions; i++ )
    {
        paddr_t iter_base = pr_get_base(&table[i]);
        paddr_t iter_limit = pr_get_limit(&table[i]);

        /* Skip invalid (disabled) regions */
        if ( !region_is_valid(&table[i]) )
            continue;

        /* No match */
        if ( (iter_limit < base) || (iter_base > limit) )
            continue;

        /* Exact match */
        if ( (iter_base == base) && (iter_limit == limit) )
        {
            *index = i;
            return MPUMAP_REGION_FOUND;
        }

        /* Inclusive match */
        if ( (base >= iter_base) && (limit <= iter_limit) )
        {
            *index = i;
            return MPUMAP_REGION_INCLUSIVE;
        }

        /* Overlap */
        printk("Range %#"PRIpaddr" - %#"PRIpaddr" overlaps with the existing region %#"PRIpaddr" - %#"PRIpaddr"\n",
               base, limit + 1, iter_base, iter_limit + 1);
        return MPUMAP_REGION_OVERLAP;
    }

    return MPUMAP_REGION_NOTFOUND;
}

/*
 * Allocate an entry for a new EL2 MPU region in the bitmap xen_mpumap_mask.
 * @param idx   Set to the index of the allocated EL2 MPU region on success.
 * @return      0 on success, otherwise -ENOENT on failure.
 */
static int xen_mpumap_alloc_entry(uint8_t *idx)
{
    ASSERT(spin_is_locked(&xen_mpumap_lock));

    *idx = find_first_zero_bit(xen_mpumap_mask, max_mpu_regions);
    if ( *idx == max_mpu_regions )
    {
        printk(XENLOG_ERR "EL2 MPU memory region mapping pool exhausted\n");
        return -ENOENT;
    }

    set_bit(*idx, xen_mpumap_mask);

    return 0;
}

/*
 * Disable and remove an MPU region from the data structure and MPU registers.
 *
 * @param index Index of the MPU region to be disabled.
 */
static void disable_mpu_region_from_index(uint8_t index)
{
    ASSERT(spin_is_locked(&xen_mpumap_lock));
    ASSERT(index != INVALID_REGION_IDX);

    if ( !region_is_valid(&xen_mpumap[index]) )
    {
        printk(XENLOG_WARNING
               "MPU memory region[%u] is already disabled\n", index);
        return;
    }

    /* Zeroing the region will also zero the region enable */
    memset(&xen_mpumap[index], 0, sizeof(pr_t));
    clear_bit(index, xen_mpumap_mask);

    /*
     * Both Armv8-R AArch64 and AArch32 have direct access to the enable bit for
     * MPU regions numbered from 0 to 31.
     */
    if ( (index & PRENR_MASK) != 0 )
    {
        /* Clear respective bit */
        register_t val = READ_SYSREG(PRENR_EL2) & (~(1UL << index));

        WRITE_SYSREG(val, PRENR_EL2);
    }
    else
        write_protection_region(&xen_mpumap[index], index);
}

/*
 * Update the entry in the MPU memory region mapping table (xen_mpumap) for the
 * given memory range and flags, creating one if none exists.
 *
 * @param base  Base address (inclusive).
 * @param limit Limit address (exclusive).
 * @param flags Region attributes (a combination of PAGE_HYPERVISOR_XXX)
 * @return      0 on success, otherwise negative on error.
 */
static int xen_mpumap_update_entry(paddr_t base, paddr_t limit,
                                   unsigned int flags)
{
    bool flags_has_page_present;
    uint8_t idx;
    int rc;

    ASSERT(spin_is_locked(&xen_mpumap_lock));

    rc = mpumap_contains_region(xen_mpumap, max_mpu_regions, base, limit, &idx);
    if ( rc < 0 )
        return -EINVAL;

    flags_has_page_present = flags & _PAGE_PRESENT;

    /* Currently we don't support modifying an existing entry. */
    if ( flags_has_page_present && (rc >= MPUMAP_REGION_FOUND) )
    {
        printk("Modifying an existing entry is not supported\n");
        return -EINVAL;
    }

    /*
     * Currently, we only support removing/modifying a *WHOLE* MPU memory
     * region. Part-region removal/modification is not supported as in the worst
     * case it will leave two/three fragments behind.
     */
    if ( rc == MPUMAP_REGION_INCLUSIVE )
    {
        printk("Part-region removal/modification is not supported\n");
        return -EINVAL;
    }

    /* We are inserting a mapping => Create new region. */
    if ( flags_has_page_present && (MPUMAP_REGION_NOTFOUND == rc) )
    {
        rc = xen_mpumap_alloc_entry(&idx);
        if ( rc )
            return -ENOENT;

        xen_mpumap[idx] = pr_of_addr(base, limit, flags);

        write_protection_region(&xen_mpumap[idx], idx);
    }

    /* Removing a mapping */
    if ( !flags_has_page_present )
    {
        if ( rc == MPUMAP_REGION_NOTFOUND )
        {
            printk("Cannot remove an entry that does not exist\n");
            return -EINVAL;
        }

        disable_mpu_region_from_index(idx);
    }

    return 0;
}

int xen_mpumap_update(paddr_t base, paddr_t limit, unsigned int flags)
{
    int rc;

    if ( flags_has_rwx(flags) )
    {
        printk("Mappings should not be both Writeable and Executable\n");
        return -EINVAL;
    }

    if ( base >= limit )
    {
        printk("Base address %#"PRIpaddr" must be smaller than limit address %#"PRIpaddr"\n",
               base, limit);
        return -EINVAL;
    }

    if ( !IS_ALIGNED(base, PAGE_SIZE) || !IS_ALIGNED(limit, PAGE_SIZE) )
    {
        printk("base address %#"PRIpaddr", or limit address %#"PRIpaddr" is not page aligned\n",
               base, limit);
        return -EINVAL;
    }

    spin_lock(&xen_mpumap_lock);

    rc = xen_mpumap_update_entry(base, limit, flags);
    if ( !rc )
        context_sync_mpu();

    spin_unlock(&xen_mpumap_lock);

    return rc;
}

int destroy_xen_mappings(unsigned long s, unsigned long e)
{
    ASSERT(IS_ALIGNED(s, PAGE_SIZE));
    ASSERT(IS_ALIGNED(e, PAGE_SIZE));
    ASSERT(s < e);

    return xen_mpumap_update(s, e, 0);
}

int map_pages_to_xen(unsigned long virt, mfn_t mfn, unsigned long nr_mfns,
                     unsigned int flags)
{
    /* MPU systems have no translation, ma == va, so pass virt directly */
    return xen_mpumap_update(virt, mfn_to_maddr(mfn_add(mfn, nr_mfns)), flags);
}

void __init setup_mm(void)
{
    BUG_ON("unimplemented");
}

int modify_xen_mappings(unsigned long s, unsigned long e, unsigned int nf)
{
    BUG_ON("unimplemented");
    return -EINVAL;
}

void dump_hyp_walk(vaddr_t addr)
{
    BUG_ON("unimplemented");
}

/* Release all __init and __initdata ranges to be reused */
void free_init_memory(void)
{
    BUG_ON("unimplemented");
}

void __iomem *ioremap_attr(paddr_t start, size_t len, unsigned int flags)
{
    BUG_ON("unimplemented");
    return NULL;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
