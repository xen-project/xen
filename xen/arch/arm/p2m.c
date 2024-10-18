/* SPDX-License-Identifier: GPL-2.0-only */
#include <xen/iocap.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/softirq.h>

#include <asm/event.h>
#include <asm/flushtlb.h>
#include <asm/guest_walk.h>
#include <asm/mem_access.h>
#include <asm/page.h>
#include <asm/traps.h>

#ifdef CONFIG_ARM_64
unsigned int __read_mostly max_vmid = MAX_VMID_8_BIT;
#endif

/*
 * Set to the maximum configured support for IPA bits, so the number of IPA bits can be
 * restricted by external entity (e.g. IOMMU).
 */
unsigned int __read_mostly p2m_ipa_bits = PADDR_BITS;

/* Unlock the flush and do a P2M TLB flush if necessary */
void p2m_write_unlock(struct p2m_domain *p2m)
{
    /*
     * The final flush is done with the P2M write lock taken to avoid
     * someone else modifying the P2M wbefore the TLB invalidation has
     * completed.
     */
    p2m_tlb_flush_sync(p2m);

    write_unlock(&p2m->lock);
}

void memory_type_changed(struct domain *d)
{
}

mfn_t p2m_lookup(struct domain *d, gfn_t gfn, p2m_type_t *t)
{
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    p2m_read_lock(p2m);
    mfn = p2m_get_entry(p2m, gfn, t, NULL, NULL, NULL);
    p2m_read_unlock(p2m);

    return mfn;
}

struct page_info *p2m_get_page_from_gfn(struct domain *d, gfn_t gfn,
                                        p2m_type_t *t)
{
    struct page_info *page;
    p2m_type_t p2mt;
    mfn_t mfn = p2m_lookup(d, gfn, &p2mt);

    if ( t )
        *t = p2mt;

    if ( !p2m_is_any_ram(p2mt) )
        return NULL;

    if ( !mfn_valid(mfn) )
        return NULL;

    page = mfn_to_page(mfn);

    /*
     * get_page won't work on foreign mapping because the page doesn't
     * belong to the current domain.
     */
    if ( p2m_is_foreign(p2mt) )
    {
        struct domain *fdom = page_get_owner_and_reference(page);
        ASSERT(fdom != NULL);
        ASSERT(fdom != d);
        return page;
    }

    return get_page(page, d) ? page : NULL;
}

int guest_physmap_mark_populate_on_demand(struct domain *d,
                                          unsigned long gfn,
                                          unsigned int order)
{
    return -ENOSYS;
}

unsigned long p2m_pod_decrease_reservation(struct domain *d, gfn_t gfn,
                                           unsigned int order)
{
    return 0;
}

int p2m_insert_mapping(struct domain *d, gfn_t start_gfn, unsigned long nr,
                       mfn_t mfn, p2m_type_t t)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int rc;

    p2m_write_lock(p2m);
    rc = p2m_set_entry(p2m, start_gfn, nr, mfn, t, p2m->default_access);
    p2m_write_unlock(p2m);

    return rc;
}

static inline int p2m_remove_mapping(struct domain *d,
                                     gfn_t start_gfn,
                                     unsigned long nr,
                                     mfn_t mfn)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    unsigned long i;
    int rc;

    p2m_write_lock(p2m);
    /*
     * Before removing the GFN - MFN mapping for any RAM pages make sure
     * that there is no difference between what is already mapped and what
     * is requested to be unmapped.
     * If they don't match bail out early. For instance, this could happen
     * if two CPUs are requesting to unmap the same P2M entry concurrently.
     */
    for ( i = 0; i < nr; )
    {
        unsigned int cur_order;
        p2m_type_t t;
        mfn_t mfn_return = p2m_get_entry(p2m, gfn_add(start_gfn, i), &t, NULL,
                                         &cur_order, NULL);

        if ( p2m_is_any_ram(t) &&
             (!mfn_valid(mfn) || !mfn_eq(mfn_add(mfn, i), mfn_return)) )
        {
            rc = -EILSEQ;
            goto out;
        }

        i += (1UL << cur_order) -
             ((gfn_x(start_gfn) + i) & ((1UL << cur_order) - 1));
    }

    rc = p2m_set_entry(p2m, start_gfn, nr, INVALID_MFN,
                       p2m_invalid, p2m_access_rwx);

out:
    p2m_write_unlock(p2m);

    return rc;
}

int map_regions_p2mt(struct domain *d,
                     gfn_t gfn,
                     unsigned long nr,
                     mfn_t mfn,
                     p2m_type_t p2mt)
{
    return p2m_insert_mapping(d, gfn, nr, mfn, p2mt);
}

int unmap_regions_p2mt(struct domain *d,
                       gfn_t gfn,
                       unsigned long nr,
                       mfn_t mfn)
{
    return p2m_remove_mapping(d, gfn, nr, mfn);
}

int map_mmio_regions(struct domain *d,
                     gfn_t start_gfn,
                     unsigned long nr,
                     mfn_t mfn)
{
    return p2m_insert_mapping(d, start_gfn, nr, mfn, p2m_mmio_direct_dev);
}

int unmap_mmio_regions(struct domain *d,
                       gfn_t start_gfn,
                       unsigned long nr,
                       mfn_t mfn)
{
    return p2m_remove_mapping(d, start_gfn, nr, mfn);
}

int map_dev_mmio_page(struct domain *d, gfn_t gfn, mfn_t mfn)
{
    int res;

    if ( !iomem_access_permitted(d, mfn_x(mfn), mfn_x(mfn)) )
        return 0;

    res = p2m_insert_mapping(d, gfn, 1, mfn, p2m_mmio_direct_c);
    if ( res < 0 )
    {
        printk(XENLOG_G_ERR "Unable to map MFN %#"PRI_mfn" in %pd\n",
               mfn_x(mfn), d);
        return res;
    }

    return 0;
}

int guest_physmap_add_entry(struct domain *d,
                            gfn_t gfn,
                            mfn_t mfn,
                            unsigned long page_order,
                            p2m_type_t t)
{
    return p2m_insert_mapping(d, gfn, (1 << page_order), mfn, t);
}

int guest_physmap_remove_page(struct domain *d, gfn_t gfn, mfn_t mfn,
                              unsigned int page_order)
{
    return p2m_remove_mapping(d, gfn, (1 << page_order), mfn);
}

int set_foreign_p2m_entry(struct domain *d, const struct domain *fd,
                          unsigned long gfn, mfn_t mfn)
{
    struct page_info *page = mfn_to_page(mfn);
    int rc;

    ASSERT(arch_acquire_resource_check(d));

    if ( !get_page(page, fd) )
        return -EINVAL;

    /*
     * It is valid to always use p2m_map_foreign_rw here as if this gets
     * called then d != fd. A case when d == fd would be rejected by
     * rcu_lock_remote_domain_by_id() earlier. Put a respective ASSERT()
     * to catch incorrect usage in future.
     */
    ASSERT(d != fd);

    rc = guest_physmap_add_entry(d, _gfn(gfn), mfn, 0, p2m_map_foreign_rw);
    if ( rc )
        put_page(page);

    return rc;
}

static spinlock_t vmid_alloc_lock = SPIN_LOCK_UNLOCKED;

/*
 * VTTBR_EL2 VMID field is 8 or 16 bits. AArch64 may support 16-bit VMID.
 * Using a bitmap here limits us to 256 or 65536 (for AArch64) concurrent
 * domains. The bitmap space will be allocated dynamically based on
 * whether 8 or 16 bit VMIDs are supported.
 */
static unsigned long *vmid_mask;

void p2m_vmid_allocator_init(void)
{
    /*
     * allocate space for vmid_mask based on MAX_VMID
     */
    vmid_mask = xzalloc_array(unsigned long, BITS_TO_LONGS(MAX_VMID));

    if ( !vmid_mask )
        panic("Could not allocate VMID bitmap space\n");

    set_bit(INVALID_VMID, vmid_mask);
}

int p2m_alloc_vmid(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    int rc, nr;

    spin_lock(&vmid_alloc_lock);

    nr = find_first_zero_bit(vmid_mask, MAX_VMID);

    ASSERT(nr != INVALID_VMID);

    if ( nr == MAX_VMID )
    {
        rc = -EBUSY;
        printk(XENLOG_ERR "p2m.c: dom%d: VMID pool exhausted\n", d->domain_id);
        goto out;
    }

    set_bit(nr, vmid_mask);

    p2m->vmid = nr;

    rc = 0;

out:
    spin_unlock(&vmid_alloc_lock);
    return rc;
}

void p2m_free_vmid(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    spin_lock(&vmid_alloc_lock);
    if ( p2m->vmid != INVALID_VMID )
        clear_bit(p2m->vmid, vmid_mask);

    spin_unlock(&vmid_alloc_lock);
}

int p2m_cache_flush_range(struct domain *d, gfn_t *pstart, gfn_t end)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    gfn_t next_block_gfn;
    gfn_t start = *pstart;
    mfn_t mfn = INVALID_MFN;
    p2m_type_t t;
    unsigned int order;
    int rc = 0;
    /* Counter for preemption */
    unsigned short count = 0;

    /*
     * The operation cache flush will invalidate the RAM assigned to the
     * guest in a given range. It will not modify the page table and
     * flushing the cache whilst the page is used by another CPU is
     * fine. So using read-lock is fine here.
     */
    p2m_read_lock(p2m);

    start = gfn_max(start, p2m->lowest_mapped_gfn);
    end = gfn_min(end, gfn_add(p2m->max_mapped_gfn, 1));

    next_block_gfn = start;

    while ( gfn_x(start) < gfn_x(end) )
    {
       /*
         * Cleaning the cache for the P2M may take a long time. So we
         * need to be able to preempt. We will arbitrarily preempt every
         * time count reach 512 or above.
         *
         * The count will be incremented by:
         *  - 1 on region skipped
         *  - 10 for each page requiring a flush
         */
        if ( count >= 512 )
        {
            if ( softirq_pending(smp_processor_id()) )
            {
                rc = -ERESTART;
                break;
            }
            count = 0;
        }

        /*
         * We want to flush page by page as:
         *  - it may not be possible to map the full block (can be up to 1GB)
         *    in Xen memory
         *  - we may want to do fine grain preemption as flushing multiple
         *    page in one go may take a long time
         *
         * As p2m_get_entry is able to return the size of the mapping
         * in the p2m, it is pointless to execute it for each page.
         *
         * We can optimize it by tracking the gfn of the next
         * block. So we will only call p2m_get_entry for each block (can
         * be up to 1GB).
         */
        if ( gfn_eq(start, next_block_gfn) )
        {
            bool valid;

            mfn = p2m_get_entry(p2m, start, &t, NULL, &order, &valid);
            next_block_gfn = gfn_next_boundary(start, order);

            if ( mfn_eq(mfn, INVALID_MFN) || !p2m_is_any_ram(t) || !valid )
            {
                count++;
                start = next_block_gfn;
                continue;
            }
        }

        count += 10;

        flush_page_to_ram(mfn_x(mfn), false);

        start = gfn_add(start, 1);
        mfn = mfn_add(mfn, 1);
    }

    if ( rc != -ERESTART )
        invalidate_icache();

    p2m_read_unlock(p2m);

    *pstart = start;

    return rc;
}

/*
 * See note at ARMv7 ARM B1.14.4 (DDI 0406C.c) (TL;DR: S/W ops are not
 * easily virtualized).
 *
 * Main problems:
 *  - S/W ops are local to a CPU (not broadcast)
 *  - We have line migration behind our back (speculation)
 *  - System caches don't support S/W at all (damn!)
 *
 * In the face of the above, the best we can do is to try and convert
 * S/W ops to VA ops. Because the guest is not allowed to infer the S/W
 * to PA mapping, it can only use S/W to nuke the whole cache, which is
 * rather a good thing for us.
 *
 * Also, it is only used when turning caches on/off ("The expected
 * usage of the cache maintenance instructions that operate by set/way
 * is associated with the powerdown and powerup of caches, if this is
 * required by the implementation.").
 *
 * We use the following policy:
 *  - If we trap a S/W operation, we enabled VM trapping to detect
 *  caches being turned on/off, and do a full clean.
 *
 *  - We flush the caches on both caches being turned on and off.
 *
 *  - Once the caches are enabled, we stop trapping VM ops.
 */
void p2m_set_way_flush(struct vcpu *v, struct cpu_user_regs *regs,
                       const union hsr hsr)
{
    /* This function can only work with the current vCPU. */
    ASSERT(v == current);

    if ( iommu_use_hap_pt(current->domain) )
    {
        gprintk(XENLOG_ERR,
                "The cache should be flushed by VA rather than by set/way.\n");
        inject_undef_exception(regs, hsr);
        return;
    }

    if ( !(v->arch.hcr_el2 & HCR_TVM) )
    {
        v->arch.need_flush_to_ram = true;
        vcpu_hcr_set_flags(v, HCR_TVM);
    }
}

void p2m_toggle_cache(struct vcpu *v, bool was_enabled)
{
    bool now_enabled = vcpu_has_cache_enabled(v);

    /* This function can only work with the current vCPU. */
    ASSERT(v == current);

    /*
     * If switching the MMU+caches on, need to invalidate the caches.
     * If switching it off, need to clean the caches.
     * Clean + invalidate does the trick always.
     */
    if ( was_enabled != now_enabled )
        v->arch.need_flush_to_ram = true;

    /* Caches are now on, stop trapping VM ops (until a S/W op) */
    if ( now_enabled )
        vcpu_hcr_clear_flags(v, HCR_TVM);
}

mfn_t gfn_to_mfn(struct domain *d, gfn_t gfn)
{
    return p2m_lookup(d, gfn, NULL);
}

struct page_info *get_page_from_gva(struct vcpu *v, vaddr_t va,
                                    unsigned long flags)
{
    struct domain *d = v->domain;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct page_info *page = NULL;
    paddr_t maddr = 0;
    uint64_t par;
    mfn_t mfn;
    p2m_type_t t;

    /*
     * XXX: To support a different vCPU, we would need to load the
     * VTTBR_EL2, TTBR0_EL1, TTBR1_EL1 and SCTLR_EL1
     */
    if ( v != current )
        return NULL;

    /*
     * The lock is here to protect us against the break-before-make
     * sequence used when updating the entry.
     */
    p2m_read_lock(p2m);
    par = gvirt_to_maddr(va, &maddr, flags);
    p2m_read_unlock(p2m);

    /*
     * gvirt_to_maddr may fail if the entry does not have the valid bit
     * set. Fallback to the second method:
     *  1) Translate the VA to IPA using software lookup -> Stage-1 page-table
     *  may not be accessible because the stage-2 entries may have valid
     *  bit unset.
     *  2) Software lookup of the MFN
     *
     * Note that when memaccess is enabled, we instead call directly
     * p2m_mem_access_check_and_get_page(...). Because the function is a
     * a variant of the methods described above, it will be able to
     * handle entries with valid bit unset.
     *
     * TODO: Integrate more nicely memaccess with the rest of the
     * function.
     * TODO: Use the fault error in PAR_EL1 to avoid pointless
     *  translation.
     */
    if ( par )
    {
        paddr_t ipa;
        unsigned int s1_perms;

        /*
         * When memaccess is enabled, the translation GVA to MADDR may
         * have failed because of a permission fault.
         */
        if ( p2m->mem_access_enabled )
            return p2m_mem_access_check_and_get_page(va, flags, v);

        /*
         * The software stage-1 table walk can still fail, e.g, if the
         * GVA is not mapped.
         */
        if ( !guest_walk_tables(v, va, &ipa, &s1_perms) )
        {
            dprintk(XENLOG_G_DEBUG,
                    "%pv: Failed to walk page-table va %#"PRIvaddr"\n", v, va);
            return NULL;
        }

        mfn = p2m_lookup(d, gaddr_to_gfn(ipa), &t);
        if ( mfn_eq(INVALID_MFN, mfn) || !p2m_is_ram(t) )
            return NULL;

        /*
         * Check permission that are assumed by the caller. For instance
         * in case of guestcopy, the caller assumes that the translated
         * page can be accessed with the requested permissions. If this
         * is not the case, we should fail.
         *
         * Please note that we do not check for the GV2M_EXEC
         * permission. This is fine because the hardware-based translation
         * instruction does not test for execute permissions.
         */
        if ( (flags & GV2M_WRITE) && !(s1_perms & GV2M_WRITE) )
            return NULL;

        if ( (flags & GV2M_WRITE) && t != p2m_ram_rw )
            return NULL;
    }
    else
        mfn = maddr_to_mfn(maddr);

    if ( !mfn_valid(mfn) )
    {
        dprintk(XENLOG_G_DEBUG, "%pv: Invalid MFN %#"PRI_mfn"\n",
                v, mfn_x(mfn));
        return NULL;
    }

    page = mfn_to_page(mfn);
    ASSERT(page);

    if ( unlikely(!get_page(page, d)) )
    {
        dprintk(XENLOG_G_DEBUG, "%pv: Failing to acquire the MFN %#"PRI_mfn"\n",
                v, mfn_x(maddr_to_mfn(maddr)));
        return NULL;
    }

    return page;
}

void __init p2m_restrict_ipa_bits(unsigned int ipa_bits)
{
    /*
     * Calculate the minimum of the maximum IPA bits that any external entity
     * can support.
     */
    if ( ipa_bits < p2m_ipa_bits )
        p2m_ipa_bits = ipa_bits;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
