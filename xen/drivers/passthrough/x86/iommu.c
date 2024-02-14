/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/cpu.h>
#include <xen/sched.h>
#include <xen/iocap.h>
#include <xen/iommu.h>
#include <xen/paging.h>
#include <xen/guest_access.h>
#include <xen/event.h>
#include <xen/softirq.h>
#include <xen/vm_event.h>
#include <xsm/xsm.h>

#include <asm/hvm/io.h>
#include <asm/io_apic.h>
#include <asm/mem_paging.h>
#include <asm/pt-contig-markers.h>
#include <asm/setup.h>

const struct iommu_init_ops *__initdata iommu_init_ops;
struct iommu_ops __ro_after_init iommu_ops;
bool __read_mostly iommu_non_coherent;
bool __initdata iommu_superpages = true;

enum iommu_intremap __read_mostly iommu_intremap = iommu_intremap_full;

#ifdef CONFIG_PV
/* Possible unfiltered LAPIC/MSI messages from untrusted sources? */
bool __read_mostly untrusted_msi;
#endif

#ifndef iommu_intpost
/*
 * In the current implementation of VT-d posted interrupts, in some extreme
 * cases, the per cpu list which saves the blocked vCPU will be very long,
 * and this will affect the interrupt latency, so let this feature off by
 * default until we find a good solution to resolve it.
 */
bool __read_mostly iommu_intpost;
#endif

void __init acpi_iommu_init(void)
{
    int ret = -ENODEV;

    if ( !iommu_enable && !iommu_intremap )
        return;

    if ( !acpi_disabled )
    {
        ret = acpi_dmar_init();

#ifndef iommu_snoop
        /*
         * As long as there's no per-domain snoop control, and as long as on
         * AMD we uniformly force coherent accesses, a possible command line
         * override should affect VT-d only.
         */
        if ( ret )
            iommu_snoop = true;
#endif

        if ( ret == -ENODEV )
            ret = acpi_ivrs_init();
    }

    if ( ret )
    {
        iommu_enable = false;
        iommu_intremap = iommu_intremap_off;
    }
}

int __init iommu_hardware_setup(void)
{
    struct IO_APIC_route_entry **ioapic_entries = NULL;
    int rc;

    if ( !iommu_init_ops )
        return -ENODEV;

    rc = scan_pci_devices();
    if ( rc )
        return rc;

    if ( !iommu_ops.init )
        iommu_ops = *iommu_init_ops->ops;
    else
        /* x2apic setup may have previously initialised the struct. */
        ASSERT(iommu_ops.init == iommu_init_ops->ops->init);

    if ( !x2apic_enabled && iommu_intremap )
    {
        /*
         * If x2APIC is enabled interrupt remapping is already enabled, so
         * there's no need to mess with the IO-APIC because the remapping
         * entries are already correctly setup by x2apic_bsp_setup.
         */
        ioapic_entries = alloc_ioapic_entries();
        if ( !ioapic_entries )
            return -ENOMEM;
        rc = save_IO_APIC_setup(ioapic_entries);
        if ( rc )
        {
            free_ioapic_entries(ioapic_entries);
            return rc;
        }

        mask_8259A();
        mask_IO_APIC_setup(ioapic_entries);
    }

    if ( !iommu_superpages )
        iommu_ops.page_sizes &= PAGE_SIZE_4K;

    rc = iommu_init_ops->setup();

    ASSERT(iommu_superpages || iommu_ops.page_sizes == PAGE_SIZE_4K);

    if ( ioapic_entries )
    {
        restore_IO_APIC_setup(ioapic_entries, rc);
        unmask_8259A();
        free_ioapic_entries(ioapic_entries);
    }

    return rc;
}

int iommu_enable_x2apic(void)
{
    if ( system_state < SYS_STATE_active )
    {
        if ( !iommu_supports_x2apic() )
            return -EOPNOTSUPP;

        iommu_ops = *iommu_init_ops->ops;
    }
    else if ( !x2apic_enabled )
        return -EOPNOTSUPP;

    if ( !iommu_ops.enable_x2apic )
        return -EOPNOTSUPP;

    return iommu_call(&iommu_ops, enable_x2apic);
}

void iommu_update_ire_from_apic(
    unsigned int apic, unsigned int pin, uint64_t rte)
{
    iommu_vcall(&iommu_ops, update_ire_from_apic, apic, pin, rte);
}

unsigned int iommu_read_apic_from_ire(unsigned int apic, unsigned int reg)
{
    return iommu_call(&iommu_ops, read_apic_from_ire, apic, reg);
}

int __init iommu_setup_hpet_msi(struct msi_desc *msi)
{
    const struct iommu_ops *ops = iommu_get_ops();
    return ops->setup_hpet_msi ? iommu_call(ops, setup_hpet_msi, msi) : -ENODEV;
}

void __hwdom_init arch_iommu_check_autotranslated_hwdom(struct domain *d)
{
    if ( !is_iommu_enabled(d) )
        panic("Presently, iommu must be enabled for PVH hardware domain\n");

    if ( !iommu_hwdom_strict )
        panic("PVH hardware domain iommu must be set in 'strict' mode\n");
}

int arch_iommu_domain_init(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    spin_lock_init(&hd->arch.mapping_lock);

    INIT_PAGE_LIST_HEAD(&hd->arch.pgtables.list);
    spin_lock_init(&hd->arch.pgtables.lock);
    INIT_LIST_HEAD(&hd->arch.identity_maps);

    return 0;
}

void arch_iommu_domain_destroy(struct domain *d)
{
    /*
     * There should be not page-tables left allocated by the time the
     * domain is destroyed. Note that arch_iommu_domain_destroy() is
     * called unconditionally, so pgtables may be uninitialized.
     */
    ASSERT(!dom_iommu(d)->platform_ops ||
           page_list_empty(&dom_iommu(d)->arch.pgtables.list));
}

struct identity_map {
    struct list_head list;
    paddr_t base, end;
    p2m_access_t access;
    unsigned int count;
};

int iommu_identity_mapping(struct domain *d, p2m_access_t p2ma,
                           paddr_t base, paddr_t end,
                           unsigned int flag)
{
    unsigned long base_pfn = base >> PAGE_SHIFT_4K;
    unsigned long end_pfn = PAGE_ALIGN_4K(end) >> PAGE_SHIFT_4K;
    struct identity_map *map;
    struct domain_iommu *hd = dom_iommu(d);

    ASSERT(pcidevs_locked());
    ASSERT(base < end);

    /*
     * No need to acquire hd->arch.mapping_lock: Both insertion and removal
     * get done while holding pcidevs_lock.
     */
    list_for_each_entry( map, &hd->arch.identity_maps, list )
    {
        if ( map->base == base && map->end == end )
        {
            int ret = 0;

            if ( p2ma != p2m_access_x )
            {
                if ( map->access != p2ma )
                    return -EADDRINUSE;
                ++map->count;
                return 0;
            }

            if ( --map->count )
                return 0;

            while ( base_pfn < end_pfn )
            {
                if ( clear_identity_p2m_entry(d, base_pfn) )
                    ret = -ENXIO;
                base_pfn++;
            }

            list_del(&map->list);
            xfree(map);

            return ret;
        }

        if ( end >= map->base && map->end >= base )
            return -EADDRINUSE;
    }

    if ( p2ma == p2m_access_x )
        return -ENOENT;

    while ( base_pfn < end_pfn )
    {
        int err = set_identity_p2m_entry(d, base_pfn, p2ma, flag);

        if ( err )
            return err;
        base_pfn++;
    }

    map = xmalloc(struct identity_map);
    if ( !map )
        return -ENOMEM;
    map->base = base;
    map->end = end;
    map->access = p2ma;
    map->count = 1;
    list_add_tail(&map->list, &hd->arch.identity_maps);

    return 0;
}

void iommu_identity_map_teardown(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    struct identity_map *map, *tmp;

    list_for_each_entry_safe ( map, tmp, &hd->arch.identity_maps, list )
    {
        list_del(&map->list);
        xfree(map);
    }
}

static int __hwdom_init cf_check map_subtract(unsigned long s, unsigned long e,
                                              void *data)
{
    struct rangeset *map = data;

    return rangeset_remove_range(map, s, e);
}

struct map_data {
    struct domain *d;
    unsigned int flush_flags;
    bool mmio_ro;
};

static int __hwdom_init cf_check identity_map(unsigned long s, unsigned long e,
                                              void *data)
{
    struct map_data *info = data;
    struct domain *d = info->d;
    long rc;

    if ( iommu_verbose )
        printk(XENLOG_INFO " [%010lx, %010lx] R%c\n",
               s, e, info->mmio_ro ? 'O' : 'W');

    if ( paging_mode_translate(d) )
    {
        if ( info->mmio_ro )
        {
            ASSERT_UNREACHABLE();
            /* End the rangeset iteration, as other regions will also fail. */
            return -EOPNOTSUPP;
        }
        while ( (rc = map_mmio_regions(d, _gfn(s), e - s + 1, _mfn(s))) > 0 )
        {
            s += rc;
            process_pending_softirqs();
        }
    }
    else
    {
        const unsigned int perms = IOMMUF_readable | IOMMUF_preempt |
                                   (info->mmio_ro ? 0 : IOMMUF_writable);

        /*
         * Read-only ranges are strictly MMIO and need an additional iomem
         * permissions check.
         */
        while ( info->mmio_ro && s <= e && !iomem_access_permitted(d, s, e) )
        {
            /*
             * Consume a frame per iteration until the remainder is accessible
             * or there's nothing left to map.
             */
            if ( iomem_access_permitted(d, s, s) )
            {
                rc = iommu_map(d, _dfn(s), _mfn(s), 1, perms,
                               &info->flush_flags);
                if ( rc < 0 )
                    break;
                /* Must map a frame at least, which is what we request for. */
                ASSERT(rc == 1);
                process_pending_softirqs();
            }
            s++;
        }
        while ( (rc = iommu_map(d, _dfn(s), _mfn(s), e - s + 1,
                                perms, &info->flush_flags)) > 0 )
        {
            s += rc;
            process_pending_softirqs();
        }
    }
    ASSERT(rc <= 0);
    if ( rc )
        printk(XENLOG_WARNING
               "IOMMU identity mapping of [%lx, %lx] failed: %ld\n",
               s, e, rc);

    /* Ignore errors and attempt to map the remaining regions. */
    return 0;
}

void __hwdom_init arch_iommu_hwdom_init(struct domain *d)
{
    unsigned int i;
    struct rangeset *map;
    struct map_data map_data = { .d = d };
    int rc;

    BUG_ON(!is_hardware_domain(d));

    /* Reserved IOMMU mappings are enabled by default. */
    if ( iommu_hwdom_reserved == -1 )
        iommu_hwdom_reserved = 1;

    if ( iommu_hwdom_inclusive )
    {
        printk(XENLOG_WARNING
               "IOMMU inclusive mappings are deprecated and will be removed in future versions\n");

        if ( !is_pv_domain(d) )
        {
            printk(XENLOG_WARNING
                   "IOMMU inclusive mappings are only supported on PV Dom0\n");
            iommu_hwdom_inclusive = false;
        }
    }

    if ( iommu_hwdom_passthrough )
        return;

    map = rangeset_new(NULL, NULL, 0);
    if ( !map )
        panic("IOMMU init: unable to allocate rangeset\n");

    if ( iommu_hwdom_inclusive )
    {
        /* Add the whole range below 4GB, UNUSABLE regions will be removed. */
        rc = rangeset_add_range(map, 0, PFN_DOWN(GB(4)) - 1);
        if ( rc )
            panic("IOMMU inclusive mappings can't be added: %d\n", rc);
    }

    for ( i = 0; i < e820.nr_map; i++ )
    {
        const struct e820entry entry = e820.map[i];

        switch ( entry.type )
        {
        case E820_UNUSABLE:
            /* Only relevant for inclusive mode, otherwise this is a no-op. */
            rc = rangeset_remove_range(map, PFN_DOWN(entry.addr),
                                       PFN_DOWN(entry.addr + entry.size - 1));
            if ( rc )
                panic("IOMMU failed to remove unusable memory: %d\n", rc);
            continue;

        case E820_RESERVED:
            if ( !iommu_hwdom_inclusive && !iommu_hwdom_reserved )
                continue;
            break;

        case E820_RAM:
            if ( iommu_hwdom_strict )
                continue;
            break;

        default:
            continue;
        }

        rc = rangeset_add_range(map, PFN_DOWN(entry.addr),
                                PFN_DOWN(entry.addr + entry.size - 1));
        if ( rc )
            panic("IOMMU failed to add identity range: %d\n", rc);
    }

    /* Remove any areas in-use by Xen. */
    rc = remove_xen_ranges(map);
    if ( rc )
        panic("IOMMU failed to remove Xen ranges: %d\n", rc);

    /* Remove any overlap with the Interrupt Address Range. */
    rc = rangeset_remove_range(map, 0xfee00, 0xfeeff);
    if ( rc )
        panic("IOMMU failed to remove Interrupt Address Range: %d\n", rc);

    /* If emulating IO-APIC(s) make sure the base address is unmapped. */
    if ( has_vioapic(d) )
    {
        for ( i = 0; i < d->arch.hvm.nr_vioapics; i++ )
        {
            rc = rangeset_remove_singleton(map,
                PFN_DOWN(domain_vioapic(d, i)->base_address));
            if ( rc )
                panic("IOMMU failed to remove IO-APIC: %d\n", rc);
        }
    }

    if ( is_pv_domain(d) )
    {
        /*
         * Be consistent with CPU mappings: Dom0 is permitted to establish r/o
         * ones there (also for e.g. HPET in certain cases), so it should also
         * have such established for IOMMUs.  Remove any read-only ranges here,
         * since ranges in mmio_ro_ranges are already explicitly mapped below
         * in read-only mode.
         */
        rc = rangeset_report_ranges(mmio_ro_ranges, 0, ~0UL, map_subtract, map);
        if ( rc )
            panic("IOMMU failed to remove read-only regions: %d\n", rc);
    }

    if ( has_vpci(d) )
    {
        /*
         * TODO: runtime added MMCFG regions are not checked to make sure they
         * don't overlap with already mapped regions, thus preventing trapping.
         */
        rc = vpci_subtract_mmcfg(d, map);
        if ( rc )
            panic("IOMMU unable to remove MMCFG areas: %d\n", rc);
    }

    /* Remove any regions past the last address addressable by the domain. */
    rc = rangeset_remove_range(map, PFN_DOWN(1UL << domain_max_paddr_bits(d)),
                               ~0UL);
    if ( rc )
        panic("IOMMU unable to remove unaddressable ranges: %d\n", rc);

    if ( iommu_verbose )
        printk(XENLOG_INFO "%pd: identity mappings for IOMMU:\n", d);

    rc = rangeset_report_ranges(map, 0, ~0UL, identity_map, &map_data);
    rangeset_destroy(map);
    if ( !rc && is_pv_domain(d) )
    {
        map_data.mmio_ro = true;
        rc = rangeset_report_ranges(mmio_ro_ranges, 0, ~0UL, identity_map,
                                    &map_data);
    }
    if ( rc )
        printk(XENLOG_WARNING "IOMMU unable to create %smappings: %d\n",
               map_data.mmio_ro ? "read-only " : "", rc);

    /* Use if to avoid compiler warning */
    if ( iommu_iotlb_flush_all(d, map_data.flush_flags) )
        return;
}

void arch_pci_init_pdev(struct pci_dev *pdev)
{
    pdev->arch.pseudo_domid = DOMID_INVALID;
}

unsigned long *__init iommu_init_domid(domid_t reserve)
{
    unsigned long *map;

    if ( !iommu_quarantine )
        return ZERO_BLOCK_PTR;

    BUILD_BUG_ON(DOMID_MASK * 2U >= UINT16_MAX);

    map = xzalloc_array(unsigned long, BITS_TO_LONGS(UINT16_MAX - DOMID_MASK));
    if ( map && reserve != DOMID_INVALID )
    {
        ASSERT(reserve > DOMID_MASK);
        __set_bit(reserve & DOMID_MASK, map);
    }

    return map;
}

domid_t iommu_alloc_domid(unsigned long *map)
{
    /*
     * This is used uniformly across all IOMMUs, such that on typical
     * systems we wouldn't re-use the same ID very quickly (perhaps never).
     */
    static unsigned int start;
    unsigned int idx = find_next_zero_bit(map, UINT16_MAX - DOMID_MASK, start);

    ASSERT(pcidevs_locked());

    if ( idx >= UINT16_MAX - DOMID_MASK )
        idx = find_first_zero_bit(map, UINT16_MAX - DOMID_MASK);
    if ( idx >= UINT16_MAX - DOMID_MASK )
        return DOMID_INVALID;

    __set_bit(idx, map);

    start = idx + 1;

    return idx | (DOMID_MASK + 1);
}

void iommu_free_domid(domid_t domid, unsigned long *map)
{
    ASSERT(pcidevs_locked());

    if ( domid == DOMID_INVALID )
        return;

    ASSERT(domid > DOMID_MASK);

    if ( !__test_and_clear_bit(domid & DOMID_MASK, map) )
        BUG();
}

int iommu_free_pgtables(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    struct page_info *pg;
    unsigned int done = 0;

    if ( !is_iommu_enabled(d) )
        return 0;

    /* After this barrier, no new IOMMU mappings can be inserted. */
    spin_barrier(&hd->arch.mapping_lock);

    /*
     * Pages will be moved to the free list below. So we want to
     * clear the root page-table to avoid any potential use after-free.
     */
    iommu_vcall(hd->platform_ops, clear_root_pgtable, d);

    while ( (pg = page_list_remove_head(&hd->arch.pgtables.list)) )
    {
        free_domheap_page(pg);

        if ( !(++done & 0xff) && general_preempt_check() )
            return -ERESTART;
    }

    return 0;
}

struct page_info *iommu_alloc_pgtable(struct domain_iommu *hd,
                                      uint64_t contig_mask)
{
    unsigned int memflags = 0;
    struct page_info *pg;
    uint64_t *p;

#ifdef CONFIG_NUMA
    if ( hd->node != NUMA_NO_NODE )
        memflags = MEMF_node(hd->node);
#endif

    pg = alloc_domheap_page(NULL, memflags);
    if ( !pg )
        return NULL;

    p = __map_domain_page(pg);

    if ( contig_mask )
    {
        /* See pt-contig-markers.h for a description of the marker scheme. */
        unsigned int i, shift = find_first_set_bit(contig_mask);

        ASSERT((CONTIG_LEVEL_SHIFT & (contig_mask >> shift)) == CONTIG_LEVEL_SHIFT);

        p[0] = (CONTIG_LEVEL_SHIFT + 0ULL) << shift;
        p[1] = 0;
        p[2] = 1ULL << shift;
        p[3] = 0;

        for ( i = 4; i < PAGE_SIZE / sizeof(*p); i += 4 )
        {
            p[i + 0] = (find_first_set_bit(i) + 0ULL) << shift;
            p[i + 1] = 0;
            p[i + 2] = 1ULL << shift;
            p[i + 3] = 0;
        }
    }
    else
        clear_page(p);

    iommu_sync_cache(p, PAGE_SIZE);

    unmap_domain_page(p);

    spin_lock(&hd->arch.pgtables.lock);
    page_list_add(pg, &hd->arch.pgtables.list);
    spin_unlock(&hd->arch.pgtables.lock);

    return pg;
}

/*
 * Intermediate page tables which get replaced by large pages may only be
 * freed after a suitable IOTLB flush. Hence such pages get queued on a
 * per-CPU list, with a per-CPU tasklet processing the list on the assumption
 * that the necessary IOTLB flush will have occurred by the time tasklets get
 * to run. (List and tasklet being per-CPU has the benefit of accesses not
 * requiring any locking.)
 */
static DEFINE_PER_CPU(struct page_list_head, free_pgt_list);
static DEFINE_PER_CPU(struct tasklet, free_pgt_tasklet);

static void cf_check free_queued_pgtables(void *arg)
{
    struct page_list_head *list = arg;
    struct page_info *pg;
    unsigned int done = 0;

    ASSERT(list == &this_cpu(free_pgt_list));

    while ( (pg = page_list_remove_head(list)) )
    {
        free_domheap_page(pg);

        /*
         * Just to be on the safe side, check for processing softirqs every
         * once in a while.  Generally it is expected that parties queuing
         * pages for freeing will find a need for preemption before too many
         * pages can be queued.  Granularity of checking is somewhat arbitrary.
         */
        if ( !(++done & 0x1ff) )
             process_pending_softirqs();
    }
}

void iommu_queue_free_pgtable(struct domain_iommu *hd, struct page_info *pg)
{
    unsigned int cpu = smp_processor_id();

    spin_lock(&hd->arch.pgtables.lock);
    page_list_del(pg, &hd->arch.pgtables.list);
    spin_unlock(&hd->arch.pgtables.lock);

    page_list_add_tail(pg, &per_cpu(free_pgt_list, cpu));

    tasklet_schedule(&per_cpu(free_pgt_tasklet, cpu));
}

static int cf_check cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    struct page_list_head *list = &per_cpu(free_pgt_list, cpu);
    struct tasklet *tasklet = &per_cpu(free_pgt_tasklet, cpu);

    switch ( action )
    {
    case CPU_DOWN_PREPARE:
        tasklet_kill(tasklet);
        break;

    case CPU_DEAD:
        if ( !page_list_empty(list) )
        {
            page_list_splice(list, &this_cpu(free_pgt_list));
            INIT_PAGE_LIST_HEAD(list);
            tasklet_schedule(&this_cpu(free_pgt_tasklet));
        }
        break;

    case CPU_UP_PREPARE:
        INIT_PAGE_LIST_HEAD(list);
        fallthrough;
    case CPU_DOWN_FAILED:
        tasklet_init(tasklet, free_queued_pgtables, list);
        if ( !page_list_empty(list) )
            tasklet_schedule(tasklet);
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback,
};

static int __init cf_check bsp_init(void)
{
    if ( iommu_enabled )
    {
        cpu_callback(&cpu_nfb, CPU_UP_PREPARE,
                     (void *)(unsigned long)smp_processor_id());
        register_cpu_notifier(&cpu_nfb);
    }

    return 0;
}
presmp_initcall(bsp_init);

bool arch_iommu_use_permitted(const struct domain *d)
{
    /*
     * Prevent device assign if mem paging, mem sharing or log-dirty
     * have been enabled for this domain, or if PoD is still in active use.
     */
    return d == dom_io ||
           (likely(!mem_sharing_enabled(d)) &&
            likely(!mem_paging_enabled(d)) &&
            likely(!p2m_pod_active(d)) &&
            likely(!p2m_is_global_logdirty(d)));
}

static int __init cf_check adjust_irq_affinities(void)
{
    iommu_adjust_irq_affinities();

    return 0;
}
__initcall(adjust_irq_affinities);

bool __init iommu_unity_region_ok(const char *prefix, mfn_t start, mfn_t end)
{
    mfn_t addr;

    if ( e820_all_mapped(mfn_to_maddr(start), mfn_to_maddr(end) + PAGE_SIZE,
                         E820_RESERVED) )
        return true;

    printk(XENLOG_WARNING
           "%s: [%#" PRI_mfn " ,%#" PRI_mfn "] is not (entirely) in reserved memory\n",
           prefix, mfn_x(start), mfn_x(end));

    for ( addr = start; mfn_x(addr) <= mfn_x(end); addr = mfn_add(addr, 1) )
    {
        unsigned int type = page_get_ram_type(addr);

        if ( type == RAM_TYPE_UNKNOWN )
        {
            if ( e820_add_range(mfn_to_maddr(addr),
                                mfn_to_maddr(addr) + PAGE_SIZE, E820_RESERVED) )
                continue;
            printk(XENLOG_ERR
                   "%s: page at %#" PRI_mfn " couldn't be reserved\n",
                   prefix, mfn_x(addr));
            return false;
        }

        /*
         * Types which aren't RAM are considered good enough.
         * Note that a page being partially RESERVED, ACPI or UNUSABLE will
         * force Xen into assuming the whole page as having that type in
         * practice.
         */
        if ( type & (RAM_TYPE_RESERVED | RAM_TYPE_ACPI |
                     RAM_TYPE_UNUSABLE) )
            continue;

        printk(XENLOG_ERR
               "%s: page at %#" PRI_mfn " can't be converted\n",
               prefix, mfn_x(addr));
        return false;
    }

    return true;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
