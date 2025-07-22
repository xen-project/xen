/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bootinfo.h>
#include <xen/device_tree.h>
#include <xen/domain.h>
#include <xen/domain_page.h>
#include <xen/err.h>
#include <xen/event.h>
#include <xen/fdt-domain-build.h>
#include <xen/fdt-kernel.h>
#include <xen/grant_table.h>
#include <xen/init.h>
#include <xen/iocap.h>
#include <xen/iommu.h>
#include <xen/libfdt/libfdt.h>
#include <xen/llc-coloring.h>
#include <xen/sizes.h>
#include <xen/sched.h>
#include <xen/stdbool.h>
#include <xen/types.h>
#include <xen/vmap.h>

#include <public/bootfdt.h>
#include <public/domctl.h>
#include <public/event_channel.h>
#include <public/io/xs_wire.h>

#include <asm/dom0less-build.h>
#include <asm/setup.h>

#include <xen/static-memory.h>
#include <xen/static-shmem.h>

#define XENSTORE_PFN_LATE_ALLOC UINT64_MAX

static domid_t __initdata xs_domid = DOMID_INVALID;
static bool __initdata need_xenstore;

void __init set_xs_domain(struct domain *d)
{
    if ( xs_domid != DOMID_INVALID )
        panic("Only 1 xenstore domain can be specified! (%u)", xs_domid);

    xs_domid = d->domain_id;
    set_global_virq_handler(d, VIRQ_DOM_EXC);
}

bool __init is_dom0less_mode(void)
{
    struct boot_modules *mods = &bootinfo.modules;
    struct boot_module *mod;
    unsigned int i;
    bool dom0found = false;
    bool domUfound = false;

    /* Look into the boot_modules */
    for ( i = 0 ; i < mods->nr_mods ; i++ )
    {
        mod = &mods->module[i];
        /* Find if dom0 and domU kernels are present */
        if ( mod->kind == BOOTMOD_KERNEL )
        {
            if ( mod->domU == false )
            {
                dom0found = true;
                break;
            }
            else
                domUfound = true;
        }
    }

    /*
     * If there is no dom0 kernel but at least one domU, then we are in
     * dom0less mode
     */
    return ( !dom0found && domUfound );
}

static int __init alloc_xenstore_evtchn(struct domain *d)
{
    evtchn_alloc_unbound_t alloc;
    int rc;

    alloc.dom = d->domain_id;
    alloc.remote_dom = xs_domid;
    rc = evtchn_alloc_unbound(&alloc, 0);
    if ( rc )
    {
        printk("Failed allocating event channel for domain\n");
        return rc;
    }

    d->arch.hvm.params[HVM_PARAM_STORE_EVTCHN] = alloc.port;

    return 0;
}

static void __init initialize_domU_xenstore(void)
{
    struct domain *d;

    if ( xs_domid == DOMID_INVALID )
        return;

    for_each_domain( d )
    {
        uint64_t gfn = d->arch.hvm.params[HVM_PARAM_STORE_PFN];
        int rc;

        if ( gfn == 0 )
            continue;

        if ( is_xenstore_domain(d) )
            continue;

        rc = alloc_xenstore_evtchn(d);
        if ( rc < 0 )
            panic("%pd: Failed to allocate xenstore_evtchn\n", d);

        if ( gfn != XENSTORE_PFN_LATE_ALLOC && IS_ENABLED(CONFIG_GRANT_TABLE) )
        {
            ASSERT(gfn < UINT32_MAX);
            gnttab_seed_entry(d, GNTTAB_RESERVED_XENSTORE, xs_domid, gfn);
        }
    }
}

/*
 * Scan device tree properties for passthrough specific information.
 * Returns < 0 on error
 *         0 on success
 */
static int __init handle_passthrough_prop(struct kernel_info *kinfo,
                                          const struct fdt_property *xen_reg,
                                          const struct fdt_property *xen_path,
                                          bool xen_force,
                                          uint32_t address_cells,
                                          uint32_t size_cells)
{
    const __be32 *cell;
    unsigned int i, len;
    struct dt_device_node *node;
    int res;
    paddr_t mstart, size, gstart;

    if ( !kinfo->xen_reg_assigned )
    {
        kinfo->xen_reg_assigned = rangeset_new(NULL, NULL, 0);

        if ( !kinfo->xen_reg_assigned )
            return -ENOMEM;
    }

    /* xen,reg specifies where to map the MMIO region */
    cell = (const __be32 *)xen_reg->data;
    len = fdt32_to_cpu(xen_reg->len) / ((address_cells * 2 + size_cells) *
                                        sizeof(uint32_t));

    for ( i = 0; i < len; i++ )
    {
        device_tree_get_reg(&cell, address_cells, size_cells,
                            &mstart, &size);
        gstart = dt_next_cell(address_cells, &cell);

        if ( gstart & ~PAGE_MASK || mstart & ~PAGE_MASK || size & ~PAGE_MASK )
        {
            printk(XENLOG_ERR
                   "DomU passthrough config has not page aligned addresses/sizes\n");
            return -EINVAL;
        }

        res = iomem_permit_access(kinfo->bd.d, paddr_to_pfn(mstart),
                                  paddr_to_pfn(PAGE_ALIGN(mstart + size - 1)));
        if ( res )
        {
            printk(XENLOG_ERR "Unable to permit to dom%d access to"
                   " 0x%"PRIpaddr" - 0x%"PRIpaddr"\n",
                   kinfo->bd.d->domain_id,
                   mstart & PAGE_MASK, PAGE_ALIGN(mstart + size) - 1);
            return res;
        }

        res = map_regions_p2mt(kinfo->bd.d,
                               gaddr_to_gfn(gstart),
                               PFN_DOWN(size),
                               maddr_to_mfn(mstart),
                               p2m_mmio_direct_dev);
        if ( res < 0 )
        {
            printk(XENLOG_ERR
                   "Failed to map %"PRIpaddr" to the guest at%"PRIpaddr"\n",
                   mstart, gstart);
            return -EFAULT;
        }

        res = rangeset_add_range(kinfo->xen_reg_assigned, PFN_DOWN(gstart),
                                 PFN_DOWN(gstart + size - 1));
        if ( res )
            return res;
    }

    /*
     * If xen_force, we let the user assign a MMIO region with no
     * associated path.
     */
    if ( xen_path == NULL )
        return xen_force ? 0 : -EINVAL;

    /*
     * xen,path specifies the corresponding node in the host DT.
     * Both interrupt mappings and IOMMU settings are based on it,
     * as they are done based on the corresponding host DT node.
     */
    node = dt_find_node_by_path(xen_path->data);
    if ( node == NULL )
    {
        printk(XENLOG_ERR "Couldn't find node %s in host_dt!\n",
               xen_path->data);
        return -EINVAL;
    }

    res = map_device_irqs_to_domain(kinfo->bd.d, node, true, NULL);
    if ( res < 0 )
        return res;

    res = iommu_add_dt_device(node);
    if ( res < 0 )
        return res;

    /* If xen_force, we allow assignment of devices without IOMMU protection. */
    if ( xen_force && !dt_device_is_protected(node) )
        return 0;

    return iommu_assign_dt_device(kinfo->bd.d, node);
}

static int __init handle_prop_pfdt(struct kernel_info *kinfo,
                                   const void *pfdt, int nodeoff,
                                   uint32_t address_cells, uint32_t size_cells,
                                   bool scan_passthrough_prop)
{
    void *fdt = kinfo->fdt;
    int propoff, nameoff, res;
    const struct fdt_property *prop, *xen_reg = NULL, *xen_path = NULL;
    const char *name;
    bool found, xen_force = false;

    for ( propoff = fdt_first_property_offset(pfdt, nodeoff);
          propoff >= 0;
          propoff = fdt_next_property_offset(pfdt, propoff) )
    {
        if ( !(prop = fdt_get_property_by_offset(pfdt, propoff, NULL)) )
            return -FDT_ERR_INTERNAL;

        found = false;
        nameoff = fdt32_to_cpu(prop->nameoff);
        name = fdt_string(pfdt, nameoff);

        if ( scan_passthrough_prop )
        {
            if ( dt_prop_cmp("xen,reg", name) == 0 )
            {
                xen_reg = prop;
                found = true;
            }
            else if ( dt_prop_cmp("xen,path", name) == 0 )
            {
                xen_path = prop;
                found = true;
            }
            else if ( dt_prop_cmp("xen,force-assign-without-iommu",
                                  name) == 0 )
            {
                xen_force = true;
                found = true;
            }
        }

        /*
         * Copy properties other than the ones above: xen,reg, xen,path,
         * and xen,force-assign-without-iommu.
         */
        if ( !found )
        {
            res = fdt_property(fdt, name, prop->data, fdt32_to_cpu(prop->len));
            if ( res )
                return res;
        }
    }

    /*
     * Only handle passthrough properties if both xen,reg and xen,path
     * are present, or if xen,force-assign-without-iommu is specified.
     */
    if ( xen_reg != NULL && (xen_path != NULL || xen_force) )
    {
        res = handle_passthrough_prop(kinfo, xen_reg, xen_path, xen_force,
                                      address_cells, size_cells);
        if ( res < 0 )
        {
            printk(XENLOG_ERR "Failed to assign device to %pd\n", kinfo->bd.d);
            return res;
        }
    }
    else if ( (xen_path && !xen_reg) || (xen_reg && !xen_path && !xen_force) )
    {
        printk(XENLOG_ERR "xen,reg or xen,path missing for %pd\n",
               kinfo->bd.d);
        return -EINVAL;
    }

    /* FDT_ERR_NOTFOUND => There is no more properties for this node */
    return ( propoff != -FDT_ERR_NOTFOUND ) ? propoff : 0;
}

static int __init scan_pfdt_node(struct kernel_info *kinfo, const void *pfdt,
                                 int nodeoff,
                                 uint32_t address_cells, uint32_t size_cells,
                                 bool scan_passthrough_prop)
{
    int rc = 0;
    void *fdt = kinfo->fdt;
    int node_next;

    rc = fdt_begin_node(fdt, fdt_get_name(pfdt, nodeoff, NULL));
    if ( rc )
        return rc;

    rc = handle_prop_pfdt(kinfo, pfdt, nodeoff, address_cells, size_cells,
                          scan_passthrough_prop);
    if ( rc )
        return rc;

    address_cells = device_tree_get_u32(pfdt, nodeoff, "#address-cells",
                                        DT_ROOT_NODE_ADDR_CELLS_DEFAULT);
    size_cells = device_tree_get_u32(pfdt, nodeoff, "#size-cells",
                                     DT_ROOT_NODE_SIZE_CELLS_DEFAULT);

    node_next = fdt_first_subnode(pfdt, nodeoff);
    while ( node_next > 0 )
    {
        rc = scan_pfdt_node(kinfo, pfdt, node_next, address_cells, size_cells,
                            scan_passthrough_prop);
        if ( rc )
            return rc;

        node_next = fdt_next_subnode(pfdt, node_next);
    }

    return fdt_end_node(fdt);
}

static int __init check_partial_fdt(void *pfdt, size_t size)
{
    int res;

    if ( fdt_magic(pfdt) != FDT_MAGIC )
    {
        dprintk(XENLOG_ERR, "Partial FDT is not a valid Flat Device Tree");
        return -EINVAL;
    }

    res = fdt_check_header(pfdt);
    if ( res )
    {
        dprintk(XENLOG_ERR, "Failed to check the partial FDT (%d)", res);
        return -EINVAL;
    }

    if ( fdt_totalsize(pfdt) > size )
    {
        dprintk(XENLOG_ERR, "Partial FDT totalsize is too big");
        return -EINVAL;
    }

    return 0;
}

static int __init domain_handle_dtb_boot_module(struct domain *d,
                                                struct kernel_info *kinfo)
{
    void *pfdt;
    int res, node_next;

    pfdt = ioremap_cache(kinfo->dtb->start, kinfo->dtb->size);
    if ( pfdt == NULL )
        return -EFAULT;

    res = check_partial_fdt(pfdt, kinfo->dtb->size);
    if ( res < 0 )
        goto out;

    for ( node_next = fdt_first_subnode(pfdt, 0);
          node_next > 0;
          node_next = fdt_next_subnode(pfdt, node_next) )
    {
        const char *name = fdt_get_name(pfdt, node_next, NULL);

        if ( name == NULL )
            continue;

        /*
         * Only scan /$(interrupt_controller) /aliases /passthrough,
         * ignore the rest.
         * They don't have to be parsed in order.
         *
         * Take the interrupt controller phandle value from the special
         * interrupt controller node in the DTB fragment.
         */
        if ( init_intc_phandle(kinfo, name, node_next, pfdt) == 0 )
            continue;

        if ( dt_node_cmp(name, "aliases") == 0 )
        {
            res = scan_pfdt_node(kinfo, pfdt, node_next,
                                 DT_ROOT_NODE_ADDR_CELLS_DEFAULT,
                                 DT_ROOT_NODE_SIZE_CELLS_DEFAULT,
                                 false);
            if ( res )
                goto out;
            continue;
        }
        if ( dt_node_cmp(name, "passthrough") == 0 )
        {
            res = scan_pfdt_node(kinfo, pfdt, node_next,
                                 DT_ROOT_NODE_ADDR_CELLS_DEFAULT,
                                 DT_ROOT_NODE_SIZE_CELLS_DEFAULT,
                                 true);
            if ( res )
                goto out;
            continue;
        }
    }

 out:
    iounmap(pfdt);

    return res;
}

/*
 * The max size for DT is 2MB. However, the generated DT is small (not including
 * domU passthrough DT nodes whose size we account separately), 4KB are enough
 * for now, but we might have to increase it in the future.
 */
#define DOMU_DTB_SIZE 4096
static int __init prepare_dtb_domU(struct domain *d, struct kernel_info *kinfo)
{
    int addrcells, sizecells;
    int ret, fdt_size = DOMU_DTB_SIZE;

    kinfo->phandle_intc = GUEST_PHANDLE_GIC;

#ifdef CONFIG_GRANT_TABLE
    kinfo->gnttab_start = GUEST_GNTTAB_BASE;
    kinfo->gnttab_size = GUEST_GNTTAB_SIZE;
#endif

    addrcells = GUEST_ROOT_ADDRESS_CELLS;
    sizecells = GUEST_ROOT_SIZE_CELLS;

    /* Account for domU passthrough DT size */
    if ( kinfo->dtb )
        fdt_size += kinfo->dtb->size;

    /* Cap to max DT size if needed */
    fdt_size = min(fdt_size, SZ_2M);

    kinfo->fdt = xmalloc_bytes(fdt_size);
    if ( kinfo->fdt == NULL )
        return -ENOMEM;

    ret = fdt_create(kinfo->fdt, fdt_size);
    if ( ret < 0 )
        goto err;

    ret = fdt_finish_reservemap(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    ret = fdt_begin_node(kinfo->fdt, "");
    if ( ret < 0 )
        goto err;

    ret = fdt_property_cell(kinfo->fdt, "#address-cells", addrcells);
    if ( ret )
        goto err;

    ret = fdt_property_cell(kinfo->fdt, "#size-cells", sizecells);
    if ( ret )
        goto err;

    ret = make_chosen_node(kinfo);
    if ( ret )
        goto err;

    ret = make_cpus_node(d, kinfo->fdt);
    if ( ret )
        goto err;

    ret = make_memory_node(kinfo, addrcells, sizecells,
                           kernel_info_get_mem(kinfo));
    if ( ret )
        goto err;

    ret = make_resv_memory_node(kinfo, addrcells, sizecells);
    if ( ret )
        goto err;

    /*
     * domain_handle_dtb_boot_module has to be called before the rest of
     * the device tree is generated because it depends on the value of
     * the field phandle_intc.
     */
    if ( kinfo->dtb )
    {
        ret = domain_handle_dtb_boot_module(d, kinfo);
        if ( ret )
            goto err;
    }

    ret = make_intc_domU_node(kinfo);
    if ( ret )
        goto err;

    ret = make_timer_node(kinfo);
    if ( ret )
        goto err;

    if ( kinfo->dom0less_feature & DOM0LESS_ENHANCED_NO_XS )
    {
        ret = make_hypervisor_node(d, kinfo, addrcells, sizecells);
        if ( ret )
            goto err;
    }

    ret = make_arch_nodes(kinfo);
    if ( ret )
        goto err;

    ret = fdt_end_node(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    ret = fdt_finish(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    return 0;

  err:
    printk("Device tree generation failed (%d).\n", ret);
    xfree(kinfo->fdt);

    return -EINVAL;
}

#define XENSTORE_PFN_OFFSET 1
static int __init alloc_xenstore_page(struct domain *d)
{
    struct page_info *xenstore_pg;
    struct xenstore_domain_interface *interface;
    mfn_t mfn;
    gfn_t gfn;
    int rc;

    if ( (UINT_MAX - d->max_pages) < 1 )
    {
        printk(XENLOG_ERR "%pd: Over-allocation for d->max_pages by 1 page.\n",
               d);
        return -EINVAL;
    }

    d->max_pages += 1;
    xenstore_pg = alloc_domheap_page(d, MEMF_bits(32));
    if ( xenstore_pg == NULL && is_64bit_domain(d) )
        xenstore_pg = alloc_domheap_page(d, 0);
    if ( xenstore_pg == NULL )
        return -ENOMEM;

    mfn = page_to_mfn(xenstore_pg);
    if ( !mfn_x(mfn) )
        return -ENOMEM;

    if ( !is_domain_direct_mapped(d) )
        gfn = gaddr_to_gfn(GUEST_MAGIC_BASE +
                           (XENSTORE_PFN_OFFSET << PAGE_SHIFT));
    else
        gfn = gaddr_to_gfn(mfn_to_maddr(mfn));

    rc = guest_physmap_add_page(d, gfn, mfn, 0);
    if ( rc )
    {
        free_domheap_page(xenstore_pg);
        return rc;
    }

#ifdef CONFIG_HVM
    d->arch.hvm.params[HVM_PARAM_STORE_PFN] = gfn_x(gfn);
#endif
    interface = map_domain_page(mfn);
    interface->connection = XENSTORE_RECONNECT;
    unmap_domain_page(interface);

    return 0;
}

static int __init alloc_xenstore_params(struct kernel_info *kinfo)
{
    struct domain *d = kinfo->bd.d;
    int rc = 0;

#ifdef CONFIG_HVM
    if ( (kinfo->dom0less_feature & (DOM0LESS_XENSTORE | DOM0LESS_XS_LEGACY))
                                 == (DOM0LESS_XENSTORE | DOM0LESS_XS_LEGACY) )
        d->arch.hvm.params[HVM_PARAM_STORE_PFN] = XENSTORE_PFN_LATE_ALLOC;
    else
#endif
    if ( kinfo->dom0less_feature & DOM0LESS_XENSTORE )
    {
        rc = alloc_xenstore_page(d);
        if ( rc < 0 )
            return rc;
    }

    return rc;
}

static void __init domain_vcpu_affinity(struct domain *d,
                                        const struct dt_device_node *node)
{
    struct dt_device_node *np;

    dt_for_each_child_node(node, np)
    {
        const char *hard_affinity_str = NULL;
        uint32_t val;
        int rc;
        struct vcpu *v;
        cpumask_t affinity;

        if ( !dt_device_is_compatible(np, "xen,vcpu") )
            continue;

        if ( !dt_property_read_u32(np, "id", &val) )
            panic("Invalid xen,vcpu node for domain %s\n", dt_node_name(node));

        if ( val >= d->max_vcpus )
            panic("Invalid vcpu_id %u for domain %s, max_vcpus=%u\n", val,
                  dt_node_name(node), d->max_vcpus);

        v = d->vcpu[val];
        rc = dt_property_read_string(np, "hard-affinity", &hard_affinity_str);
        if ( rc < 0 )
            continue;

        cpumask_clear(&affinity);
        while ( *hard_affinity_str != '\0' )
        {
            unsigned int start, end;

            start = simple_strtoul(hard_affinity_str, &hard_affinity_str, 0);

            if ( *hard_affinity_str == '-' )    /* Range */
            {
                hard_affinity_str++;
                end = simple_strtoul(hard_affinity_str, &hard_affinity_str, 0);
            }
            else                /* Single value */
                end = start;

            if ( end >= nr_cpu_ids )
                panic("Invalid pCPU %u for domain %s\n", end, dt_node_name(node));

            for ( ; start <= end; start++ )
                cpumask_set_cpu(start, &affinity);

            if ( *hard_affinity_str == ',' )
                hard_affinity_str++;
            else if ( *hard_affinity_str != '\0' )
                break;
        }

        rc = vcpu_set_hard_affinity(v, &affinity);
        if ( rc )
            panic("vcpu%d: failed (rc=%d) to set hard affinity for domain %s\n",
                  v->vcpu_id, rc, dt_node_name(node));
    }
}

#ifdef CONFIG_ARCH_PAGING_MEMPOOL
static unsigned long __init domain_p2m_pages(unsigned long maxmem_kb,
                                             unsigned int smp_cpus)
{
    /*
     * Keep in sync with libxl__get_required_paging_memory().
     * 256 pages (1MB) per vcpu, plus 1 page per MiB of RAM for the P2M map,
     * plus 128 pages to cover extended regions.
     */
    unsigned long memkb = 4 * (256 * smp_cpus + (maxmem_kb / 1024) + 128);

    BUILD_BUG_ON(PAGE_SIZE != SZ_4K);

    return DIV_ROUND_UP(memkb, 1024) << (20 - PAGE_SHIFT);
}

static int __init domain_p2m_set_allocation(struct domain *d, uint64_t mem,
                                            const struct dt_device_node *node)
{
    unsigned long p2m_pages;
    uint32_t p2m_mem_mb;
    int rc;

    rc = dt_property_read_u32(node, "xen,domain-p2m-mem-mb", &p2m_mem_mb);
    /* If xen,domain-p2m-mem-mb is not specified, use the default value. */
    p2m_pages = rc ?
                p2m_mem_mb << (20 - PAGE_SHIFT) :
                domain_p2m_pages(mem, d->max_vcpus);

    spin_lock(&d->arch.paging.lock);
    rc = p2m_set_allocation(d, p2m_pages, NULL);
    spin_unlock(&d->arch.paging.lock);

    return rc;
}
#else /* !CONFIG_ARCH_PAGING_MEMPOOL */
static inline int __init domain_p2m_set_allocation(
    struct domain *d, uint64_t mem, const struct dt_device_node *node)
{
    return 0;
}
#endif /* CONFIG_ARCH_PAGING_MEMPOOL */

static int __init construct_domU(struct domain *d,
                          const struct dt_device_node *node)
{
    struct kernel_info kinfo = KERNEL_INFO_INIT;
    const char *dom0less_enhanced;
    int rc;
    u64 mem;

    rc = dt_property_read_u64(node, "memory", &mem);
    if ( !rc )
    {
        printk("Error building DomU: cannot read \"memory\" property\n");
        return -EINVAL;
    }
    kinfo.unassigned_mem = (paddr_t)mem * SZ_1K;

    rc = domain_p2m_set_allocation(d, mem, node);
    if ( rc != 0 )
        return rc;

    printk("*** LOADING DOMU cpus=%u memory=%#"PRIx64"KB ***\n",
           d->max_vcpus, mem);

    rc = dt_property_read_string(node, "xen,enhanced", &dom0less_enhanced);
    if ( rc == -EILSEQ ||
         rc == -ENODATA ||
         (rc == 0 && !strcmp(dom0less_enhanced, "enabled")) )
    {
        need_xenstore = true;
        kinfo.dom0less_feature = DOM0LESS_ENHANCED;
    }
    else if ( rc == 0 && !strcmp(dom0less_enhanced, "legacy") )
    {
        need_xenstore = true;
        kinfo.dom0less_feature = DOM0LESS_ENHANCED_LEGACY;
    }
    else if ( rc == 0 && !strcmp(dom0less_enhanced, "no-xenstore") )
        kinfo.dom0less_feature = DOM0LESS_ENHANCED_NO_XS;

    if ( vcpu_create(d, 0) == NULL )
        return -ENOMEM;

    d->max_pages = ((paddr_t)mem * SZ_1K) >> PAGE_SHIFT;

    kinfo.bd.d = d;

    rc = kernel_probe(&kinfo, node);
    if ( rc < 0 )
        return rc;

    set_domain_type(d, &kinfo);

    if ( is_hardware_domain(d) )
    {
        rc = construct_hwdom(&kinfo, node);
        if ( rc < 0 )
            return rc;
    }
    else
    {
        if ( !dt_find_property(node, "xen,static-mem", NULL) )
            allocate_memory(d, &kinfo);
        else if ( !is_domain_direct_mapped(d) )
            allocate_static_memory(d, &kinfo, node);
        else
            assign_static_memory_11(d, &kinfo, node);

        rc = process_shm(d, &kinfo, node);
        if ( rc < 0 )
            return rc;

        rc = init_vuart(d, &kinfo, node);
        if ( rc < 0 )
            return rc;

        rc = prepare_dtb_domU(d, &kinfo);
        if ( rc < 0 )
            return rc;

        rc = construct_domain(d, &kinfo);
        if ( rc < 0 )
            return rc;
    }

    domain_vcpu_affinity(d, node);

    rc = alloc_xenstore_params(&kinfo);

    rangeset_destroy(kinfo.xen_reg_assigned);

    return rc;
}

void __init create_domUs(void)
{
    struct dt_device_node *node;
    const char *dom0less_iommu;
    bool iommu = false;
    const struct dt_device_node *cpupool_node,
                                *chosen = dt_find_node_by_path("/chosen");

    BUG_ON(chosen == NULL);
    dt_for_each_child_node(chosen, node)
    {
        const char *llc_colors_str = NULL;
        struct domain *d;
        struct xen_domctl_createdomain d_cfg = {0};
        unsigned int flags = 0U;
        bool has_dtb = false;
        uint32_t val;
        int rc;

        if ( !dt_device_is_compatible(node, "xen,domain") )
            continue;

        if ( (max_init_domid + 1) >= DOMID_FIRST_RESERVED )
            panic("No more domain IDs available\n");

        d_cfg.max_evtchn_port = 1023;
        d_cfg.max_grant_frames = -1;
        d_cfg.max_maptrack_frames = -1;
        d_cfg.grant_opts = XEN_DOMCTL_GRANT_version(opt_gnttab_max_version);

        if ( dt_property_read_u32(node, "capabilities", &val) )
        {
            if ( val & ~DOMAIN_CAPS_MASK )
                panic("Invalid capabilities (%"PRIx32")\n", val);

            if ( val & DOMAIN_CAPS_CONTROL )
                flags |= CDF_privileged;

            if ( val & DOMAIN_CAPS_HARDWARE )
            {
                if ( hardware_domain )
                    panic("Only 1 hardware domain can be specified! (%pd)\n",
                            hardware_domain);

#ifdef CONFIG_GRANT_TABLE
                d_cfg.max_grant_frames = gnttab_dom0_frames();
#endif
                d_cfg.max_evtchn_port = -1;
                flags |= CDF_hardware;
                iommu = true;
            }

            if ( val & DOMAIN_CAPS_XENSTORE )
            {
                d_cfg.flags |= XEN_DOMCTL_CDF_xs_domain;
                d_cfg.max_evtchn_port = -1;
            }
        }

        if ( dt_find_property(node, "xen,static-mem", NULL) )
        {
            if ( llc_coloring_enabled )
                panic("LLC coloring and static memory are incompatible\n");

            flags |= CDF_staticmem;
        }

        if ( dt_property_read_bool(node, "direct-map") )
        {
            if ( !(flags & CDF_staticmem) )
                panic("direct-map is not valid for domain %s without static allocation.\n",
                      dt_node_name(node));

            flags |= CDF_directmap;
        }

        if ( !dt_property_read_u32(node, "cpus", &d_cfg.max_vcpus) )
            panic("Missing property 'cpus' for domain %s\n",
                  dt_node_name(node));

        if ( !dt_property_read_string(node, "passthrough", &dom0less_iommu) )
        {
            if ( flags & CDF_hardware )
                panic("Don't specify passthrough for hardware domain\n");

            if ( !strcmp(dom0less_iommu, "enabled") )
                iommu = true;
        }

        if ( (flags & CDF_hardware) && !(flags & CDF_directmap) &&
             !iommu_enabled )
            panic("non-direct mapped hardware domain requires iommu\n");

        if ( dt_find_compatible_node(node, NULL, "multiboot,device-tree") )
        {
            if ( flags & CDF_hardware )
                panic("\"multiboot,device-tree\" incompatible with hardware domain\n");

            has_dtb = true;
        }

        if ( iommu_enabled && (iommu || has_dtb) )
            d_cfg.flags |= XEN_DOMCTL_CDF_iommu;

        /* Get the optional property domain-cpupool */
        cpupool_node = dt_parse_phandle(node, "domain-cpupool", 0);
        if ( cpupool_node )
        {
            int pool_id = btcpupools_get_domain_pool_id(cpupool_node);
            if ( pool_id < 0 )
                panic("Error getting cpupool id from domain-cpupool (%d)\n",
                      pool_id);
            d_cfg.cpupool_id = pool_id;
        }

        if ( dt_property_read_u32(node, "max_grant_version", &val) )
            d_cfg.grant_opts = XEN_DOMCTL_GRANT_version(val);

        if ( dt_property_read_u32(node, "max_grant_frames", &val) )
        {
            if ( val > INT32_MAX )
                panic("max_grant_frames (%"PRIu32") overflow\n", val);
            d_cfg.max_grant_frames = val;
        }

        if ( dt_property_read_u32(node, "max_maptrack_frames", &val) )
        {
            if ( val > INT32_MAX )
                panic("max_maptrack_frames (%"PRIu32") overflow\n", val);
            d_cfg.max_maptrack_frames = val;
        }

        dt_property_read_string(node, "llc-colors", &llc_colors_str);
        if ( !llc_coloring_enabled && llc_colors_str )
            panic("'llc-colors' found, but LLC coloring is disabled\n");

        arch_create_domUs(node, &d_cfg, flags);

        /*
         * The variable max_init_domid is initialized with zero, so here it's
         * very important to use the pre-increment operator to call
         * domain_create() with a domid > 0. (domid == 0 is reserved for Dom0)
         */
        d = domain_create(++max_init_domid, &d_cfg, flags);
        if ( IS_ERR(d) )
            panic("Error creating domain %s (rc = %ld)\n",
                  dt_node_name(node), PTR_ERR(d));

        if ( llc_coloring_enabled &&
             (rc = domain_set_llc_colors_from_str(d, llc_colors_str)) )
            panic("Error initializing LLC coloring for domain %s (rc = %d)\n",
                  dt_node_name(node), rc);

        d->is_console = true;
        dt_device_set_used_by(node, d->domain_id);

        rc = construct_domU(d, node);
        if ( rc )
            panic("Could not set up domain %s (rc = %d)\n",
                  dt_node_name(node), rc);

        if ( d_cfg.flags & XEN_DOMCTL_CDF_xs_domain )
            set_xs_domain(d);
    }

    if ( need_xenstore && xs_domid == DOMID_INVALID )
        panic("xenstore requested, but xenstore domain not present\n");

    initialize_domU_xenstore();
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
