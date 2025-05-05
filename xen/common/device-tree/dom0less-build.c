/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bootfdt.h>
#include <xen/device_tree.h>
#include <xen/domain.h>
#include <xen/err.h>
#include <xen/event.h>
#include <xen/grant_table.h>
#include <xen/init.h>
#include <xen/iommu.h>
#include <xen/llc-coloring.h>
#include <xen/sched.h>
#include <xen/stdbool.h>
#include <xen/types.h>

#include <public/bootfdt.h>
#include <public/domctl.h>
#include <public/event_channel.h>

#include <asm/dom0less-build.h>
#include <asm/setup.h>

static domid_t __initdata xs_domid = DOMID_INVALID;

void __init set_xs_domain(struct domain *d)
{
    xs_domid = d->domain_id;
    set_global_virq_handler(d, VIRQ_DOM_EXC);
}

bool __init is_dom0less_mode(void)
{
    struct bootmodules *mods = &bootinfo.modules;
    struct bootmodule *mod;
    unsigned int i;
    bool dom0found = false;
    bool domUfound = false;

    /* Look into the bootmodules */
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

void __init create_domUs(void)
{
    struct dt_device_node *node;
    const char *dom0less_iommu;
    bool iommu = false;
    const struct dt_device_node *cpupool_node,
                                *chosen = dt_find_node_by_path("/chosen");
    const char *llc_colors_str = NULL;

    BUG_ON(chosen == NULL);
    dt_for_each_child_node(chosen, node)
    {
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
                if ( xs_domid != DOMID_INVALID )
                    panic("Only 1 xenstore domain can be specified! (%u)\n",
                            xs_domid);

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
