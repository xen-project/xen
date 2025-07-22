/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bootfdt.h>
#include <xen/device_tree.h>
#include <xen/dom0less-build.h>
#include <xen/domain.h>
#include <xen/grant_table.h>
#include <xen/llc-coloring.h>
#include <xen/sched.h>

#include <public/bootfdt.h>
#include <public/domctl.h>

int __init parse_dom0less_node(struct dt_device_node *node,
                               struct boot_domain *bd)
{
    struct xen_domctl_createdomain *d_cfg = &bd->create_cfg;
    unsigned int *flags = &bd->create_flags;
    struct dt_device_node *cpupool_node;
    uint32_t val;
    bool has_dtb = false;
    bool iommu = false;
    const char *dom0less_iommu = NULL;

    if ( !dt_device_is_compatible(node, "xen,domain") )
        return -ENOENT;

    *flags = 0;
    *d_cfg = (struct xen_domctl_createdomain){
        .max_evtchn_port = 1023,
        .max_grant_frames = -1,
        .max_maptrack_frames = -1,
        .grant_opts = XEN_DOMCTL_GRANT_version(opt_gnttab_max_version),
    };

    if ( dt_property_read_u32(node, "capabilities", &val) )
    {
        if ( val & ~DOMAIN_CAPS_MASK )
            panic("Invalid capabilities (%"PRIx32")\n", val);

        if ( val & DOMAIN_CAPS_CONTROL )
            *flags |= CDF_privileged;

        if ( val & DOMAIN_CAPS_HARDWARE )
        {
            if ( hardware_domain )
                panic("Only 1 hardware domain can be specified! (%pd)\n",
                        hardware_domain);

#ifdef CONFIG_GRANT_TABLE
            d_cfg->max_grant_frames = gnttab_dom0_frames();
#endif
            d_cfg->max_evtchn_port = -1;
            *flags |= CDF_hardware;
            iommu = true;
        }

        if ( val & DOMAIN_CAPS_XENSTORE )
        {
            d_cfg->flags |= XEN_DOMCTL_CDF_xs_domain;
            d_cfg->max_evtchn_port = -1;
        }
    }

    if ( dt_find_property(node, "xen,static-mem", NULL) )
    {
        if ( llc_coloring_enabled )
            panic("LLC coloring and static memory are incompatible\n");

        *flags |= CDF_staticmem;
    }

    if ( dt_property_read_bool(node, "direct-map") )
    {
        if ( !(*flags & CDF_staticmem) )
            panic("direct-map is not valid for domain %s without static allocation.\n",
                  dt_node_name(node));

        *flags |= CDF_directmap;
    }

    if ( !dt_property_read_u32(node, "cpus", &d_cfg->max_vcpus) )
        panic("Missing property 'cpus' for domain %s\n",
              dt_node_name(node));

    if ( !dt_property_read_string(node, "passthrough", &dom0less_iommu) )
    {
        if ( *flags & CDF_hardware )
            panic("Don't specify passthrough for hardware domain\n");

        if ( !strcmp(dom0less_iommu, "enabled") )
            iommu = true;
    }

    if ( (*flags & CDF_hardware) && !(*flags & CDF_directmap) &&
         !iommu_enabled )
        panic("non-direct mapped hardware domain requires iommu\n");

    if ( dt_find_compatible_node(node, NULL, "multiboot,device-tree") )
    {
        if ( *flags & CDF_hardware )
            panic("\"multiboot,device-tree\" incompatible with hardware domain\n");

        has_dtb = true;
    }

    if ( iommu_enabled && (iommu || has_dtb) )
        d_cfg->flags |= XEN_DOMCTL_CDF_iommu;

    /* Get the optional property domain-cpupool */
    cpupool_node = dt_parse_phandle(node, "domain-cpupool", 0);
    if ( cpupool_node )
    {
        int pool_id = btcpupools_get_domain_pool_id(cpupool_node);
        if ( pool_id < 0 )
            panic("Error getting cpupool id from domain-cpupool (%d)\n",
                  pool_id);
        d_cfg->cpupool_id = pool_id;
    }

    if ( dt_property_read_u32(node, "max_grant_version", &val) )
        d_cfg->grant_opts = XEN_DOMCTL_GRANT_version(val);

    if ( dt_property_read_u32(node, "max_grant_frames", &val) )
    {
        if ( val > INT32_MAX )
            panic("max_grant_frames (%"PRIu32") overflow\n", val);
        d_cfg->max_grant_frames = val;
    }

    if ( dt_property_read_u32(node, "max_maptrack_frames", &val) )
    {
        if ( val > INT32_MAX )
            panic("max_maptrack_frames (%"PRIu32") overflow\n", val);
        d_cfg->max_maptrack_frames = val;
    }

#ifdef CONFIG_HAS_LLC_COLORING
    dt_property_read_string(node, "llc-colors", &bd->llc_colors_str);
    if ( !llc_coloring_enabled && bd->llc_colors_str )
        panic("'llc-colors' found, but LLC coloring is disabled\n");
#endif

    return arch_parse_dom0less_node(node, bd);
}
