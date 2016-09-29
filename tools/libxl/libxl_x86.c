#include "libxl_internal.h"
#include "libxl_arch.h"

#include <xc_dom.h>

int libxl__arch_domain_prepare_config(libxl__gc *gc,
                                      libxl_domain_config *d_config,
                                      xc_domain_configuration_t *xc_config)
{

    if (d_config->c_info.type == LIBXL_DOMAIN_TYPE_HVM) {
        if (d_config->b_info.device_model_version !=
            LIBXL_DEVICE_MODEL_VERSION_NONE) {
            xc_config->emulation_flags = XEN_X86_EMU_ALL;
        } else if (libxl_defbool_val(d_config->b_info.u.hvm.apic)) {
            /*
             * HVM guests without device model may want
             * to have LAPIC emulation.
             */
            xc_config->emulation_flags = XEN_X86_EMU_LAPIC;
        }
    } else {
        xc_config->emulation_flags = 0;
    }

    return 0;
}

int libxl__arch_domain_save_config(libxl__gc *gc,
                                   libxl_domain_config *d_config,
                                   const xc_domain_configuration_t *xc_config)
{
    return 0;
}

static const char *e820_names(int type)
{
    switch (type) {
        case E820_RAM: return "RAM";
        case E820_RESERVED: return "Reserved";
        case E820_ACPI: return "ACPI";
        case E820_NVS: return "ACPI NVS";
        case E820_UNUSABLE: return "Unusable";
        default: break;
    }
    return "Unknown";
}

static int e820_sanitize(libxl__gc *gc, struct e820entry src[],
                         uint32_t *nr_entries,
                         unsigned long map_limitkb,
                         unsigned long balloon_kb)
{
    uint64_t delta_kb = 0, start = 0, start_kb = 0, last = 0, ram_end;
    uint32_t i, idx = 0, nr;
    struct e820entry e820[E820MAX];

    if (!src || !map_limitkb || !nr_entries)
        return ERROR_INVAL;

    nr = *nr_entries;
    if (!nr)
        return ERROR_INVAL;

    if (nr > E820MAX)
        return ERROR_NOMEM;

    /* Weed out anything under 1MB */
    for (i = 0; i < nr; i++) {
        if (src[i].addr > 0x100000)
            continue;

        src[i].type = 0;
        src[i].size = 0;
        src[i].addr = -1ULL;
    }

    /* Find the lowest and highest entry in E820, skipping over
     * undesired entries. */
    start = -1ULL;
    last = 0;
    for (i = 0; i < nr; i++) {
        if ((src[i].type == E820_RAM) ||
            (src[i].type == E820_UNUSABLE) ||
            (src[i].type == 0))
            continue;

        start = src[i].addr < start ? src[i].addr : start;
        last = src[i].addr + src[i].size > last ?
               src[i].addr + src[i].size > last : last;
    }
    if (start > 1024)
        start_kb = start >> 10;

    /* Add the memory RAM region for the guest */
    e820[idx].addr = 0;
    e820[idx].size = (uint64_t)map_limitkb << 10;
    e820[idx].type = E820_RAM;

    /* .. and trim if neccessary */
    if (start_kb && map_limitkb > start_kb) {
        delta_kb = map_limitkb - start_kb;
        if (delta_kb)
            e820[idx].size -= (uint64_t)(delta_kb << 10);
    }
    /* Note: We don't touch balloon_kb here. Will add it at the end. */
    ram_end = e820[idx].addr + e820[idx].size;
    idx ++;

    LOG(DEBUG, "Memory: %"PRIu64"kB End of RAM: " \
        "0x%"PRIx64" (PFN) Delta: %"PRIu64"kB, PCI start: %"PRIu64"kB " \
        "(0x%"PRIx64" PFN), Balloon %"PRIu64"kB\n", (uint64_t)map_limitkb,
        ram_end >> 12, delta_kb, start_kb ,start >> 12,
        (uint64_t)balloon_kb);


    /* This whole code below is to guard against if the Intel IGD is passed into
     * the guest. If we don't pass in IGD, this whole code can be ignored.
     *
     * The reason for this code is that Intel boxes fill their E820 with
     * E820_RAM amongst E820_RESERVED and we can't just ditch those E820_RAM.
     * That is b/c any "gaps" in the E820 is considered PCI I/O space by
     * Linux and it would be utilized by the Intel IGD as I/O space while
     * in reality it was an RAM region.
     *
     * What this means is that we have to walk the E820 and for any region
     * that is RAM and below 4GB and above ram_end, needs to change its type
     * to E820_UNUSED. We also need to move some of the E820_RAM regions if
     * the overlap with ram_end. */
    for (i = 0; i < nr; i++) {
        uint64_t end = src[i].addr + src[i].size;

        /* We don't care about E820_UNUSABLE, but we need to
         * change the type to zero b/c the loop after this
         * sticks E820_UNUSABLE on the guest's E820 but ignores
         * the ones with type zero. */
        if ((src[i].type == E820_UNUSABLE) ||
            /* Any region that is within the "RAM region" can
             * be safely ditched. */
            (end < ram_end)) {
                src[i].type = 0;
                continue;
        }

        /* Look only at RAM regions. */
        if (src[i].type != E820_RAM)
            continue;

        /* We only care about RAM regions below 4GB. */
        if (src[i].addr >= (1ULL<<32))
            continue;

        /* E820_RAM overlaps with our RAM region. Move it */
        if (src[i].addr < ram_end) {
            uint64_t delta;

            src[i].type = E820_UNUSABLE;
            delta = ram_end - src[i].addr;
            /* The end < ram_end should weed this out */
            if (src[i].size < delta)
                src[i].type = 0;
            else {
                src[i].size -= delta;
                src[i].addr = ram_end;
            }
            if (src[i].addr + src[i].size != end) {
                /* We messed up somewhere */
                src[i].type = 0;
                LOGE(ERROR, "Computed E820 wrongly. Continuing on.");
            }
        }
        /* Lastly, convert the RAM to UNSUABLE. Look in the Linux kernel
           at git commit 2f14ddc3a7146ea4cd5a3d1ecd993f85f2e4f948
            "xen/setup: Inhibit resource API from using System RAM E820
           gaps as PCI mem gaps" for full explanation. */
        if (end > ram_end)
            src[i].type = E820_UNUSABLE;
    }

    /* Check if there is a region between ram_end and start. */
    if (start > ram_end) {
        int add_unusable = 1;
        for (i = 0; i < nr && add_unusable; i++) {
            if (src[i].type != E820_UNUSABLE)
                continue;
            if (ram_end != src[i].addr)
                continue;
            if (start != src[i].addr + src[i].size) {
                /* there is one, adjust it */
                src[i].size = start - src[i].addr;
            }
            add_unusable = 0;
        }
        /* .. and if not present, add it in. This is to guard against
           the Linux guest assuming that the gap between the end of
           RAM region and the start of the E820_[ACPI,NVS,RESERVED]
           is PCI I/O space. Which it certainly is _not_. */
        if (add_unusable) {
            e820[idx].type = E820_UNUSABLE;
            e820[idx].addr = ram_end;
            e820[idx].size = start - ram_end;
            idx++;
        }
    }
    /* Almost done: copy them over, ignoring the undesireable ones */
    for (i = 0; i < nr; i++) {
        if ((src[i].type == E820_RAM) ||
            (src[i].type == 0))
            continue;

        e820[idx].type = src[i].type;
        e820[idx].addr = src[i].addr;
        e820[idx].size = src[i].size;
        idx++;
    }
    /* At this point we have the mapped RAM + E820 entries from src. */
    if (balloon_kb || delta_kb) {
        /* and if we truncated the RAM region, then add it to the end. */
        e820[idx].type = E820_RAM;
        e820[idx].addr = (uint64_t)(1ULL << 32) > last ?
                         (uint64_t)(1ULL << 32) : last;
        /* also add the balloon memory to the end. */
        e820[idx].size = (uint64_t)(delta_kb << 10) +
                         (uint64_t)(balloon_kb << 10);
        idx++;

    }
    nr = idx;

    for (i = 0; i < nr; i++) {
      LOG(DEBUG, ":\t[%"PRIx64" -> %"PRIx64"] %s", e820[i].addr >> 12,
          (e820[i].addr + e820[i].size) >> 12, e820_names(e820[i].type));
    }

    /* Done: copy the sanitized version. */
    *nr_entries = nr;
    memcpy(src, e820, nr * sizeof(struct e820entry));
    return 0;
}

static int e820_host_sanitize(libxl__gc *gc,
                              libxl_domain_build_info *b_info,
                              struct e820entry map[],
                              uint32_t *nr)
{
    int rc;

    rc = xc_get_machine_memory_map(CTX->xch, map, *nr);
    if (rc < 0)
        return ERROR_FAIL;

    *nr = rc;

    rc = e820_sanitize(gc, map, nr, b_info->target_memkb,
                       (b_info->max_memkb - b_info->target_memkb) +
                       b_info->u.pv.slack_memkb);
    return rc;
}

static int libxl__e820_alloc(libxl__gc *gc, uint32_t domid,
        libxl_domain_config *d_config)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int rc;
    uint32_t nr;
    struct e820entry map[E820MAX];
    libxl_domain_build_info *b_info;

    if (d_config == NULL || d_config->c_info.type == LIBXL_DOMAIN_TYPE_HVM)
        return ERROR_INVAL;

    b_info = &d_config->b_info;
    if (!libxl_defbool_val(b_info->u.pv.e820_host))
        return ERROR_INVAL;

    nr = E820MAX;
    rc = e820_host_sanitize(gc, b_info, map, &nr);
    if (rc)
        return ERROR_FAIL;

    rc = xc_domain_set_memory_map(ctx->xch, domid, map, nr);

    if (rc < 0)
        return ERROR_FAIL;

    return 0;
}

int libxl__arch_domain_create(libxl__gc *gc, libxl_domain_config *d_config,
        uint32_t domid)
{
    int ret = 0;
    int tsc_mode;
    uint32_t rtc_timeoffset;
    libxl_ctx *ctx = libxl__gc_owner(gc);

    if (d_config->b_info.type == LIBXL_DOMAIN_TYPE_PV)
        xc_domain_set_memmap_limit(ctx->xch, domid,
                                   (d_config->b_info.max_memkb +
                                    d_config->b_info.u.pv.slack_memkb));

    switch (d_config->b_info.tsc_mode) {
    case LIBXL_TSC_MODE_DEFAULT:
        tsc_mode = 0;
        break;
    case LIBXL_TSC_MODE_ALWAYS_EMULATE:
        tsc_mode = 1;
        break;
    case LIBXL_TSC_MODE_NATIVE:
        tsc_mode = 2;
        break;
    case LIBXL_TSC_MODE_NATIVE_PARAVIRT:
        tsc_mode = 3;
        break;
    default:
        abort();
    }
    xc_domain_set_tsc_info(ctx->xch, domid, tsc_mode, 0, 0, 0);
    if (libxl_defbool_val(d_config->b_info.disable_migrate))
        xc_domain_disable_migrate(ctx->xch, domid);
    rtc_timeoffset = d_config->b_info.rtc_timeoffset;
    if (libxl_defbool_val(d_config->b_info.localtime)) {
        time_t t;
        struct tm *tm, result;

        t = time(NULL);
        tm = localtime_r(&t, &result);

        if (!tm) {
            LOGE(ERROR, "Failed to call localtime_r");
            ret = ERROR_FAIL;
            goto out;
        }

        rtc_timeoffset += tm->tm_gmtoff;
    }

    if (rtc_timeoffset)
        xc_domain_set_time_offset(ctx->xch, domid, rtc_timeoffset);

    if (d_config->b_info.type == LIBXL_DOMAIN_TYPE_HVM ||
        libxl_defbool_val(d_config->c_info.pvh)) {

        unsigned long shadow;
        shadow = (d_config->b_info.shadow_memkb + 1023) / 1024;
        xc_shadow_control(ctx->xch, domid, XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION, NULL, 0, &shadow, 0, NULL);
    }

    if (d_config->c_info.type == LIBXL_DOMAIN_TYPE_PV &&
            libxl_defbool_val(d_config->b_info.u.pv.e820_host)) {
        ret = libxl__e820_alloc(gc, domid, d_config);
        if (ret) {
            LOGE(ERROR, "Failed while collecting E820 with: %d (errno:%d)\n",
                 ret, errno);
        }
    }

out:
    return ret;
}

int libxl__arch_extra_memory(libxl__gc *gc,
                             const libxl_domain_build_info *info,
                             uint64_t *out)
{
    *out = LIBXL_MAXMEM_CONSTANT;

    return 0;
}

int libxl__arch_domain_init_hw_description(libxl__gc *gc,
                                           libxl_domain_build_info *info,
                                           libxl__domain_build_state *state,
                                           struct xc_dom_image *dom)
{
    return 0;
}

int libxl__arch_domain_finalise_hw_description(libxl__gc *gc,
                                               libxl_domain_build_info *info,
                                               struct xc_dom_image *dom)
{
    int rc = 0;

    if ((info->type == LIBXL_DOMAIN_TYPE_HVM) &&
        (info->device_model_version == LIBXL_DEVICE_MODEL_VERSION_NONE)) {
        rc = libxl__dom_load_acpi(gc, info, dom);
        if (rc != 0)
            LOGE(ERROR, "libxl_dom_load_acpi failed");
    }

    return rc;
}

/* Return 0 on success, ERROR_* on failure. */
int libxl__arch_vnuma_build_vmemrange(libxl__gc *gc,
                                      uint32_t domid,
                                      libxl_domain_build_info *b_info,
                                      libxl__domain_build_state *state)
{
    int nid, nr_vmemrange, rc;
    uint32_t nr_e820, e820_count;
    struct e820entry map[E820MAX];
    xen_vmemrange_t *vmemranges;
    unsigned int array_size;

    /* If e820_host is not set, call the generic function */
    if (!(b_info->type == LIBXL_DOMAIN_TYPE_PV &&
          libxl_defbool_val(b_info->u.pv.e820_host)))
        return libxl__vnuma_build_vmemrange_pv_generic(gc, domid, b_info,
                                                       state);

    assert(state->vmemranges == NULL);

    nr_e820 = E820MAX;
    rc = e820_host_sanitize(gc, b_info, map, &nr_e820);
    if (rc) goto out;

    e820_count = 0;
    nr_vmemrange = 0;
    vmemranges = NULL;
    array_size = 0;
    for (nid = 0; nid < b_info->num_vnuma_nodes; nid++) {
        libxl_vnode_info *p = &b_info->vnuma_nodes[nid];
        uint64_t remaining_bytes = (p->memkb << 10), bytes;

        while (remaining_bytes > 0) {
            if (e820_count >= nr_e820) {
                rc = ERROR_NOMEM;
                goto out;
            }

            /* Skip non RAM region */
            if (map[e820_count].type != E820_RAM) {
                e820_count++;
                continue;
            }

            if (nr_vmemrange >= array_size) {
                array_size += 32;
                GCREALLOC_ARRAY(vmemranges, array_size);
            }

            bytes = map[e820_count].size >= remaining_bytes ?
                remaining_bytes : map[e820_count].size;

            vmemranges[nr_vmemrange].start = map[e820_count].addr;
            vmemranges[nr_vmemrange].end = map[e820_count].addr + bytes;

            if (map[e820_count].size >= remaining_bytes) {
                map[e820_count].addr += bytes;
                map[e820_count].size -= bytes;
            } else {
                e820_count++;
            }

            remaining_bytes -= bytes;

            vmemranges[nr_vmemrange].flags = 0;
            vmemranges[nr_vmemrange].nid = nid;
            nr_vmemrange++;
        }
    }

    state->vmemranges = vmemranges;
    state->num_vmemranges = nr_vmemrange;

    rc = 0;
out:
    return rc;
}

int libxl__arch_domain_map_irq(libxl__gc *gc, uint32_t domid, int irq)
{
    int ret;

    ret = xc_physdev_map_pirq(CTX->xch, domid, irq, &irq);
    if (ret)
        return ret;

    ret = xc_domain_irq_permission(CTX->xch, domid, irq, 1);

    return ret;
}

/*
 * Here we're just trying to set these kinds of e820 mappings:
 *
 * #1. Low memory region
 *
 * Low RAM starts at least from 1M to make sure all standard regions
 * of the PC memory map, like BIOS, VGA memory-mapped I/O and vgabios,
 * have enough space.
 * Note: Those stuffs below 1M are still constructed with multiple
 * e820 entries by hvmloader. At this point we don't change anything.
 *
 * #2. RDM region if it exists
 *
 * #3. High memory region if it exists
 *
 * Note: these regions are not overlapping since we already check
 * to adjust them. Please refer to libxl__domain_device_construct_rdm().
 */
#define GUEST_LOW_MEM_START_DEFAULT 0x100000
int libxl__arch_domain_construct_memmap(libxl__gc *gc,
                                        libxl_domain_config *d_config,
                                        uint32_t domid,
                                        struct xc_dom_image *dom)
{
    int rc = 0;
    unsigned int nr = 0, i;
    /* We always own at least one lowmem entry. */
    unsigned int e820_entries = 1;
    struct e820entry *e820 = NULL;
    uint64_t highmem_size =
                    dom->highmem_end ? dom->highmem_end - (1ull << 32) : 0;
    uint32_t lowmem_start = dom->device_model ? GUEST_LOW_MEM_START_DEFAULT : 0;
    unsigned page_size = XC_DOM_PAGE_SIZE(dom);

    /* Add all rdm entries. */
    for (i = 0; i < d_config->num_rdms; i++)
        if (d_config->rdms[i].policy != LIBXL_RDM_RESERVE_POLICY_INVALID)
            e820_entries++;


    /* If we should have a highmem range. */
    if (highmem_size)
        e820_entries++;

    for (i = 0; i < MAX_ACPI_MODULES; i++)
        if (dom->acpi_modules[i].length)
            e820_entries++;

    if (e820_entries >= E820MAX) {
        LOG(ERROR, "Ooops! Too many entries in the memory map!");
        rc = ERROR_INVAL;
        goto out;
    }

    e820 = libxl__malloc(gc, sizeof(struct e820entry) * e820_entries);

    /* Low memory */
    e820[nr].addr = lowmem_start;
    e820[nr].size = dom->lowmem_end - lowmem_start;
    e820[nr].type = E820_RAM;
    nr++;

    /* RDM mapping */
    for (i = 0; i < d_config->num_rdms; i++) {
        if (d_config->rdms[i].policy == LIBXL_RDM_RESERVE_POLICY_INVALID)
            continue;

        e820[nr].addr = d_config->rdms[i].start;
        e820[nr].size = d_config->rdms[i].size;
        e820[nr].type = E820_RESERVED;
        nr++;
    }

    for (i = 0; i < MAX_ACPI_MODULES; i++) {
        if (dom->acpi_modules[i].length) {
            e820[nr].addr = dom->acpi_modules[i].guest_addr_out & ~(page_size - 1);
            e820[nr].size = dom->acpi_modules[i].length +
                (dom->acpi_modules[i].guest_addr_out & (page_size - 1));
            e820[nr].type = E820_ACPI;
            nr++;
        }
    }

    /* High memory */
    if (highmem_size) {
        e820[nr].addr = ((uint64_t)1 << 32);
        e820[nr].size = highmem_size;
        e820[nr].type = E820_RAM;
    }

    if (xc_domain_set_memory_map(CTX->xch, domid, e820, e820_entries) != 0) {
        rc = ERROR_FAIL;
        goto out;
    }

out:
    return rc;
}

void libxl__arch_domain_build_info_acpi_setdefault(
                                        libxl_domain_build_info *b_info)
{
    libxl_defbool_setdefault(&b_info->acpi, true);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
