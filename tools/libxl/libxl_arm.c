#include "libxl_internal.h"
#include "libxl_arch.h"

#include <xc_dom.h>
#include <stdbool.h>
#include <libfdt.h>
#include <assert.h>

/**
 * IRQ line type.
 * DT_IRQ_TYPE_NONE            - default, unspecified type
 * DT_IRQ_TYPE_EDGE_RISING     - rising edge triggered
 * DT_IRQ_TYPE_EDGE_FALLING    - falling edge triggered
 * DT_IRQ_TYPE_EDGE_BOTH       - rising and falling edge triggered
 * DT_IRQ_TYPE_LEVEL_HIGH      - high level triggered
 * DT_IRQ_TYPE_LEVEL_LOW       - low level triggered
 */
#define DT_IRQ_TYPE_NONE           0x00000000
#define DT_IRQ_TYPE_EDGE_RISING    0x00000001
#define DT_IRQ_TYPE_EDGE_FALLING   0x00000002
#define DT_IRQ_TYPE_EDGE_BOTH                           \
    (DT_IRQ_TYPE_EDGE_FALLING | DT_IRQ_TYPE_EDGE_RISING)
#define DT_IRQ_TYPE_LEVEL_HIGH     0x00000004
#define DT_IRQ_TYPE_LEVEL_LOW      0x00000008

static const char *gicv_to_string(uint8_t gic_version)
{
    switch (gic_version) {
    case XEN_DOMCTL_CONFIG_GIC_V2:
        return "V2";
    case XEN_DOMCTL_CONFIG_GIC_V3:
        return "V3";
    default:
        return "unknown";
    }
}

int libxl__arch_domain_create(libxl__gc *gc, libxl_domain_config *d_config,
                              uint32_t domid)
{
    return 0;
}

static struct arch_info {
    const char *guest_type;
    const char *timer_compat;
    const char *cpu_compat;
} arch_info[] = {
    {"xen-3.0-armv7l",  "arm,armv7-timer", "arm,cortex-a15" },
    {"xen-3.0-aarch64", "arm,armv8-timer", "arm,armv8" },
};

enum {
    PHANDLE_NONE = 0,
    PHANDLE_GIC,
};

typedef uint32_t be32;
typedef be32 gic_interrupt[3];

#define ROOT_ADDRESS_CELLS 2
#define ROOT_SIZE_CELLS 2

#define PROP_INITRD_START "linux,initrd-start"
#define PROP_INITRD_END "linux,initrd-end"

static void set_cell(be32 **cellp, int size, uint64_t val)
{
    int cells = size;

    while (size--) {
        (*cellp)[size] = cpu_to_fdt32(val);
        val >>= 32;
    }

    (*cellp) += cells;
}

static void set_interrupt(gic_interrupt interrupt, unsigned int irq,
                          unsigned int cpumask, unsigned int level)
{
    be32 *cells = interrupt;
    int is_ppi = (irq < 32);

    /* SGIs are not describe in the device tree */
    assert(irq >= 16);

    irq -= (is_ppi) ? 16: 32; /* PPIs start at 16, SPIs at 32 */

    /* See linux Documentation/devictree/bindings/arm/gic.txt */
    set_cell(&cells, 1, is_ppi); /* is a PPI? */
    set_cell(&cells, 1, irq);
    set_cell(&cells, 1, (cpumask << 8) | level);
}

static void set_range(be32 **cellp,
                      int address_cells, int size_cells,
                      uint64_t address, uint64_t size)
{
    set_cell(cellp, address_cells, address);
    set_cell(cellp, size_cells, size);
}

static int fdt_property_compat(libxl__gc *gc, void *fdt, unsigned nr_compat, ...)
{
    const char *compats[nr_compat];
    int i;
    size_t sz;
    va_list ap;
    char *compat, *p;

    va_start(ap, nr_compat);
    sz = 0;
    for (i = 0; i < nr_compat; i++) {
        const char *c = va_arg(ap, const char *);
        compats[i] = c;
        sz += strlen(compats[i]) + 1;
    }
    va_end(ap);

    p = compat = libxl__zalloc(gc, sz);
    for (i = 0; i < nr_compat; i++) {
        strcpy(p, compats[i]);
        p += strlen(compats[i]) + 1;
    }

    return fdt_property(fdt, "compatible", compat, sz);
}

static int fdt_property_interrupts(libxl__gc *gc, void *fdt,
                                   gic_interrupt *intr,
                                   unsigned num_irq)
{
    int res;

    res = fdt_property(fdt, "interrupts", intr, sizeof (intr[0]) * num_irq);
    if (res) return res;

    res = fdt_property_cell(fdt, "interrupt-parent", PHANDLE_GIC);
    if (res) return res;

    return 0;
}

static int fdt_property_regs(libxl__gc *gc, void *fdt,
                             unsigned addr_cells,
                             unsigned size_cells,
                             unsigned num_regs, ...)
{
    uint32_t regs[num_regs*(addr_cells+size_cells)];
    be32 *cells = &regs[0];
    int i;
    va_list ap;
    uint64_t base, size;

    va_start(ap, num_regs);
    for (i = 0 ; i < num_regs; i++) {
        base = addr_cells ? va_arg(ap, uint64_t) : 0;
        size = size_cells ? va_arg(ap, uint64_t) : 0;
        set_range(&cells, addr_cells, size_cells, base, size);
    }
    va_end(ap);

    return fdt_property(fdt, "reg", regs, sizeof(regs));
}

static int make_root_properties(libxl__gc *gc,
                                const libxl_version_info *vers,
                                void *fdt)
{
    int res;

    res = fdt_property_string(fdt, "model", GCSPRINTF("XENVM-%d.%d",
                                                      vers->xen_version_major,
                                                      vers->xen_version_minor));
    if (res) return res;

    res = fdt_property_compat(gc, fdt, 2,
                              GCSPRINTF("xen,xenvm-%d.%d",
                                        vers->xen_version_major,
                                        vers->xen_version_minor),
                              "xen,xenvm");
    if (res) return res;

    res = fdt_property_cell(fdt, "interrupt-parent", PHANDLE_GIC);
    if (res) return res;

    res = fdt_property_cell(fdt, "#address-cells", ROOT_ADDRESS_CELLS);
    if (res) return res;

    res = fdt_property_cell(fdt, "#size-cells", ROOT_SIZE_CELLS);
    if (res) return res;

    return 0;
}

static int make_chosen_node(libxl__gc *gc, void *fdt, bool ramdisk,
                            const libxl_domain_build_info *info)
{
    int res;

    /* See linux Documentation/devicetree/... */
    res = fdt_begin_node(fdt, "chosen");
    if (res) return res;

    if (info->cmdline) {
        res = fdt_property_string(fdt, "bootargs", info->cmdline);
        if (res) return res;
    }

    if (ramdisk) {
        uint64_t dummy = 0;
        LOG(DEBUG, "/chosen adding placeholder linux,initrd properties");
        res = fdt_property(fdt, PROP_INITRD_START, &dummy, sizeof(dummy));
        if (res) return res;
        res = fdt_property(fdt, PROP_INITRD_END, &dummy, sizeof(dummy));
        if (res) return res;
    }

    res = fdt_end_node(fdt);
    if (res) return res;

    return 0;
}

static int make_cpus_node(libxl__gc *gc, void *fdt, int nr_cpus,
                          const struct arch_info *ainfo)
{
    int res, i;

    res = fdt_begin_node(fdt, "cpus");
    if (res) return res;

    res = fdt_property_cell(fdt, "#address-cells", 1);
    if (res) return res;

    res = fdt_property_cell(fdt, "#size-cells", 0);
    if (res) return res;

    for (i = 0; i < nr_cpus; i++) {
        const char *name = GCSPRINTF("cpu@%d", i);

        res = fdt_begin_node(fdt, name);
        if (res) return res;

        res = fdt_property_string(fdt, "device_type", "cpu");
        if (res) return res;

        res = fdt_property_compat(gc, fdt, 1, ainfo->cpu_compat);
        if (res) return res;

        res = fdt_property_string(fdt, "enable-method", "psci");
        if (res) return res;

        res = fdt_property_regs(gc, fdt, 1, 0, 1, (uint64_t)i);
        if (res) return res;

        res = fdt_end_node(fdt);
        if (res) return res;
    }

    res = fdt_end_node(fdt);
    if (res) return res;

    return 0;
}

static int make_psci_node(libxl__gc *gc, void *fdt)
{
    int res;

    res = fdt_begin_node(fdt, "psci");
    if (res) return res;

    res = fdt_property_compat(gc, fdt, 2, "arm,psci-0.2","arm,psci");
    if (res) return res;

    res = fdt_property_string(fdt, "method", "hvc");
    if (res) return res;

    res = fdt_property_cell(fdt, "cpu_off", PSCI_cpu_off);
    if (res) return res;

    res = fdt_property_cell(fdt, "cpu_on", PSCI_cpu_on);
    if (res) return res;

    res = fdt_end_node(fdt);
    if (res) return res;

    return 0;
}

static int make_memory_nodes(libxl__gc *gc, void *fdt,
                             const struct xc_dom_image *dom)
{
    int res, i;
    const char *name;
    const uint64_t bankbase[] = GUEST_RAM_BANK_BASES;

    for (i = 0; i < GUEST_RAM_BANKS; i++) {
        name = GCSPRINTF("memory@%"PRIx64, bankbase[i]);

        LOG(DEBUG, "Creating placeholder node /%s", name);

        res = fdt_begin_node(fdt, name);
        if (res) return res;

        res = fdt_property_string(fdt, "device_type", "memory");
        if (res) return res;

        res = fdt_property_regs(gc, fdt, ROOT_ADDRESS_CELLS, ROOT_SIZE_CELLS,
                                1, 0, 0);
        if (res) return res;

        res = fdt_end_node(fdt);
        if (res) return res;
    }

    return 0;
}

static int make_gicv2_node(libxl__gc *gc, void *fdt,
                           uint64_t gicd_base, uint64_t gicd_size,
                           uint64_t gicc_base, uint64_t gicc_size)
{
    int res;
    const char *name = GCSPRINTF("interrupt-controller@%"PRIx64, gicd_base);

    res = fdt_begin_node(fdt, name);
    if (res) return res;

    res = fdt_property_compat(gc, fdt, 2,
                              "arm,cortex-a15-gic",
                              "arm,cortex-a9-gic");
    if (res) return res;


    res = fdt_property_cell(fdt, "#interrupt-cells", 3);
    if (res) return res;

    res = fdt_property_cell(fdt, "#address-cells", 0);
    if (res) return res;

    res = fdt_property(fdt, "interrupt-controller", NULL, 0);
    if (res) return res;

    res = fdt_property_regs(gc, fdt, ROOT_ADDRESS_CELLS, ROOT_SIZE_CELLS,
                            2,
                            gicd_base, gicd_size,
                            gicc_base, gicc_size);
    if (res) return res;

    res = fdt_property_cell(fdt, "linux,phandle", PHANDLE_GIC);
    if (res) return res;

    res = fdt_property_cell(fdt, "phandle", PHANDLE_GIC);
    if (res) return res;

    res = fdt_end_node(fdt);
    if (res) return res;

    return 0;
}

static int make_gicv3_node(libxl__gc *gc, void *fdt)
{
    int res;
    const uint64_t gicd_base = GUEST_GICV3_GICD_BASE;
    const uint64_t gicd_size = GUEST_GICV3_GICD_SIZE;
    const uint64_t gicr0_base = GUEST_GICV3_GICR0_BASE;
    const uint64_t gicr0_size = GUEST_GICV3_GICR0_SIZE;
    const char *name = GCSPRINTF("interrupt-controller@%"PRIx64, gicd_base);

    res = fdt_begin_node(fdt, name);
    if (res) return res;

    res = fdt_property_compat(gc, fdt, 1, "arm,gic-v3");
    if (res) return res;

    res = fdt_property_cell(fdt, "#interrupt-cells", 3);
    if (res) return res;

    res = fdt_property_cell(fdt, "#address-cells", 0);
    if (res) return res;

    res = fdt_property(fdt, "interrupt-controller", NULL, 0);
    if (res) return res;

    res = fdt_property_cell(fdt, "redistributor-stride",
                            GUEST_GICV3_RDIST_STRIDE);
    if (res) return res;

    res = fdt_property_cell(fdt, "#redistributor-regions",
                            GUEST_GICV3_RDIST_REGIONS);
    if (res) return res;

    res = fdt_property_regs(gc, fdt, ROOT_ADDRESS_CELLS, ROOT_SIZE_CELLS,
                            2,
                            gicd_base, gicd_size,
                            gicr0_base, gicr0_size);
    if (res) return res;

    res = fdt_property_cell(fdt, "linux,phandle", PHANDLE_GIC);
    if (res) return res;

    res = fdt_property_cell(fdt, "phandle", PHANDLE_GIC);
    if (res) return res;

    res = fdt_end_node(fdt);
    if (res) return res;

    return 0;
}

static int make_timer_node(libxl__gc *gc, void *fdt, const struct arch_info *ainfo)
{
    int res;
    gic_interrupt ints[3];

    res = fdt_begin_node(fdt, "timer");
    if (res) return res;

    res = fdt_property_compat(gc, fdt, 1, ainfo->timer_compat);
    if (res) return res;

    set_interrupt(ints[0], GUEST_TIMER_PHYS_S_PPI, 0xf, DT_IRQ_TYPE_LEVEL_LOW);
    set_interrupt(ints[1], GUEST_TIMER_PHYS_NS_PPI, 0xf, DT_IRQ_TYPE_LEVEL_LOW);
    set_interrupt(ints[2], GUEST_TIMER_VIRT_PPI, 0xf, DT_IRQ_TYPE_LEVEL_LOW);

    res = fdt_property_interrupts(gc, fdt, ints, 3);
    if (res) return res;

    res = fdt_end_node(fdt);
    if (res) return res;

    return 0;
}

static int make_hypervisor_node(libxl__gc *gc, void *fdt,
                                const libxl_version_info *vers)
{
    int res;
    gic_interrupt intr;

    /* See linux Documentation/devicetree/bindings/arm/xen.txt */
    res = fdt_begin_node(fdt, "hypervisor");
    if (res) return res;

    res = fdt_property_compat(gc, fdt, 2,
                              GCSPRINTF("xen,xen-%d.%d",
                                        vers->xen_version_major,
                                        vers->xen_version_minor),
                              "xen,xen");
    if (res) return res;

    /* reg 0 is grant table space */
    res = fdt_property_regs(gc, fdt, ROOT_ADDRESS_CELLS, ROOT_SIZE_CELLS,
                            1,GUEST_GNTTAB_BASE, GUEST_GNTTAB_SIZE);
    if (res) return res;

    /*
     * interrupts is evtchn upcall:
     *  - Active-low level-sensitive
     *  - All cpus
     */
    set_interrupt(intr, GUEST_EVTCHN_PPI, 0xf, DT_IRQ_TYPE_LEVEL_LOW);

    res = fdt_property_interrupts(gc, fdt, &intr, 1);
    if (res) return res;

    res = fdt_end_node(fdt);
    if (res) return res;

    return 0;
}

static const struct arch_info *get_arch_info(libxl__gc *gc,
                                             const struct xc_dom_image *dom)
{
    int i;

    for (i=0; i < ARRAY_SIZE(arch_info); i++) {
        const struct arch_info *info = &arch_info[i];
        if (!strcmp(dom->guest_type, info->guest_type))
            return info;
    }
    LOG(ERROR, "Unable to find arch FDT info for %s\n", dom->guest_type);
    return NULL;
}

static void debug_dump_fdt(libxl__gc *gc, void *fdt)
{
    int fd = -1, rc, r;

    const char *dtb = getenv("LIBXL_DEBUG_DUMP_DTB");

    if (!dtb) goto out;

    fd = open(dtb, O_CREAT|O_TRUNC|O_WRONLY, 0666);
    if (fd < 0) {
        LOGE(DEBUG, "cannot open %s for LIBXL_DEBUG_DUMP_DTB", dtb);
        goto out;
    }

    rc = libxl_write_exactly(CTX, fd, fdt, fdt_totalsize(fdt), dtb, "dtb");
    if (rc < 0) goto out;

out:
    if (fd >= 0) {
        r = close(fd);
        if (r < 0) LOGE(DEBUG, "failed to close DTB debug dump output");
    }
}

#define FDT_MAX_SIZE (1<<20)

int libxl__arch_domain_init_hw_description(libxl__gc *gc,
                                           libxl_domain_build_info *info,
                                           struct xc_dom_image *dom)
{
    xc_domain_configuration_t config;
    void *fdt = NULL;
    int rc, res;
    size_t fdt_size = 0;

    const libxl_version_info *vers;
    const struct arch_info *ainfo;

    assert(info->type == LIBXL_DOMAIN_TYPE_PV);

    vers = libxl_get_version_info(CTX);
    if (vers == NULL) return ERROR_FAIL;

    ainfo = get_arch_info(gc, dom);
    if (ainfo == NULL) return ERROR_FAIL;

    LOG(DEBUG, "configure the domain");
    config.gic_version = XEN_DOMCTL_CONFIG_GIC_DEFAULT;
    if (xc_domain_configure(CTX->xch, dom->guest_domid, &config) != 0) {
        LOG(ERROR, "couldn't configure the domain");
        return ERROR_FAIL;
    }

    LOG(DEBUG, "constructing DTB for Xen version %d.%d guest",
        vers->xen_version_major, vers->xen_version_minor);
    LOG(DEBUG, "  - vGIC version: %s", gicv_to_string(config.gic_version));

/*
 * Call "call" handling FDR_ERR_*. Will either:
 * - loop back to retry_resize
 * - set rc and goto out
 * - fall through successfully
 *
 * On FDT_ERR_NOSPACE we start again from scratch rather than
 * realloc+libfdt_open_into because "call" may have failed half way
 * through a series of steps leaving the partial tree in an
 * inconsistent state, e.g. leaving a node open.
 */
#define FDT( call ) do {                                        \
    int fdt_res = (call);                                       \
    if (fdt_res == -FDT_ERR_NOSPACE && fdt_size < FDT_MAX_SIZE) \
        goto next_resize;                                       \
    else if (fdt_res < 0) {                                     \
        LOG(ERROR, "FDT: %s failed: %d = %s",                   \
            #call, fdt_res, fdt_strerror(fdt_res));             \
        rc = ERROR_FAIL;                                        \
        goto out;                                               \
    }                                                           \
} while(0)

    for (;;) {
next_resize:
        if (fdt_size) {
            fdt_size <<= 1;
            LOG(DEBUG, "Increasing FDT size to %zd and retrying", fdt_size);
        } else {
            fdt_size = 4096;
        }

        fdt = libxl__realloc(gc, fdt, fdt_size);

        FDT( fdt_create(fdt, fdt_size) );

        FDT( fdt_finish_reservemap(fdt) );

        FDT( fdt_begin_node(fdt, "") );

        FDT( make_root_properties(gc, vers, fdt) );
        FDT( make_chosen_node(gc, fdt, !!dom->ramdisk_blob, info) );
        FDT( make_cpus_node(gc, fdt, info->max_vcpus, ainfo) );
        FDT( make_psci_node(gc, fdt) );

        FDT( make_memory_nodes(gc, fdt, dom) );

        switch (config.gic_version) {
        case XEN_DOMCTL_CONFIG_GIC_V2:
            FDT( make_gicv2_node(gc, fdt,
                                 GUEST_GICD_BASE, GUEST_GICD_SIZE,
                                 GUEST_GICC_BASE, GUEST_GICC_SIZE) );
            break;
        case XEN_DOMCTL_CONFIG_GIC_V3:
            FDT( make_gicv3_node(gc, fdt) );
            break;
        default:
            LOG(ERROR, "Unknown GIC version %d", config.gic_version);
            rc = ERROR_FAIL;
            goto out;
        }

        FDT( make_timer_node(gc, fdt, ainfo) );
        FDT( make_hypervisor_node(gc, fdt, vers) );

        FDT( fdt_end_node(fdt) );

        FDT( fdt_finish(fdt) );
        break;
    }
#undef FDT

    LOG(DEBUG, "fdt total size %d", fdt_totalsize(fdt));

    res = xc_dom_devicetree_mem(dom, fdt, fdt_totalsize(fdt));
    if (res) {
        LOGE(ERROR, "xc_dom_devicetree_file failed");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;

out:
    return rc;
}

static void finalise_one_memory_node(libxl__gc *gc, void *fdt,
                                     uint64_t base, uint64_t size)
{
    int node, res;
    const char *name = GCSPRINTF("/memory@%"PRIx64, base);

    node = fdt_path_offset(fdt, name);
    assert(node > 0);

    if (size == 0) {
        LOG(DEBUG, "Nopping out placeholder node %s", name);
        fdt_nop_node(fdt, node);
    } else {
        uint32_t regs[ROOT_ADDRESS_CELLS+ROOT_SIZE_CELLS];
        be32 *cells = &regs[0];

        LOG(DEBUG, "Populating placeholder node %s", name);

        set_range(&cells, ROOT_ADDRESS_CELLS, ROOT_SIZE_CELLS, base, size);

        res = fdt_setprop_inplace(fdt, node, "reg", regs, sizeof(regs));
        assert(!res);
    }
}

int libxl__arch_domain_finalise_hw_description(libxl__gc *gc,
                                               libxl_domain_build_info *info,
                                               struct xc_dom_image *dom)
{
    void *fdt = dom->devicetree_blob;
    int i;
    const uint64_t bankbase[] = GUEST_RAM_BANK_BASES;

    const struct xc_dom_seg *ramdisk = dom->ramdisk_blob ?
        &dom->ramdisk_seg : NULL;

    if (ramdisk) {
        int chosen, res;
        uint64_t val;

        /* Neither the fdt_path_offset() nor either of the
         * fdt_setprop_inplace() calls can fail. If they do then
         * make_chosen_node() (see above) has got something very
         * wrong.
         */
        chosen = fdt_path_offset(fdt, "/chosen");
        assert(chosen > 0);

        LOG(DEBUG, "/chosen updating initrd properties to cover "
            "%"PRIx64"-%"PRIx64,
            ramdisk->vstart, ramdisk->vend);

        val = cpu_to_fdt64(ramdisk->vstart);
        res = fdt_setprop_inplace(fdt, chosen, PROP_INITRD_START,
                                  &val, sizeof(val));
        assert(!res);

        val = cpu_to_fdt64(ramdisk->vend);
        res = fdt_setprop_inplace(fdt, chosen, PROP_INITRD_END,
                                  &val, sizeof(val));
        assert(!res);

    }

    for (i = 0; i < GUEST_RAM_BANKS; i++) {
        const uint64_t size = (uint64_t)dom->rambank_size[i] << XC_PAGE_SHIFT;

        finalise_one_memory_node(gc, fdt, bankbase[i], size);
    }

    debug_dump_fdt(gc, fdt);

    return 0;
}
