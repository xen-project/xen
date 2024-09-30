#include "libxl_internal.h"
#include "libxl_arch.h"
#include "libxl_libfdt_compat.h"
#include "libxl_arm.h"

#include <xen-tools/arm-arch-capabilities.h>

#include <stdbool.h>
#include <libfdt.h>
#include <assert.h>
#include <xen/device_tree_defs.h>

/*
 * There is no clear requirements for the total size of Virtio MMIO region.
 * The size of control registers is 0x100 and device-specific configuration
 * registers starts at the offset 0x100, however it's size depends on the device
 * and the driver. Pick the biggest known size at the moment to cover most
 * of the devices (also consider allowing the user to configure the size via
 * config file for the one not conforming with the proposed value).
 */
#define VIRTIO_MMIO_DEV_SIZE   xen_mk_ullong(0x200)

static uint64_t alloc_virtio_mmio_base(libxl__gc *gc, uint64_t *virtio_mmio_base)
{
    uint64_t base = *virtio_mmio_base;

    /* Make sure we have enough reserved resources */
    if (base + VIRTIO_MMIO_DEV_SIZE >
        GUEST_VIRTIO_MMIO_BASE + GUEST_VIRTIO_MMIO_SIZE) {
        LOG(ERROR, "Ran out of reserved range for Virtio MMIO BASE 0x%"PRIx64"\n",
            base);
        return 0;
    }
    *virtio_mmio_base += VIRTIO_MMIO_DEV_SIZE;

    return base;
}

static uint32_t alloc_virtio_mmio_irq(libxl__gc *gc, uint32_t *virtio_mmio_irq)
{
    uint32_t irq = *virtio_mmio_irq;

    /* Make sure we have enough reserved resources */
    if (irq > GUEST_VIRTIO_MMIO_SPI_LAST) {
        LOG(ERROR, "Ran out of reserved range for Virtio MMIO IRQ %u\n", irq);
        return 0;
    }
    (*virtio_mmio_irq)++;

    return irq;
}

static int alloc_virtio_mmio_params(libxl__gc *gc, uint64_t *base,
                                    uint32_t *irq, uint64_t *virtio_mmio_base,
                                    uint32_t *virtio_mmio_irq)
{
    *base = alloc_virtio_mmio_base(gc, virtio_mmio_base);
    if (!*base)
        return ERROR_FAIL;

    *irq = alloc_virtio_mmio_irq(gc, virtio_mmio_irq);
    if (!*irq)
        return ERROR_FAIL;

    LOG(DEBUG, "Allocate Virtio MMIO params: IRQ %u BASE 0x%"PRIx64, *irq,
        *base);

    return 0;
}

static const char *gicv_to_string(libxl_gic_version gic_version)
{
    switch (gic_version) {
    case LIBXL_GIC_VERSION_V2:
        return "V2";
    case LIBXL_GIC_VERSION_V3:
        return "V3";
    default:
        return "unknown";
    }
}

int libxl__arch_domain_prepare_config(libxl__gc *gc,
                                      libxl_domain_config *d_config,
                                      struct xen_domctl_createdomain *config)
{
    uint32_t nr_spis = 0;
    unsigned int i;
    uint32_t vuart_irq, virtio_irq = 0;
    bool vuart_enabled = false, virtio_enabled = false;
    uint64_t virtio_mmio_base = GUEST_VIRTIO_MMIO_BASE;
    uint32_t virtio_mmio_irq = GUEST_VIRTIO_MMIO_SPI_FIRST;
    int rc;

    /*
     * If pl011 vuart is enabled then increment the nr_spis to allow allocation
     * of SPI VIRQ for pl011.
     */
    if (d_config->b_info.arch_arm.vuart == LIBXL_VUART_TYPE_SBSA_UART) {
        nr_spis += (GUEST_VPL011_SPI - 32) + 1;
        vuart_irq = GUEST_VPL011_SPI;
        vuart_enabled = true;
    }

    for (i = 0; i < d_config->num_disks; i++) {
        libxl_device_disk *disk = &d_config->disks[i];

        if (disk->specification == LIBXL_DISK_SPECIFICATION_VIRTIO) {
            rc = alloc_virtio_mmio_params(gc, &disk->base, &disk->irq,
                                          &virtio_mmio_base,
                                          &virtio_mmio_irq);

            if (rc)
                return rc;
        }
    }

    for (i = 0; i < d_config->num_virtios; i++) {
        libxl_device_virtio *virtio = &d_config->virtios[i];

        if (virtio->transport != LIBXL_VIRTIO_TRANSPORT_MMIO)
            continue;

        rc = alloc_virtio_mmio_params(gc, &virtio->base, &virtio->irq,
                                      &virtio_mmio_base, &virtio_mmio_irq);

        if (rc)
            return rc;
    }

    /*
     * Every virtio-mmio device uses one emulated SPI. If Virtio devices are
     * present, make sure that we allocate enough SPIs for them.
     * The resulting "nr_spis" needs to cover the highest possible SPI.
     */
    if (virtio_mmio_irq != GUEST_VIRTIO_MMIO_SPI_FIRST) {
        virtio_enabled = true;

        /*
         * Assumes that "virtio_mmio_irq" is the highest allocated irq, which is
         * updated from alloc_virtio_mmio_irq() currently.
         */
        virtio_irq = virtio_mmio_irq - 1;
        nr_spis = max(nr_spis, virtio_irq - 32 + 1);
    }

    for (i = 0; i < d_config->b_info.num_irqs; i++) {
        uint32_t irq = d_config->b_info.irqs[i];
        uint32_t spi;

        /*
         * This check ensures the if user has requested pass-through of a certain irq
         * which conflicts with vpl011 irq then it flags an error to indicate to the
         * user that the specific HW irq cannot be used as it is dedicated for vpl011.
         * 
         * TODO:
         * The vpl011 irq should be assigned such that it never conflicts with user
         * specified irqs thereby preventing its pass-through. This TODO is for
         * implementing that logic in future.
         */
        if (vuart_enabled && irq == vuart_irq) {
            LOG(ERROR, "Physical IRQ %u conflicting with pl011 SPI\n", irq);
            return ERROR_FAIL;
        }

        /* The same check as for vpl011 */
        if (virtio_enabled &&
            (irq >= GUEST_VIRTIO_MMIO_SPI_FIRST && irq <= virtio_irq)) {
            LOG(ERROR, "Physical IRQ %u conflicting with Virtio MMIO IRQ range\n", irq);
            return ERROR_FAIL;
        }

        if (irq < 32)
            continue;

        spi = irq - 32;

        if (nr_spis <= spi)
            nr_spis = spi + 1;
    }

    LOG(DEBUG, "Configure the domain");

    config->arch.nr_spis = max(nr_spis, d_config->b_info.arch_arm.nr_spis);
    LOG(DEBUG, " - Allocate %u SPIs", config->arch.nr_spis);

    switch (d_config->b_info.arch_arm.gic_version) {
    case LIBXL_GIC_VERSION_DEFAULT:
        config->arch.gic_version = XEN_DOMCTL_CONFIG_GIC_NATIVE;
        break;
    case LIBXL_GIC_VERSION_V2:
        config->arch.gic_version = XEN_DOMCTL_CONFIG_GIC_V2;
        break;
    case LIBXL_GIC_VERSION_V3:
        config->arch.gic_version = XEN_DOMCTL_CONFIG_GIC_V3;
        break;
    default:
        LOG(ERROR, "Unknown GIC version %d",
            d_config->b_info.arch_arm.gic_version);
        return ERROR_FAIL;
    }

    switch (d_config->b_info.tee) {
    case LIBXL_TEE_TYPE_NONE:
        config->arch.tee_type = XEN_DOMCTL_CONFIG_TEE_NONE;
        break;
    case LIBXL_TEE_TYPE_OPTEE:
        config->arch.tee_type = XEN_DOMCTL_CONFIG_TEE_OPTEE;
        break;
    case LIBXL_TEE_TYPE_FFA:
        config->arch.tee_type = XEN_DOMCTL_CONFIG_TEE_FFA;
        break;
    default:
        LOG(ERROR, "Unknown TEE type %d",
            d_config->b_info.tee);
        return ERROR_FAIL;
    }

    /* Parameter is sanitised in libxl__arch_domain_build_info_setdefault */
    if (d_config->b_info.arch_arm.sve_vl) {
        /* Vector length is divided by 128 in struct xen_domctl_createdomain */
        config->arch.sve_vl = d_config->b_info.arch_arm.sve_vl / 128U;
    }

    return 0;
}

int libxl__arch_domain_save_config(libxl__gc *gc,
                                   libxl_domain_config *d_config,
                                   libxl__domain_build_state *state,
                                   const struct xen_domctl_createdomain *config)
{
    switch (config->arch.gic_version) {
    case XEN_DOMCTL_CONFIG_GIC_V2:
        d_config->b_info.arch_arm.gic_version = LIBXL_GIC_VERSION_V2;
        break;
    case XEN_DOMCTL_CONFIG_GIC_V3:
        d_config->b_info.arch_arm.gic_version = LIBXL_GIC_VERSION_V3;
        break;
    default:
        LOG(ERROR, "Unexpected gic version %u", config->arch.gic_version);
        return ERROR_FAIL;
    }

    state->clock_frequency = config->arch.clock_frequency;

    return 0;
}

int libxl__arch_domain_create(libxl__gc *gc,
                              libxl_domain_config *d_config,
                              libxl__domain_build_state *state,
                              uint32_t domid)
{
    return libxl__domain_set_paging_mempool_size(gc, d_config, domid);
}

int libxl__arch_extra_memory(libxl__gc *gc,
                             const libxl_domain_build_info *info,
                             uint64_t *out)
{
    int rc = 0;
    uint64_t size = 0;

    if (libxl_defbool_val(info->acpi)) {
        rc = libxl__get_acpi_size(gc, info, &size);
        if (rc < 0) {
            rc = ERROR_FAIL;
            goto out;
        }
    }

    *out = LIBXL_MAXMEM_CONSTANT + DIV_ROUNDUP(size, 1024);
out:
    return rc;
}

static struct arch_info {
    const char *guest_type;
    const char *timer_compat;
    const char *cpu_compat;
} arch_info[] = {
    {"xen-3.0-armv7l",  "arm,armv7-timer", "arm,cortex-a15" },
    {"xen-3.0-aarch64", "arm,armv8-timer", "arm,armv8" },
};

typedef uint32_t be32;
typedef be32 gic_interrupt[3];

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

    res = fdt_property_cell(fdt, "interrupt-parent", GUEST_PHANDLE_GIC);
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

static int fdt_property_reg_placeholder(libxl__gc *gc, void *fdt,
                                        unsigned int addr_cells,
                                        unsigned int size_cells,
                                        unsigned int num_regs)
{
    uint32_t regs[num_regs * (addr_cells + size_cells)];
    be32 *cells = &regs[0];
    unsigned int i;

    for (i = 0; i < num_regs; i++)
        set_range(&cells, addr_cells, size_cells, 0, 0);

    return fdt_property(fdt, "reg", regs, sizeof(regs));
}

static int fdt_property_values(libxl__gc *gc, void *fdt,
                               const char *name,
                               unsigned num_cells, ...)
{
    uint32_t prop[num_cells];
    be32 *cells = &prop[0];
    int i;
    va_list ap;
    uint32_t arg;

    va_start(ap, num_cells);
    for (i = 0 ; i < num_cells; i++) {
        arg = va_arg(ap, uint32_t);
        set_cell(&cells, 1, arg);
    }
    va_end(ap);

    return fdt_property(fdt, name, prop, sizeof(prop));
}

static int fdt_property_vpci_ranges(libxl__gc *gc, void *fdt,
                                    unsigned addr_cells,
                                    unsigned size_cells,
                                    unsigned num_regs, ...)
{
    uint32_t regs[num_regs*((addr_cells*2)+size_cells+1)];
    be32 *cells = &regs[0];
    int i;
    va_list ap;
    uint64_t arg;

    va_start(ap, num_regs);
    for (i = 0 ; i < num_regs; i++) {
        /* Set the memory bit field */
        arg = va_arg(ap, uint32_t);
        set_cell(&cells, 1, arg);

        /* Set the vpci bus address */
        arg = addr_cells ? va_arg(ap, uint64_t) : 0;
        set_cell(&cells, addr_cells , arg);

        /* Set the cpu bus address where vpci address is mapped */
        set_cell(&cells, addr_cells, arg);

        /* Set the vpci size requested */
        arg = size_cells ? va_arg(ap, uint64_t) : 0;
        set_cell(&cells, size_cells, arg);
    }
    va_end(ap);

    return fdt_property(fdt, "ranges", regs, sizeof(regs));
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

    res = fdt_property_cell(fdt, "interrupt-parent", GUEST_PHANDLE_GIC);
    if (res) return res;

    res = fdt_property_cell(fdt, "#address-cells", GUEST_ROOT_ADDRESS_CELLS);
    if (res) return res;

    res = fdt_property_cell(fdt, "#size-cells", GUEST_ROOT_SIZE_CELLS);
    if (res) return res;

    return 0;
}

static int make_chosen_node(libxl__gc *gc, void *fdt, bool ramdisk,
                            libxl__domain_build_state *state,
                            const libxl_domain_build_info *info)
{
    int res;

    /* 1024 bit enough to mix Linux CRNG state several times */
    uint8_t seed[128];

    /* See linux Documentation/devicetree/... */
    res = fdt_begin_node(fdt, "chosen");
    if (res) return res;

    if (state->pv_cmdline) {
        LOG(DEBUG, "/chosen/bootargs = %s", state->pv_cmdline);
        res = fdt_property_string(fdt, "bootargs", state->pv_cmdline);
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

    if (libxl_defbool_val(info->acpi)) {
        const uint64_t acpi_base = GUEST_ACPI_BASE;
        const char *name = GCSPRINTF("module@%"PRIx64, acpi_base);

        res = fdt_begin_node(fdt, name);
        if (res) return res;

        res = fdt_property_compat(gc, fdt, 2, "xen,guest-acpi",
                                  "multiboot,module");
        if (res) return res;

        res = fdt_property_regs(gc, fdt, GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
                                1, 0, 0);
        if (res) return res;

        res = fdt_end_node(fdt);
        if (res) return res;
    }

    res = libxl__random_bytes(gc, seed, sizeof(seed));
    if (res) return res;
    res = fdt_property(fdt, "rng-seed", seed, sizeof(seed));
    if (res) return res;

    res = fdt_end_node(fdt);
    if (res) return res;

    return 0;
}

static int make_cpus_node(libxl__gc *gc, void *fdt, int nr_cpus,
                          const struct arch_info *ainfo)
{
    int res, i;
    uint64_t mpidr_aff;

    res = fdt_begin_node(fdt, "cpus");
    if (res) return res;

    res = fdt_property_cell(fdt, "#address-cells", 1);
    if (res) return res;

    res = fdt_property_cell(fdt, "#size-cells", 0);
    if (res) return res;

    for (i = 0; i < nr_cpus; i++) {
        const char *name;

        mpidr_aff = libxl__compute_mpdir(i);
        name = GCSPRINTF("cpu@%"PRIx64, mpidr_aff);

        res = fdt_begin_node(fdt, name);
        if (res) return res;

        res = fdt_property_string(fdt, "device_type", "cpu");
        if (res) return res;

        res = fdt_property_compat(gc, fdt, 1, ainfo->cpu_compat);
        if (res) return res;

        res = fdt_property_string(fdt, "enable-method", "psci");
        if (res) return res;

        res = fdt_property_regs(gc, fdt, 1, 0, 1, mpidr_aff);
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

    res = fdt_property_compat(gc, fdt, 3, "arm,psci-1.0",
                              "arm,psci-0.2", "arm,psci");
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

static int make_optee_node(libxl__gc *gc, void *fdt)
{
    int res;
    LOG(DEBUG, "Creating OP-TEE node in dtb");

    res = fdt_begin_node(fdt, "firmware");
    if (res) return res;

    res = fdt_begin_node(fdt, "optee");
    if (res) return res;

    res = fdt_property_compat(gc, fdt, 1, "linaro,optee-tz");
    if (res) return res;

    res = fdt_property_string(fdt, "method", "hvc");
    if (res) return res;

    res = fdt_end_node(fdt);
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

        res = fdt_property_regs(gc, fdt, GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
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

    res = fdt_property_regs(gc, fdt, GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
                            2,
                            gicd_base, gicd_size,
                            gicc_base, gicc_size);
    if (res) return res;

    res = fdt_property_cell(fdt, "linux,phandle", GUEST_PHANDLE_GIC);
    if (res) return res;

    res = fdt_property_cell(fdt, "phandle", GUEST_PHANDLE_GIC);
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

    res = fdt_property_regs(gc, fdt, GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
                            2,
                            gicd_base, gicd_size,
                            gicr0_base, gicr0_size);
    if (res) return res;

    res = fdt_property_cell(fdt, "linux,phandle", GUEST_PHANDLE_GIC);
    if (res) return res;

    res = fdt_property_cell(fdt, "phandle", GUEST_PHANDLE_GIC);
    if (res) return res;

    res = fdt_end_node(fdt);
    if (res) return res;

    return 0;
}

static int make_timer_node(libxl__gc *gc, void *fdt,
                           const struct arch_info *ainfo,
                           uint32_t frequency)
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

    if ( frequency )
        fdt_property_u32(fdt, "clock-frequency", frequency);

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

    /*
     * reg 0 is a placeholder for grant table space, reg 1...N are
     * the placeholders for extended regions.
     */
    res = fdt_property_reg_placeholder(gc, fdt, GUEST_ROOT_ADDRESS_CELLS,
                                       GUEST_ROOT_SIZE_CELLS,
                                       GUEST_RAM_BANKS + 1);
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

static int make_vpl011_uart_node(libxl__gc *gc, void *fdt,
                                 const struct arch_info *ainfo,
                                 struct xc_dom_image *dom)
{
    int res;
    gic_interrupt intr;

    res = fdt_begin_node(fdt, "sbsa-pl011");
    if (res) return res;

    res = fdt_property_compat(gc, fdt, 1, "arm,sbsa-uart");
    if (res) return res;

    res = fdt_property_regs(gc, fdt, GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
                            1,
                            GUEST_PL011_BASE, GUEST_PL011_SIZE);
    if (res) return res;

    set_interrupt(intr, GUEST_VPL011_SPI, 0xf, DT_IRQ_TYPE_LEVEL_HIGH);

    res = fdt_property_interrupts(gc, fdt, &intr, 1);
    if (res) return res;

    /* Use a default baud rate of 115200. */
    fdt_property_u32(fdt, "current-speed", 115200);

    res = fdt_end_node(fdt);
    if (res) return res;

    return 0;
}

static int make_vpci_node(libxl__gc *gc, void *fdt,
                          const struct arch_info *ainfo,
                          struct xc_dom_image *dom)
{
    int res;
    const uint64_t vpci_ecam_base = GUEST_VPCI_ECAM_BASE;
    const uint64_t vpci_ecam_size = GUEST_VPCI_ECAM_SIZE;
    const char *name = GCSPRINTF("pcie@%"PRIx64, vpci_ecam_base);

    res = fdt_begin_node(fdt, name);
    if (res) return res;

    res = fdt_property_compat(gc, fdt, 1, "pci-host-ecam-generic");
    if (res) return res;

    res = fdt_property_string(fdt, "device_type", "pci");
    if (res) return res;

    res = fdt_property_regs(gc, fdt, GUEST_ROOT_ADDRESS_CELLS,
            GUEST_ROOT_SIZE_CELLS, 1, vpci_ecam_base, vpci_ecam_size);
    if (res) return res;

    res = fdt_property_values(gc, fdt, "bus-range", 2, 0, 255);
    if (res) return res;

    res = fdt_property_cell(fdt, "#address-cells", 3);
    if (res) return res;

    res = fdt_property_cell(fdt, "#size-cells", 2);
    if (res) return res;

    res = fdt_property_string(fdt, "status", "okay");
    if (res) return res;

    res = fdt_property_vpci_ranges(gc, fdt, GUEST_ROOT_ADDRESS_CELLS,
        GUEST_ROOT_SIZE_CELLS, 2,
        GUEST_VPCI_ADDR_TYPE_MEM, GUEST_VPCI_MEM_ADDR, GUEST_VPCI_MEM_SIZE,
        GUEST_VPCI_ADDR_TYPE_PREFETCH_MEM, GUEST_VPCI_PREFETCH_MEM_ADDR,
        GUEST_VPCI_PREFETCH_MEM_SIZE);
    if (res) return res;

    res = fdt_end_node(fdt);
    if (res) return res;

    return 0;
}

static int make_xen_iommu_node(libxl__gc *gc, void *fdt)
{
    int res;

    /* See Linux Documentation/devicetree/bindings/iommu/xen,grant-dma.yaml */
    res = fdt_begin_node(fdt, "xen_iommu");
    if (res) return res;

    res = fdt_property_compat(gc, fdt, 1, "xen,grant-dma");
    if (res) return res;

    res = fdt_property_cell(fdt, "#iommu-cells", 1);
    if (res) return res;

    res = fdt_property_cell(fdt, "phandle", GUEST_PHANDLE_IOMMU);
    if (res) return res;

    res = fdt_end_node(fdt);
    if (res) return res;

    return 0;
}

/* The caller is responsible to complete / close the fdt node */
static int make_virtio_mmio_node_common(libxl__gc *gc, void *fdt, uint64_t base,
                                        uint32_t irq, uint32_t backend_domid,
                                        bool grant_usage)
{
    int res;
    gic_interrupt intr;
    const char *name = GCSPRINTF("virtio@%"PRIx64, base);

    res = fdt_begin_node(fdt, name);
    if (res) return res;

    res = fdt_property_compat(gc, fdt, 1, "virtio,mmio");
    if (res) return res;

    res = fdt_property_regs(gc, fdt, GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
                            1, base, VIRTIO_MMIO_DEV_SIZE);
    if (res) return res;

    set_interrupt(intr, irq, 0xf, DT_IRQ_TYPE_EDGE_RISING);
    res = fdt_property_interrupts(gc, fdt, &intr, 1);
    if (res) return res;

    res = fdt_property(fdt, "dma-coherent", NULL, 0);
    if (res) return res;

    if (grant_usage) {
        uint32_t iommus_prop[2];

        iommus_prop[0] = cpu_to_fdt32(GUEST_PHANDLE_IOMMU);
        iommus_prop[1] = cpu_to_fdt32(backend_domid);

        res = fdt_property(fdt, "iommus", iommus_prop, sizeof(iommus_prop));
        if (res) return res;
    }

    return res;
}

static int make_virtio_mmio_node(libxl__gc *gc, void *fdt, uint64_t base,
                                 uint32_t irq, uint32_t backend_domid,
                                 bool grant_usage)
{
    int res;

    res = make_virtio_mmio_node_common(gc, fdt, base, irq, backend_domid, grant_usage);
    if (res) return res;

    return fdt_end_node(fdt);
}

/*
 * The DT bindings for I2C device are present here:
 *
 * https://www.kernel.org/doc/Documentation/devicetree/bindings/i2c/i2c-virtio.yaml
 */
static int make_virtio_mmio_node_i2c(libxl__gc *gc, void *fdt)
{
    int res;

    res = fdt_begin_node(fdt, "i2c");
    if (res) return res;

    res = fdt_property_compat(gc, fdt, 1, VIRTIO_DEVICE_TYPE_I2C);
    if (res) return res;

    return fdt_end_node(fdt);
}

/*
 * The DT bindings for GPIO device are present here:
 *
 * https://www.kernel.org/doc/Documentation/devicetree/bindings/gpio/gpio-virtio.yaml
 */
static int make_virtio_mmio_node_gpio(libxl__gc *gc, void *fdt)
{
    int res;

    res = fdt_begin_node(fdt, "gpio");
    if (res) return res;

    res = fdt_property_compat(gc, fdt, 1, VIRTIO_DEVICE_TYPE_GPIO);
    if (res) return res;

    res = fdt_property(fdt, "gpio-controller", NULL, 0);
    if (res) return res;

    res = fdt_property_cell(fdt, "#gpio-cells", 2);
    if (res) return res;

    res = fdt_property(fdt, "interrupt-controller", NULL, 0);
    if (res) return res;

    res = fdt_property_cell(fdt, "#interrupt-cells", 2);
    if (res) return res;

    return fdt_end_node(fdt);
}

static int make_virtio_mmio_node_device(libxl__gc *gc, void *fdt, uint64_t base,
                                        uint32_t irq, const char *type,
                                        uint32_t backend_domid, bool grant_usage)
{
    int res;

    res = make_virtio_mmio_node_common(gc, fdt, base, irq, backend_domid, grant_usage);
    if (res) return res;

    /* Add device specific nodes */
    if (!strcmp(type, VIRTIO_DEVICE_TYPE_I2C)) {
        res = make_virtio_mmio_node_i2c(gc, fdt);
        if (res) return res;
    } else if (!strcmp(type, VIRTIO_DEVICE_TYPE_GPIO)) {
        res = make_virtio_mmio_node_gpio(gc, fdt);
        if (res) return res;
    } else {
        int len = sizeof(VIRTIO_DEVICE_TYPE_GENERIC) - 1;

        if (strncmp(type, VIRTIO_DEVICE_TYPE_GENERIC, len)) {
            /* Doesn't match generic virtio device */
            LOG(ERROR, "Invalid type for virtio device: %s", type);
            return -EINVAL;
        }
    }

    return fdt_end_node(fdt);
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
    LOG(ERROR, "Unable to find arch FDT info for %s", dom->guest_type);
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

#ifdef ENABLE_PARTIAL_DEVICE_TREE

static int check_partial_fdt(libxl__gc *gc, void *fdt, size_t size)
{
    int r;

    if (fdt_magic(fdt) != FDT_MAGIC) {
        LOG(ERROR, "Partial FDT is not a valid Flat Device Tree");
        return ERROR_FAIL;
    }

    r = fdt_check_header(fdt);
    if (r) {
        LOG(ERROR, "Failed to check the partial FDT (%d)", r);
        return ERROR_FAIL;
    }

    if (fdt_totalsize(fdt) > size) {
        LOG(ERROR, "Partial FDT totalsize is too big");
        return ERROR_FAIL;
    }

    return 0;
}

static int copy_properties(libxl__gc *gc, void *fdt, void *pfdt,
                           int nodeoff)
{
    int propoff, nameoff, r;
    const struct fdt_property *prop;

    for (propoff = fdt_first_property_offset(pfdt, nodeoff);
         propoff >= 0;
         propoff = fdt_next_property_offset(pfdt, propoff)) {

        if (!(prop = fdt_get_property_by_offset(pfdt, propoff, NULL))) {
            return -FDT_ERR_INTERNAL;
        }

        nameoff = fdt32_to_cpu(prop->nameoff);
        r = fdt_property(fdt, fdt_string(pfdt, nameoff),
                         prop->data, fdt32_to_cpu(prop->len));
        if (r) return r;
    }

    /* FDT_ERR_NOTFOUND => There is no more properties for this node */
    return (propoff != -FDT_ERR_NOTFOUND)? propoff : 0;
}

/* Copy a node from the partial device tree to the guest device tree */
static int copy_node(libxl__gc *gc, void *fdt, void *pfdt,
                     int nodeoff, int depth)
{
    int r;

    r = fdt_begin_node(fdt, fdt_get_name(pfdt, nodeoff, NULL));
    if (r) return r;

    r = copy_properties(gc, fdt, pfdt, nodeoff);
    if (r) return r;

    for (nodeoff = fdt_first_subnode(pfdt, nodeoff);
         nodeoff >= 0;
         nodeoff = fdt_next_subnode(pfdt, nodeoff)) {
        r = copy_node(gc, fdt, pfdt, nodeoff, depth + 1);
        if (r) return r;
    }

    if (nodeoff != -FDT_ERR_NOTFOUND)
        return nodeoff;

    r = fdt_end_node(fdt);
    if (r) return r;

    return 0;
}

static int copy_node_by_path(libxl__gc *gc, const char *path,
                             void *fdt, void *pfdt)
{
    int nodeoff, r;
    const char *name = strrchr(path, '/');

    if (!name)
        return -FDT_ERR_INTERNAL;

    name++;

    /*
     * The FDT function to look at a node doesn't take into account the
     * unit (i.e anything after @) when search by name. Check if the
     * name exactly matches.
     */
    nodeoff = fdt_path_offset(pfdt, path);
    if (nodeoff < 0)
        return nodeoff;

    if (strcmp(fdt_get_name(pfdt, nodeoff, NULL), name))
        return -FDT_ERR_NOTFOUND;

    r = copy_node(gc, fdt, pfdt, nodeoff, 0);
    if (r) return r;

    return 0;
}

/*
 * The partial device tree is not copied entirely. Only the relevant bits are
 * copied to the guest device tree:
 *  - /passthrough node
 *  - /aliases node
 */
static int copy_partial_fdt(libxl__gc *gc, void *fdt, void *pfdt)
{
    int r;

    r = copy_node_by_path(gc, "/passthrough", fdt, pfdt);
    if (r < 0) {
        LOG(ERROR, "Can't copy the node \"/passthrough\" from the partial FDT");
        return r;
    }

    r = copy_node_by_path(gc, "/aliases", fdt, pfdt);
    if (r < 0 && r != -FDT_ERR_NOTFOUND) {
        LOG(ERROR, "Can't copy the node \"/aliases\" from the partial FDT");
        return r;
    }

    return 0;
}

#else

static int check_partial_fdt(libxl__gc *gc, void *fdt, size_t size)
{
    LOG(ERROR, "partial device tree not supported");

    return ERROR_FAIL;
}

static int copy_partial_fdt(libxl__gc *gc, void *fdt, void *pfdt)
{
    /*
     * We should never be here when the partial device tree is not
     * supported.
     * */
    return -FDT_ERR_INTERNAL;
}

#endif /* ENABLE_PARTIAL_DEVICE_TREE */

#define FDT_MAX_SIZE (1<<20)

static int libxl__prepare_dtb(libxl__gc *gc, libxl_domain_config *d_config,
                              libxl__domain_build_state *state,
                              struct xc_dom_image *dom)
{
    void *fdt = NULL;
    void *pfdt = NULL;
    int rc, res;
    size_t fdt_size = 0;
    int pfdt_size = 0;
    libxl_domain_build_info *const info = &d_config->b_info;
    bool iommu_needed = false;
    unsigned int i;

    const libxl_version_info *vers;
    const struct arch_info *ainfo;

    vers = libxl_get_version_info(CTX);
    if (vers == NULL) return ERROR_FAIL;

    ainfo = get_arch_info(gc, dom);
    if (ainfo == NULL) return ERROR_FAIL;

    LOG(DEBUG, "constructing DTB for Xen version %d.%d guest",
        vers->xen_version_major, vers->xen_version_minor);
    LOG(DEBUG, " - vGIC version: %s",
        gicv_to_string(info->arch_arm.gic_version));

    if (info->device_tree) {
        LOG(DEBUG, " - Partial device tree provided: %s", info->device_tree);

        rc = libxl_read_file_contents(CTX, info->device_tree,
                                      &pfdt, &pfdt_size);
        if (rc) {
            LOGEV(ERROR, rc, "failed to read the partial device file %s",
                  info->device_tree);
            return ERROR_FAIL;
        }
        libxl__ptr_add(gc, pfdt);

        if (check_partial_fdt(gc, pfdt, pfdt_size))
            return ERROR_FAIL;
    }

/*
 * Call "call" handling FDT_ERR_*. Will either:
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
        FDT( make_chosen_node(gc, fdt, !!dom->modules[0].blob, state, info) );
        FDT( make_cpus_node(gc, fdt, info->max_vcpus, ainfo) );
        FDT( make_psci_node(gc, fdt) );

        FDT( make_memory_nodes(gc, fdt, dom) );

        switch (info->arch_arm.gic_version) {
        case LIBXL_GIC_VERSION_V2:
            FDT( make_gicv2_node(gc, fdt,
                                 GUEST_GICD_BASE, GUEST_GICD_SIZE,
                                 GUEST_GICC_BASE, GUEST_GICC_SIZE) );
            break;
        case LIBXL_GIC_VERSION_V3:
            FDT( make_gicv3_node(gc, fdt) );
            break;
        default:
            LOG(ERROR, "Unknown GIC version %s",
                gicv_to_string(info->arch_arm.gic_version));
            rc = ERROR_FAIL;
            goto out;
        }

        FDT( make_timer_node(gc, fdt, ainfo, state->clock_frequency) );
        FDT( make_hypervisor_node(gc, fdt, vers) );

        if (info->arch_arm.vuart == LIBXL_VUART_TYPE_SBSA_UART)
            FDT( make_vpl011_uart_node(gc, fdt, ainfo, dom) );

        if (info->tee == LIBXL_TEE_TYPE_OPTEE)
            FDT( make_optee_node(gc, fdt) );

        if (d_config->num_pcidevs)
            FDT( make_vpci_node(gc, fdt, ainfo, dom) );

        for (i = 0; i < d_config->num_disks; i++) {
            libxl_device_disk *disk = &d_config->disks[i];

            if (disk->specification == LIBXL_DISK_SPECIFICATION_VIRTIO) {
                if (libxl_defbool_val(disk->grant_usage))
                    iommu_needed = true;

                FDT( make_virtio_mmio_node(gc, fdt, disk->base, disk->irq,
                                           disk->backend_domid,
                                           libxl_defbool_val(disk->grant_usage)) );
            }
        }

        for (i = 0; i < d_config->num_virtios; i++) {
            libxl_device_virtio *virtio = &d_config->virtios[i];

            if (virtio->transport != LIBXL_VIRTIO_TRANSPORT_MMIO)
                continue;

            if (libxl_defbool_val(virtio->grant_usage))
                iommu_needed = true;

            FDT( make_virtio_mmio_node_device(gc, fdt, virtio->base,
                                              virtio->irq, virtio->type,
                                              virtio->backend_domid,
                                              libxl_defbool_val(virtio->grant_usage)) );
        }

        /*
         * The iommu node should be created only once for all virtio-mmio
         * devices.
         */
        if (iommu_needed)
            FDT( make_xen_iommu_node(gc, fdt) );

        if (pfdt)
            FDT( copy_partial_fdt(gc, fdt, pfdt) );

        FDT( fdt_end_node(fdt) );

        FDT( fdt_finish(fdt) );
        break;
    }
#undef FDT

    LOG(DEBUG, "fdt total size %d", fdt_totalsize(fdt));

    res = xc_dom_devicetree_mem(dom, fdt, fdt_totalsize(fdt));
    if (res) {
        LOGE(ERROR, "xc_dom_devicetree_mem failed");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;

out:
    return rc;
}

int libxl__arch_domain_init_hw_description(libxl__gc *gc,
                                           libxl_domain_config *d_config,
                                           libxl__domain_build_state *state,
                                           struct xc_dom_image *dom)
{
    int rc;
    uint64_t val;
    libxl_domain_build_info *const info = &d_config->b_info;

    if (info->type != LIBXL_DOMAIN_TYPE_PVH) {
        LOG(ERROR, "Unsupported Arm guest type %s",
            libxl_domain_type_to_string(info->type));
        return ERROR_INVAL;
    }

    /* Set the value of domain param HVM_PARAM_CALLBACK_IRQ. */
    val = MASK_INSR(HVM_PARAM_CALLBACK_TYPE_PPI,
                    HVM_PARAM_CALLBACK_IRQ_TYPE_MASK);
    /* Active-low level-sensitive  */
    val |= MASK_INSR(HVM_PARAM_CALLBACK_TYPE_PPI_FLAG_LOW_LEVEL,
                     HVM_PARAM_CALLBACK_TYPE_PPI_FLAG_MASK);
    val |= GUEST_EVTCHN_PPI;
    rc = xc_hvm_param_set(dom->xch, dom->guest_domid, HVM_PARAM_CALLBACK_IRQ,
                          val);
    if (rc)
        return rc;

    rc = libxl__prepare_dtb(gc, d_config, state, dom);
    if (rc) goto out;

    if (!libxl_defbool_val(info->acpi)) {
        LOG(DEBUG, "Generating ACPI tables is disabled by user.");
        rc = 0;
        goto out;
    }

    if (strcmp(dom->guest_type, "xen-3.0-aarch64")) {
        /* ACPI is only supported for 64-bit guest currently. */
        LOG(ERROR, "Can not enable libxl option 'acpi' for %s", dom->guest_type);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__prepare_acpi(gc, info, dom);

out:
    return rc;
}

static void finalise_one_node(libxl__gc *gc, void *fdt, const char *uname,
                              uint64_t base, uint64_t size)
{
    int node, res;
    const char *name = GCSPRINTF("%s@%"PRIx64, uname, base);

    node = fdt_path_offset(fdt, name);
    assert(node > 0);

    if (size == 0) {
        LOG(DEBUG, "Nopping out placeholder node %s", name);
        fdt_nop_node(fdt, node);
    } else {
        uint32_t regs[GUEST_ROOT_ADDRESS_CELLS+GUEST_ROOT_SIZE_CELLS];
        be32 *cells = &regs[0];

        LOG(DEBUG, "Populating placeholder node %s", name);

        set_range(&cells, GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS, base, size);

        res = fdt_setprop_inplace(fdt, node, "reg", regs, sizeof(regs));
        assert(!res);
    }
}

#define ALIGN_UP_TO_2MB(x)   (((x) + MB(2) - 1) & (~(MB(2) - 1)))

#define EXT_REGION_MIN_SIZE   xen_mk_ullong(0x0004000000) /* 64MB */

static int finalize_hypervisor_node(libxl__gc *gc, struct xc_dom_image *dom)
{
    void *fdt = dom->devicetree_blob;
    uint64_t region_size[GUEST_RAM_BANKS] = {0}, region_base[GUEST_RAM_BANKS],
        bankend[GUEST_RAM_BANKS];
    uint32_t regs[(GUEST_ROOT_ADDRESS_CELLS + GUEST_ROOT_SIZE_CELLS) *
                  (GUEST_RAM_BANKS + 1)];
    be32 *cells = &regs[0];
    const uint64_t bankbase[] = GUEST_RAM_BANK_BASES;
    const uint64_t banksize[] = GUEST_RAM_BANK_SIZES;
    unsigned int i, len, nr_regions = 0;
    libxl_dominfo info;
    int offset, rc;

    offset = fdt_path_offset(fdt, "/hypervisor");
    if (offset < 0)
        return offset;

    rc = libxl_domain_info(CTX, &info, dom->guest_domid);
    if (rc)
        return rc;

    if (info.gpaddr_bits > 64)
        return ERROR_INVAL;

    /*
     * Try to allocate separate 2MB-aligned extended regions from the first
     * and second RAM banks taking into the account the maximum supported
     * guest physical address space size and the amount of memory assigned
     * to the guest.
     */
    for (i = 0; i < GUEST_RAM_BANKS; i++) {
        region_base[i] = bankbase[i] +
            ALIGN_UP_TO_2MB((uint64_t)dom->rambank_size[i] << XC_PAGE_SHIFT);

        bankend[i] = ~0ULL >> (64 - info.gpaddr_bits);
        bankend[i] = min(bankend[i], bankbase[i] + banksize[i] - 1);
        if (bankend[i] > region_base[i])
            region_size[i] = bankend[i] - region_base[i] + 1;
    }

    /*
     * The region 0 for grant table space must be always present. If we managed
     * to allocate the extended regions then insert them as regions 1...N.
     */
    set_range(&cells, GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
              GUEST_GNTTAB_BASE, GUEST_GNTTAB_SIZE);

    for (i = 0; i < GUEST_RAM_BANKS; i++) {
        if (region_size[i] < EXT_REGION_MIN_SIZE)
            continue;

        LOG(DEBUG, "Extended region %u: %#"PRIx64"->%#"PRIx64"",
            nr_regions, region_base[i], region_base[i] + region_size[i]);

        set_range(&cells, GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
                  region_base[i], region_size[i]);
        nr_regions++;
    }

    if (!nr_regions)
        LOG(WARN, "The extended regions cannot be allocated, not enough space");

    len = sizeof(regs[0]) * (GUEST_ROOT_ADDRESS_CELLS + GUEST_ROOT_SIZE_CELLS) *
        (nr_regions + 1);

    return fdt_setprop(fdt, offset, "reg", regs, len);
}

int libxl__arch_domain_finalise_hw_description(libxl__gc *gc,
                                               uint32_t domid,
                                               libxl_domain_config *d_config,
                                               struct xc_dom_image *dom)
{
    void *fdt = dom->devicetree_blob;
    int i, res;
    const uint64_t bankbase[] = GUEST_RAM_BANK_BASES;

    const struct xc_dom_seg *ramdisk = dom->modules[0].blob ?
        &dom->modules[0].seg : NULL;

    if (ramdisk) {
        int chosen;
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

    res = finalize_hypervisor_node(gc, dom);
    if (res)
        return res;

    for (i = 0; i < GUEST_RAM_BANKS; i++) {
        const uint64_t size = (uint64_t)dom->rambank_size[i] << XC_PAGE_SHIFT;

        finalise_one_node(gc, fdt, "/memory", bankbase[i], size);
    }

    if (dom->acpi_modules[0].data) {
        finalise_one_node(gc, fdt, "/chosen/module", GUEST_ACPI_BASE,
                          dom->acpi_modules[0].length);
    }

    debug_dump_fdt(gc, fdt);

    return 0;
}

int libxl__arch_build_dom_finish(libxl__gc *gc,
                                 libxl_domain_build_info *info,
                                 struct xc_dom_image *dom,
                                 libxl__domain_build_state *state)
{
    int rc = 0, ret;

    if (info->arch_arm.vuart != LIBXL_VUART_TYPE_SBSA_UART) {
        rc = 0;
        goto out;
    }

    ret = xc_dom_vuart_init(CTX->xch,
                            XEN_DOMCTL_VUART_TYPE_VPL011,
                            dom->guest_domid,
                            dom->console_domid,
                            dom->vuart_gfn,
                            &state->vuart_port);
    if (ret < 0) {
        rc = ERROR_FAIL;
        LOG(ERROR, "xc_dom_vuart_init failed\n");
    }

out:
    return rc;
}

int libxl__arch_vnuma_build_vmemrange(libxl__gc *gc,
                                      uint32_t domid,
                                      libxl_domain_build_info *info,
                                      libxl__domain_build_state *state)
{
    return libxl__vnuma_build_vmemrange_pv_generic(gc, domid, info, state);
}

int libxl__arch_domain_map_irq(libxl__gc *gc, uint32_t domid, int irq)
{
    return xc_domain_bind_pt_spi_irq(CTX->xch, domid, irq, irq);
}

void libxl__arch_domain_create_info_setdefault(libxl__gc *gc,
                                               libxl_domain_create_info *c_info)
{
    /*
     * Arm guest are now considered as PVH by the toolstack. To allow
     * compatibility with previous toolstack, PV guest are automatically
     * converted to PVH.
     */
    if (c_info->type == LIBXL_DOMAIN_TYPE_PV) {
        LOG(WARN, "Converting PV guest to PVH.");
        LOG(WARN, "Arm guest are now PVH.");
        LOG(WARN, "Please fix your configuration file/toolstack.");

        c_info->type = LIBXL_DOMAIN_TYPE_PVH;
        /* All other fields can remain untouched */
    }
}

int libxl__arch_domain_build_info_setdefault(libxl__gc *gc,
                                             libxl_domain_build_info *b_info,
                                             const libxl_physinfo *physinfo)
{
    /* ACPI is disabled by default */
    libxl_defbool_setdefault(&b_info->acpi, false);

    /* Sanitise SVE parameter */
    if (b_info->arch_arm.sve_vl) {
        unsigned int max_sve_vl =
            arch_capabilities_arm_sve(physinfo->arch_capabilities);

        if (!max_sve_vl) {
            LOG(ERROR, "SVE is unsupported on this machine.");
            return ERROR_FAIL;
        }

        if (LIBXL_SVE_TYPE_HW == b_info->arch_arm.sve_vl) {
            b_info->arch_arm.sve_vl = max_sve_vl;
        } else if (b_info->arch_arm.sve_vl > max_sve_vl) {
            LOG(ERROR,
                "Invalid sve value: %d. Platform supports up to %u bits",
                b_info->arch_arm.sve_vl, max_sve_vl);
            return ERROR_FAIL;
        } else if (b_info->arch_arm.sve_vl % 128) {
            LOG(ERROR,
                "Invalid sve value: %d. It must be multiple of 128",
                b_info->arch_arm.sve_vl);
            return ERROR_FAIL;
        }
    }

    if (b_info->type != LIBXL_DOMAIN_TYPE_PV)
        return 0;

    LOG(DEBUG, "Converting build_info to PVH");

    /* Re-initialize type to PVH and all associated fields to defaults. */
    memset(&b_info->u, '\0', sizeof(b_info->u));
    b_info->type = LIBXL_DOMAIN_TYPE_INVALID;
    libxl_domain_build_info_init_type(b_info, LIBXL_DOMAIN_TYPE_PVH);

    return 0;
}

int libxl__arch_passthrough_mode_setdefault(libxl__gc *gc,
                                            uint32_t domid,
                                            libxl_domain_config *d_config,
                                            const libxl_physinfo *physinfo)
{
    int rc;
    libxl_domain_create_info *const c_info = &d_config->c_info;

    if (c_info->passthrough == LIBXL_PASSTHROUGH_ENABLED) {
        c_info->passthrough = LIBXL_PASSTHROUGH_SHARE_PT;
    }

    switch (c_info->passthrough) {
    case LIBXL_PASSTHROUGH_DISABLED:
    case LIBXL_PASSTHROUGH_SHARE_PT:
        break;

    default:
        LOGD(ERROR, domid,
             "passthrough=\"%s\" not supported on ARM\n",
             libxl_passthrough_to_string(c_info->passthrough));
        rc = ERROR_INVAL;
        goto out;
    }

    rc = 0;
 out:
    return rc;
}

void libxl__arch_update_domain_config(libxl__gc *gc,
                                      libxl_domain_config *dst,
                                      const libxl_domain_config *src)
{
}

int libxl__arch_hvm_map_gsi(libxl__gc *gc, uint32_t sbdf, uint32_t domid)
{
    return ERROR_INVAL;
}

int libxl__arch_hvm_unmap_gsi(libxl__gc *gc, uint32_t sbdf, uint32_t domid)
{
    return ERROR_INVAL;
}

bool libxl__arch_local_domain_has_pirq_notion(libxl__gc *gc)
{
    return true;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
