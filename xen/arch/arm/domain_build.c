#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/domain_page.h>
#include <xen/sched.h>
#include <asm/irq.h>
#include <asm/regs.h>

#include "gic.h"
#include "kernel.h"

static unsigned int __initdata opt_dom0_max_vcpus;
integer_param("dom0_max_vcpus", opt_dom0_max_vcpus);

struct vcpu *__init alloc_dom0_vcpu0(void)
{
    dom0->vcpu = xmalloc_array(struct vcpu *, opt_dom0_max_vcpus);
    if ( !dom0->vcpu )
    {
            printk("failed to alloc dom0->vccpu\n");
        return NULL;
    }
    memset(dom0->vcpu, 0, opt_dom0_max_vcpus * sizeof(*dom0->vcpu));
    dom0->max_vcpus = opt_dom0_max_vcpus;

    return alloc_vcpu(dom0, 0, 0);
}

extern void guest_mode_entry(void);

static void setup_linux_atag(paddr_t tags, paddr_t ram_s, paddr_t ram_e)
{
    paddr_t ma = gvirt_to_maddr(tags);
    void *map = map_domain_page(ma>>PAGE_SHIFT);
    void *p = map + (tags & (PAGE_SIZE - 1));
    char cmdline[] = "earlyprintk=xenboot console=ttyAMA1 root=/dev/mmcblk0 debug rw";

    /* not enough room on this page for all the tags */
    BUG_ON(PAGE_SIZE - (tags & (PAGE_SIZE - 1)) < 8 * sizeof(uint32_t));

#define TAG(type, val) *(type*)p = val; p+= sizeof(type)

    /* ATAG_CORE */
    TAG(uint32_t, 2);
    TAG(uint32_t, 0x54410001);

    /* ATAG_MEM */
    TAG(uint32_t, 4);
    TAG(uint32_t, 0x54410002);
    TAG(uint32_t, (ram_e - ram_s) & 0xFFFFFFFF);
    TAG(uint32_t, ram_s & 0xFFFFFFFF);

    /* ATAG_CMDLINE */
    TAG(uint32_t, 2 + ((strlen(cmdline) + 4) >> 2));
    TAG(uint32_t, 0x54410009);
    memcpy(p, cmdline, strlen(cmdline) + 1);
    p += ((strlen(cmdline) + 4) >> 2) << 2;

    /* ATAG_NONE */
    TAG(uint32_t, 0);
    TAG(uint32_t, 0);

#undef TAG

    unmap_domain_page(map);
}

int construct_dom0(struct domain *d)
{
    struct kernel_info kinfo = {};
    int rc;

    struct vcpu *v = d->vcpu[0];
    struct cpu_user_regs *regs = &v->arch.cpu_info->guest_cpu_user_regs;

    /* Sanity! */
    BUG_ON(d->domain_id != 0);
    BUG_ON(d->vcpu[0] == NULL);
    BUG_ON(v->is_initialised);

    printk("*** LOADING DOMAIN 0 ***\n");

    /* 128M at 2G physical */
    /* TODO size and location from DT. */
    kinfo.ram_start = 0x80000000;
    kinfo.ram_end   = 0x88000000;

    rc = kernel_prepare(&kinfo);
    if (rc < 0)
        return rc;

    d->max_pages = ~0U;

    if ( (rc = p2m_alloc_table(d)) != 0 )
        return rc;

    printk("Populate P2M %#llx->%#llx\n", kinfo.ram_start, kinfo.ram_end);
    p2m_populate_ram(d, kinfo.ram_start, kinfo.ram_end);

    printk("Map CS2 MMIO regions 1:1 in the P2M %#llx->%#llx\n", 0x18000000ULL, 0x1BFFFFFFULL);
    map_mmio_regions(d, 0x18000000, 0x1BFFFFFF, 0x18000000);
    printk("Map CS3 MMIO regions 1:1 in the P2M %#llx->%#llx\n", 0x1C000000ULL, 0x1FFFFFFFULL);
    map_mmio_regions(d, 0x1C000000, 0x1FFFFFFF, 0x1C000000);
    printk("Map VGIC MMIO regions 1:1 in the P2M %#llx->%#llx\n", 0x2C008000ULL, 0x2DFFFFFFULL);
    map_mmio_regions(d, 0x2C008000, 0x2DFFFFFF, 0x2C008000);

    gicv_setup(d);

    printk("Routing peripheral interrupts to guest\n");
    /* TODO Get from device tree */
    gic_route_irq_to_guest(d, 34, "timer0");
    /*gic_route_irq_to_guest(d, 37, "uart0"); -- XXX used by Xen*/
    gic_route_irq_to_guest(d, 38, "uart1");
    gic_route_irq_to_guest(d, 39, "uart2");
    gic_route_irq_to_guest(d, 40, "uart3");
    gic_route_irq_to_guest(d, 41, "mmc0-1");
    gic_route_irq_to_guest(d, 42, "mmc0-2");
    gic_route_irq_to_guest(d, 44, "keyboard");
    gic_route_irq_to_guest(d, 45, "mouse");
    gic_route_irq_to_guest(d, 46, "lcd");
    gic_route_irq_to_guest(d, 47, "eth");

    /* Enable second stage translation */
    WRITE_CP32(READ_CP32(HCR) | HCR_VM, HCR); isb();

    /* The following load uses domain's p2m */
    p2m_load_VTTBR(d);

    kernel_load(&kinfo);

    setup_linux_atag(kinfo.ram_start + 0x100, kinfo.ram_start, kinfo.ram_end);

    clear_bit(_VPF_down, &v->pause_flags);

    memset(regs, 0, sizeof(*regs));

    regs->pc = (uint32_t)kinfo.entry;

    regs->cpsr = PSR_ABT_MASK|PSR_FIQ_MASK|PSR_IRQ_MASK|PSR_MODE_SVC;

/* FROM LINUX head.S

 * Kernel startup entry point.
 * ---------------------------
 *
 * This is normally called from the decompressor code.  The requirements
 * are: MMU = off, D-cache = off, I-cache = dont care, r0 = 0,
 * r1 = machine nr, r2 = atags or dtb pointer.
 *...
 */

    regs->r0 = 0; /* SBZ */
    regs->r1 = 2272; /* Machine NR: Versatile Express */
    regs->r2 = kinfo.ram_start + 0x100; /* ATAGS */

    WRITE_CP32(SCTLR_BASE, SCTLR);

    WRITE_CP32(HCR_AMO|HCR_IMO|HCR_VM, HCR);
    isb();

    local_abort_enable();

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
