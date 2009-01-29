#include <xen/config.h>
#include <xen/init.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/fixmap.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/e820.h>
#include <asm/tboot.h>

/* tboot=<physical address of shared page> */
static char opt_tboot[20] = "";
string_param("tboot", opt_tboot);

/* Global pointer to shared data; NULL means no measured launch. */
tboot_shared_t *g_tboot_shared;

static const uuid_t tboot_shared_uuid = TBOOT_SHARED_UUID;

/*
 * TXT configuration registers (offsets from TXT_{PUB, PRIV}_CONFIG_REGS_BASE)
 */

#define TXT_PUB_CONFIG_REGS_BASE       0xfed30000
#define TXT_PRIV_CONFIG_REGS_BASE      0xfed20000

/* # pages for each config regs space - used by fixmap */
#define NR_TXT_CONFIG_PAGES     ((TXT_PUB_CONFIG_REGS_BASE -                \
                                  TXT_PRIV_CONFIG_REGS_BASE) >> PAGE_SHIFT)

/* offsets from pub/priv config space */
#define TXTCR_SINIT_BASE            0x0270
#define TXTCR_SINIT_SIZE            0x0278
#define TXTCR_HEAP_BASE             0x0300
#define TXTCR_HEAP_SIZE             0x0308

extern char __init_begin[], __per_cpu_start[], __per_cpu_end[], __bss_start[];

void __init tboot_probe(void)
{
    tboot_shared_t *tboot_shared;
    unsigned long p_tboot_shared;

    /* Look for valid page-aligned address for shared page. */
    p_tboot_shared = simple_strtoul(opt_tboot, NULL, 0);
    if ( (p_tboot_shared == 0) || ((p_tboot_shared & ~PAGE_MASK) != 0) )
        return;

    /* Map and check for tboot UUID. */
    set_fixmap(FIX_TBOOT_SHARED_BASE, p_tboot_shared);
    tboot_shared = (tboot_shared_t *)fix_to_virt(FIX_TBOOT_SHARED_BASE);
    if ( tboot_shared == NULL )
        return;
    if ( memcmp(&tboot_shared_uuid, (uuid_t *)tboot_shared, sizeof(uuid_t)) )
        return;

    /* new tboot_shared (w/ GAS support) is not backwards compatible */
    if ( tboot_shared->version < 3 ) {
        printk("unsupported version of tboot (%u)\n", tboot_shared->version);
        return;
    }

    g_tboot_shared = tboot_shared;
    printk("TBOOT: found shared page at phys addr %lx:\n", p_tboot_shared);
    printk("  version: %d\n", tboot_shared->version);
    printk("  log_addr: 0x%08x\n", tboot_shared->log_addr);
    printk("  shutdown_entry: 0x%08x\n", tboot_shared->shutdown_entry);
    printk("  tboot_base: 0x%08x\n", tboot_shared->tboot_base);
    printk("  tboot_size: 0x%x\n", tboot_shared->tboot_size);
}

void tboot_shutdown(uint32_t shutdown_type)
{
    uint32_t map_base, map_size;
    int err;

    g_tboot_shared->shutdown_type = shutdown_type;

    local_irq_disable();

    /* if this is S3 then set regions to MAC */
    if ( shutdown_type == TB_SHUTDOWN_S3 ) {
        g_tboot_shared->num_mac_regions = 4;
        /* S3 resume code (and other real mode trampoline code) */
        g_tboot_shared->mac_regions[0].start =
            (uint64_t)bootsym_phys(trampoline_start);
        g_tboot_shared->mac_regions[0].end =
            (uint64_t)bootsym_phys(trampoline_end);
        /* hypervisor code + data */
        g_tboot_shared->mac_regions[1].start = (uint64_t)__pa(&_stext);
        g_tboot_shared->mac_regions[1].end = (uint64_t)__pa(&__init_begin);
        /* per-cpu data */
        g_tboot_shared->mac_regions[2].start = (uint64_t)__pa(&__per_cpu_start);
        g_tboot_shared->mac_regions[2].end = (uint64_t)__pa(&__per_cpu_end);
        /* bss */
        g_tboot_shared->mac_regions[3].start = (uint64_t)__pa(&__bss_start);
        g_tboot_shared->mac_regions[3].end = (uint64_t)__pa(&_end);
    }

    /* Create identity map for tboot shutdown code. */
    map_base = PFN_DOWN(g_tboot_shared->tboot_base);
    map_size = PFN_UP(g_tboot_shared->tboot_size);

    err = map_pages_to_xen(map_base << PAGE_SHIFT, map_base, map_size,
                           __PAGE_HYPERVISOR);
    if ( err != 0 )
    {
        printk("error (0x%x) mapping tboot pages (mfns) @ 0x%x, 0x%x\n", err,
               map_base, map_size);
        return;
    }

    write_ptbase(idle_vcpu[0]);

    ((void(*)(void))(unsigned long)g_tboot_shared->shutdown_entry)();

    BUG(); /* should not reach here */
}

int tboot_in_measured_env(void)
{
    return (g_tboot_shared != NULL);
}

int __init tboot_protect_mem_regions(void)
{
    uint64_t base, size;
    uint32_t map_base, map_size;
    unsigned long map_addr;
    int rc;

    if ( !tboot_in_measured_env() )
        return 1;

    map_base = PFN_DOWN(TXT_PUB_CONFIG_REGS_BASE);
    map_size = PFN_UP(NR_TXT_CONFIG_PAGES * PAGE_SIZE);
    map_addr = (unsigned long)__va(map_base << PAGE_SHIFT);
    if ( map_pages_to_xen(map_addr, map_base, map_size, __PAGE_HYPERVISOR) )
        return 0;

    /* TXT Heap */
    base = *(uint64_t *)__va(TXT_PUB_CONFIG_REGS_BASE + TXTCR_HEAP_BASE);
    size = *(uint64_t *)__va(TXT_PUB_CONFIG_REGS_BASE + TXTCR_HEAP_SIZE);
    rc = e820_change_range_type(
        &e820, base, base + size, E820_RESERVED, E820_UNUSABLE);
    if ( !rc )
        return 0;

    /* SINIT */
    base = *(uint64_t *)__va(TXT_PUB_CONFIG_REGS_BASE + TXTCR_SINIT_BASE);
    size = *(uint64_t *)__va(TXT_PUB_CONFIG_REGS_BASE + TXTCR_SINIT_SIZE);
    rc = e820_change_range_type(
        &e820, base, base + size, E820_RESERVED, E820_UNUSABLE);
    if ( !rc )
        return 0;

    /* TXT Private Space */
    rc = e820_change_range_type(
        &e820, TXT_PRIV_CONFIG_REGS_BASE,
        TXT_PRIV_CONFIG_REGS_BASE + NR_TXT_CONFIG_PAGES * PAGE_SIZE,
        E820_RESERVED, E820_UNUSABLE);
    if ( !rc )
        return 0;

    destroy_xen_mappings(
        (unsigned long)__va(map_base << PAGE_SHIFT),
        (unsigned long)__va((map_base + map_size) << PAGE_SHIFT));

    return 1;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
