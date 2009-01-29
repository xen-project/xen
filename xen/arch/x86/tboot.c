#include <xen/config.h>
#include <xen/init.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/fixmap.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/tboot.h>

/* tboot=<physical address of shared page> */
static char opt_tboot[20] = "";
string_param("tboot", opt_tboot);

/* Global pointer to shared data; NULL means no measured launch. */
tboot_shared_t *g_tboot_shared;

static const uuid_t tboot_shared_uuid = TBOOT_SHARED_UUID;

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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
