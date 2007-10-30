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
    if ( memcmp(&tboot_shared_uuid, (uuid_t *)tboot_shared, sizeof(uuid_t)) )
        return;

    g_tboot_shared = tboot_shared;
    printk("TBOOT: found shared page at phys addr %lx:\n", p_tboot_shared);
    printk("  version: %d\n", tboot_shared->version);
    printk("  log_addr: 0x%08x\n", tboot_shared->log_addr);
    printk("  shutdown_entry32: 0x%08x\n", tboot_shared->shutdown_entry32);
    printk("  shutdown_entry64: 0x%08x\n", tboot_shared->shutdown_entry64);
    printk("  shutdown_type: %d\n", tboot_shared->shutdown_type);
    printk("  s3_tb_wakeup_entry: 0x%08x\n", tboot_shared->s3_tb_wakeup_entry);
    printk("  s3_k_wakeup_entry: 0x%08x\n", tboot_shared->s3_k_wakeup_entry);
    printk("  &acpi_sinfo: 0x%p\n", &tboot_shared->acpi_sinfo);
}

void tboot_shutdown(uint32_t shutdown_type)
{
    g_tboot_shared->shutdown_type = shutdown_type;

    local_irq_disable();

    /* Create identity map for 0-640k to include tboot code. */
    map_pages_to_xen(0, 0, PFN_UP(0xa0000), __PAGE_HYPERVISOR);
    write_ptbase(idle_vcpu[0]);

#ifdef __x86_64__
    asm volatile ( "call *%%rdi" :: "D" (g_tboot_shared->shutdown_entry64) );
#else
    asm volatile ( "call *%0" :: "r" (g_tboot_shared->shutdown_entry32) );
#endif

    BUG(); /* should not reach here */
}

int tboot_in_measured_env(void)
{
    return (g_tboot_shared != NULL);
}
