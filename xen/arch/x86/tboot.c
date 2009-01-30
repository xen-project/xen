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

/* used by tboot_protect_mem_regions() and/or tboot_parse_dmar_table() */
static uint64_t txt_heap_base, txt_heap_size;
static uint64_t sinit_base, sinit_size;

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

#define SHA1_SIZE      20
typedef uint8_t   sha1_hash_t[SHA1_SIZE];

typedef struct __packed {
    uint32_t     version;             /* currently 6 */
    sha1_hash_t  bios_acm_id;
    uint32_t     edx_senter_flags;
    uint64_t     mseg_valid;
    sha1_hash_t  sinit_hash;
    sha1_hash_t  mle_hash;
    sha1_hash_t  stm_hash;
    sha1_hash_t  lcp_policy_hash;
    uint32_t     lcp_policy_control;
    uint32_t     rlp_wakeup_addr;
    uint32_t     reserved;
    uint32_t     num_mdrs;
    uint32_t     mdrs_off;
    uint32_t     num_vtd_dmars;
    uint32_t     vtd_dmars_off;
} sinit_mle_data_t;

void __init tboot_probe(void)
{
    tboot_shared_t *tboot_shared;
    unsigned long p_tboot_shared;
    uint32_t map_base, map_size;
    unsigned long map_addr;

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

    /* these will be needed by tboot_protect_mem_regions() and/or
       tboot_parse_dmar_table(), so get them now */

    map_base = PFN_DOWN(TXT_PUB_CONFIG_REGS_BASE);
    map_size = PFN_UP(NR_TXT_CONFIG_PAGES * PAGE_SIZE);
    map_addr = (unsigned long)__va(map_base << PAGE_SHIFT);
    if ( map_pages_to_xen(map_addr, map_base, map_size, __PAGE_HYPERVISOR) )
        return;

    /* TXT Heap */
    txt_heap_base =
        *(uint64_t *)__va(TXT_PUB_CONFIG_REGS_BASE + TXTCR_HEAP_BASE);
    txt_heap_size =
        *(uint64_t *)__va(TXT_PUB_CONFIG_REGS_BASE + TXTCR_HEAP_SIZE);

    /* SINIT */
    sinit_base =
        *(uint64_t *)__va(TXT_PUB_CONFIG_REGS_BASE + TXTCR_SINIT_BASE);
    sinit_size =
        *(uint64_t *)__va(TXT_PUB_CONFIG_REGS_BASE + TXTCR_SINIT_SIZE);

    destroy_xen_mappings((unsigned long)__va(map_base << PAGE_SHIFT),
                         (unsigned long)__va((map_base + map_size) << PAGE_SHIFT));
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
    int rc;

    if ( !tboot_in_measured_env() )
        return 1;

    /* TXT Heap */
    if ( txt_heap_base == 0 )
        return 0;
    rc = e820_change_range_type(
        &e820, txt_heap_base, txt_heap_base + txt_heap_size,
        E820_RESERVED, E820_UNUSABLE);
    if ( !rc )
        return 0;

    /* SINIT */
    if ( sinit_base == 0 )
        return 0;
    rc = e820_change_range_type(
        &e820, sinit_base, sinit_base + sinit_size,
        E820_RESERVED, E820_UNUSABLE);
    if ( !rc )
        return 0;

    /* TXT Private Space */
    rc = e820_change_range_type(
        &e820, TXT_PRIV_CONFIG_REGS_BASE,
        TXT_PRIV_CONFIG_REGS_BASE + NR_TXT_CONFIG_PAGES * PAGE_SIZE,
        E820_RESERVED, E820_UNUSABLE);
    if ( !rc )
        return 0;

    return 1;
}

int __init tboot_parse_dmar_table(acpi_table_handler dmar_handler)
{
    uint32_t map_base, map_size;
    unsigned long map_vaddr;
    void *heap_ptr;
    struct acpi_table_header *dmar_table;
    int rc;

    if ( !tboot_in_measured_env() )
        return acpi_table_parse(ACPI_SIG_DMAR, dmar_handler);

    /* ACPI tables may not be DMA protected by tboot, so use DMAR copy */
    /* SINIT saved in SinitMleData in TXT heap (which is DMA protected) */

    if ( txt_heap_base == 0 )
        return 1;

    /* map TXT heap into Xen addr space */
    map_base = PFN_DOWN(txt_heap_base);
    map_size = PFN_UP(txt_heap_size);
    map_vaddr = (unsigned long)__va(map_base << PAGE_SHIFT);
    if ( map_pages_to_xen(map_vaddr, map_base, map_size, __PAGE_HYPERVISOR) )
        return 1;

    /* walk heap to SinitMleData */
    heap_ptr = __va(txt_heap_base);
    /* skip BiosData */
    heap_ptr += *(uint64_t *)heap_ptr;
    /* skip OsMleData */
    heap_ptr += *(uint64_t *)heap_ptr;
    /* skip OsSinitData */
    heap_ptr += *(uint64_t *)heap_ptr;
    /* now points to SinitMleDataSize; set to SinitMleData */
    heap_ptr += sizeof(uint64_t);
    /* get addr of DMAR table */
    dmar_table = (struct acpi_table_header *)(heap_ptr +
            ((sinit_mle_data_t *)heap_ptr)->vtd_dmars_off - sizeof(uint64_t));

    rc = dmar_handler(dmar_table);

    destroy_xen_mappings(
        (unsigned long)__va(map_base << PAGE_SHIFT),
        (unsigned long)__va((map_base + map_size) << PAGE_SHIFT));
  
    /* acpi_parse_dmar() zaps APCI DMAR signature in TXT heap table */
    /* but dom0 will read real table, so must zap it there too */
    dmar_table = NULL;
    acpi_get_table(ACPI_SIG_DMAR, 0, &dmar_table);
    if ( dmar_table != NULL )
        ((struct acpi_table_dmar *)dmar_table)->header.signature[0] = '\0';

    return rc;
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
