#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/percpu.h>

#include <asm/desc.h>

/*
 * Native and Compat GDTs used by Xen.
 *
 * The R1 and R3 descriptors are fixed in Xen's ABI for PV guests.  All other
 * descriptors are in principle variable, with the following restrictions.
 *
 * All R0 descriptors must line up in both GDTs to allow for correct
 * interrupt/exception handling.
 *
 * The SYSCALL/SYSRET GDT layout requires:
 *  - R0 long mode code followed by R0 data.
 *  - R3 compat code, followed by R3 data, followed by R3 long mode code.
 *
 * The SYSENTER GDT layout requirements are compatible with SYSCALL.  Xen does
 * not use the SYSEXIT instruction, and does not provide a compatible GDT.
 *
 * These tables are used directly by CPU0, and used as the template for the
 * GDTs of other CPUs.  Everything from the TSS onwards is unique per CPU.
 */

#define SEL2GDT(sel) (((sel) >> 3) - FIRST_RESERVED_GDT_ENTRY)

__section(".data.page_aligned") __aligned(PAGE_SIZE)
seg_desc_t boot_gdt[PAGE_SIZE / sizeof(seg_desc_t)] =
{
    /* 0xe008 - Ring 0 code, 64bit mode */
    [SEL2GDT(__HYPERVISOR_CS)] =      { 0x00af9b000000ffff },

    /* 0xe010 - Ring 0 data */
    [SEL2GDT(__HYPERVISOR_DS32)] =    { 0x00cf93000000ffff },

    /* 0xe018 - reserved */

    /* 0xe023 - Ring 3 code, compatibility */
    [SEL2GDT(FLAT_RING3_CS32)] =      { 0x00cffb000000ffff },

    /* 0xe02b - Ring 3 data */
    [SEL2GDT(FLAT_RING3_DS32)] =      { 0x00cff3000000ffff },

    /* 0xe033 - Ring 3 code, 64-bit mode */
    [SEL2GDT(FLAT_RING3_CS64)] =      { 0x00affb000000ffff },

    /* 0xe038 - reserved */
    /* 0xe040 - TSS */
    /* 0xe050 - LDT */

    /* 0xe060 - per-CPU entry (limit == cpu) */
    [SEL2GDT(PER_CPU_SELECTOR)] =     { 0x0000910000000000 },
};

#ifdef CONFIG_PV32
__section(".data.page_aligned") __aligned(PAGE_SIZE)
seg_desc_t boot_compat_gdt[PAGE_SIZE / sizeof(seg_desc_t)] =
{
    /* 0xe008 - Ring 0 code, 64bit mode */
    [SEL2GDT(__HYPERVISOR_CS)] =      { 0x00af9b000000ffff },

    /* 0xe010 - Ring 0 data */
    [SEL2GDT(__HYPERVISOR_DS32)] =    { 0x00cf93000000ffff },

    /* 0xe019 - Ring 1 code, compatibility */
    [SEL2GDT(FLAT_COMPAT_RING1_CS)] = { 0x00cfbb000000ffff },

    /* 0xe021 - Ring 1 data */
    [SEL2GDT(FLAT_COMPAT_RING1_DS)] = { 0x00cfb3000000ffff },

    /* 0xe02b - Ring 3 code, compatibility */
    [SEL2GDT(FLAT_COMPAT_RING3_CS)] = { 0x00cffb000000ffff },

    /* 0xe033 - Ring 3 data */
    [SEL2GDT(FLAT_COMPAT_RING3_DS)] = { 0x00cff3000000ffff },

    /* 0xe038 - reserved */
    /* 0xe040 - TSS */
    /* 0xe050 - LDT */

    /* 0xe060 - per-CPU entry (limit == cpu) */
    [SEL2GDT(PER_CPU_SELECTOR)] =     { 0x0000910000000000 },
};
#endif

/*
 * Used by each CPU as it starts up, to enter C with a suitable %cs.
 * References boot_cpu_gdt_table for a short period, until the CPUs switch
 * onto their per-CPU GDTs.
 */
const struct desc_ptr boot_gdtr = {
    .limit = LAST_RESERVED_GDT_BYTE,
    .base = (unsigned long)(boot_gdt - FIRST_RESERVED_GDT_ENTRY),
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
