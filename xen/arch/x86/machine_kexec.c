/******************************************************************************
 * machine_kexec.c
 *
 * Xen port written by:
 * - Simon 'Horms' Horman <horms@verge.net.au>
 * - Magnus Damm <magnus@valinux.co.jp>
 */

#include <xen/lib.h>
#include <asm/irq.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <xen/smp.h>
#include <xen/nmi.h>
#include <xen/types.h>
#include <xen/console.h>
#include <xen/kexec.h>
#include <xen/domain_page.h>
#include <asm/fixmap.h>
#include <asm/hvm/hvm.h>
#include <asm/hpet.h>

typedef void (*relocate_new_kernel_t)(
                unsigned long indirection_page,
                unsigned long *page_list,
                unsigned long start_address);

extern int machine_kexec_get_xen(xen_kexec_range_t *range);


int machine_kexec_load(int type, int slot, xen_kexec_image_t *image)
{
    unsigned long prev_ma = 0;
    int fix_base = FIX_KEXEC_BASE_0 + (slot * (KEXEC_XEN_NO_PAGES >> 1));
    int k;

    /* setup fixmap to point to our pages and record the virtual address
     * in every odd index in page_list[].
     */

    for ( k = 0; k < KEXEC_XEN_NO_PAGES; k++ )
    {
        if ( (k & 1) == 0 )
        {
            /* Even pages: machine address. */
            prev_ma = image->page_list[k];
        }
        else
        {
            /* Odd pages: va for previous ma. */
            if ( is_pv_32on64_domain(dom0) )
            {
                /*
                 * The compatability bounce code sets up a page table
                 * with a 1-1 mapping of the first 1G of memory so
                 * VA==PA here.
                 *
                 * This Linux purgatory code still sets up separate
                 * high and low mappings on the control page (entries
                 * 0 and 1) but it is harmless if they are equal since
                 * that PT is not live at the time.
                 */
                image->page_list[k] = prev_ma;
            }
            else
            {
                set_fixmap(fix_base + (k >> 1), prev_ma);
                image->page_list[k] = fix_to_virt(fix_base + (k >> 1));
            }
        }
    }

    return 0;
}

void machine_kexec_unload(int type, int slot, xen_kexec_image_t *image)
{
}

void machine_reboot_kexec(xen_kexec_image_t *image)
{
    BUG_ON(smp_processor_id() != 0);
    smp_send_stop();
    machine_kexec(image);
    BUG();
}

void machine_kexec(xen_kexec_image_t *image)
{
    struct desc_ptr gdt_desc = {
        .base = (unsigned long)(boot_cpu_gdt_table - FIRST_RESERVED_GDT_ENTRY),
        .limit = LAST_RESERVED_GDT_BYTE
    };

    if ( hpet_broadcast_is_available() )
        hpet_disable_legacy_broadcast();

    /*
     * compat_machine_kexec() returns to idle pagetables, which requires us
     * to be running on a static GDT mapping (idle pagetables have no GDT
     * mappings in their per-domain mapping area).
     */
    asm volatile ( "lgdt %0" : : "m" (gdt_desc) );

#ifdef CONFIG_COMPAT
    if ( is_pv_32on64_domain(dom0) )
    {
        extern void compat_machine_kexec(unsigned long rnk,
                                         unsigned long indirection_page,
                                         unsigned long *page_list,
                                         unsigned long start_address);
        compat_machine_kexec(image->page_list[1],
                             image->indirection_page,
                             image->page_list,
                             image->start_address);
    }
    else
#endif
    {
        relocate_new_kernel_t rnk;

        rnk = (relocate_new_kernel_t) image->page_list[1];
        (*rnk)(image->indirection_page, image->page_list,
               image->start_address);
    }
}

int machine_kexec_get(xen_kexec_range_t *range)
{
	if (range->range != KEXEC_RANGE_MA_XEN)
		return -EINVAL;
	return machine_kexec_get_xen(range);
}

void arch_crash_save_vmcoreinfo(void)
{
	VMCOREINFO_SYMBOL(dom_xen);
	VMCOREINFO_SYMBOL(dom_io);

#ifdef CONFIG_X86_32
    VMCOREINFO_SYMBOL(xenheap_phys_end);
#endif
#ifdef CONFIG_X86_PAE
	VMCOREINFO_SYMBOL_ALIAS(pgd_l3, idle_pg_table);
#endif
#ifdef CONFIG_X86_64
	VMCOREINFO_SYMBOL_ALIAS(pgd_l4, idle_pg_table);
#endif
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
