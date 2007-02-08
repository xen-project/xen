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

typedef void (*relocate_new_kernel_t)(
                unsigned long indirection_page,
                unsigned long *page_list,
                unsigned long start_address);

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
            if ( IS_COMPAT(dom0) )
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

static void __machine_reboot_kexec(void *data)
{
    xen_kexec_image_t *image = (xen_kexec_image_t *)data;

    watchdog_disable();
    console_start_sync();

    smp_send_stop();

#ifdef CONFIG_X86_IO_APIC
    disable_IO_APIC();
#endif
    hvm_disable();

    machine_kexec(image);
}

void machine_reboot_kexec(xen_kexec_image_t *image)
{
    int reboot_cpu_id;
    cpumask_t reboot_cpu;

    reboot_cpu_id = 0;

    if ( !cpu_isset(reboot_cpu_id, cpu_online_map) )
        reboot_cpu_id = smp_processor_id();

    if ( reboot_cpu_id != smp_processor_id() )
    {
        cpus_clear(reboot_cpu);
        cpu_set(reboot_cpu_id, reboot_cpu);
        on_selected_cpus(reboot_cpu, __machine_reboot_kexec, image, 1, 0);
        for (;;)
                ; /* nothing */
    }
    else
    {
        __machine_reboot_kexec(image);
    }
    BUG();
}

void machine_kexec(xen_kexec_image_t *image)
{
#ifdef CONFIG_COMPAT
    if ( IS_COMPAT(dom0) )
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
