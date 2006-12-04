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
#include <asm/kexec.h>
#include <xen/domain_page.h>
#include <asm/fixmap.h>
#include <asm/hvm/hvm.h>

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
            set_fixmap(fix_base + (k >> 1), prev_ma);
            image->page_list[k] = fix_to_virt(fix_base + (k >> 1));
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
