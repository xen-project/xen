#include <xen/config.h>
#include <asm/system.h>
#include <asm/smp.h>
#include <asm/cpregs.h>
#include <asm/page.h>
#include <asm/gic.h>
#include <asm/flushtlb.h>

void flush_tlb_mask(const cpumask_t *mask)
{
    /* No need to IPI other processors on ARM, the processor takes care of it. */
    flush_tlb_all();
}

void smp_send_event_check_mask(const cpumask_t *mask)
{
    send_SGI_mask(mask, GIC_SGI_EVENT_CHECK);
}

void smp_send_call_function_mask(const cpumask_t *mask)
{
    cpumask_t target_mask;

    cpumask_andnot(&target_mask, mask, cpumask_of(smp_processor_id()));

    send_SGI_mask(&target_mask, GIC_SGI_CALL_FUNCTION);

    if ( cpumask_test_cpu(smp_processor_id(), mask) )
    {
        local_irq_disable();
        smp_call_function_interrupt();
        local_irq_enable();
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
