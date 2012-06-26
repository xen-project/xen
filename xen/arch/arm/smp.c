#include <xen/config.h>
#include <asm/system.h>
#include <asm/smp.h>
#include <asm/cpregs.h>
#include <asm/page.h>

void flush_tlb_mask(const cpumask_t *mask)
{
    /* XXX IPI other processors */
    flush_xen_data_tlb();
}

void smp_call_function(
    void (*func) (void *info),
    void *info,
    int wait)
{
    /* TODO: No SMP just now, does not include self so nothing to do.
       cpumask_t allbutself = cpu_online_map;
       cpu_clear(smp_processor_id(), allbutself);
       on_selected_cpus(&allbutself, func, info, wait);
    */
}
void smp_send_event_check_mask(const cpumask_t *mask)
{
    /* TODO: No SMP just now, does not include self so nothing to do.
       send_IPI_mask(mask, EVENT_CHECK_VECTOR);
    */
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
