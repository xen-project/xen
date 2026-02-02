#include <xen/cpumask.h>
#include <xen/smp.h>

/*
 * FIXME: make pcpu_info[] dynamically allocated when necessary
 *        functionality will be ready
 */
/*
 * tp points to one of these per cpu.
 *
 * hart_id would be valid (no matter which value) if its
 * processor_id field is valid (less than NR_CPUS).
 */
struct pcpu_info pcpu_info[NR_CPUS] = { [0 ... NR_CPUS - 1] = {
    .processor_id = NR_CPUS,
}};

void smp_send_event_check_mask(const cpumask_t *mask)
{
    /* Catch missing implementation once SMP support is introduced */
    BUG_ON(!cpumask_subset(mask, cpumask_of(0)));
}
