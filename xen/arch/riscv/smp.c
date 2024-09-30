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
