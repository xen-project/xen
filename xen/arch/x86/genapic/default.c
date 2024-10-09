/* 
 * Default generic APIC driver. This handles upto 8 CPUs.
 */
#include <xen/cpumask.h>
#include <asm/current.h>
#include <asm/mpspec.h>
#include <asm/genapic.h>
#include <asm/fixmap.h>
#include <asm/apicdef.h>
#include <xen/kernel.h>
#include <xen/string.h>
#include <xen/smp.h>
#include <xen/init.h>
#include <asm/io_apic.h>

/* should be called last. */
const struct genapic __initconst_cf_clobber apic_default = {
	APIC_INIT("default", NULL),
	.int_delivery_mode = dest_Fixed,
	.int_dest_mode = 0, /* physical delivery */
	.init_apic_ldr = init_apic_ldr_flat,
	.vector_allocation_cpumask = vector_allocation_cpumask_phys,
	.cpu_mask_to_apicid = cpu_mask_to_apicid_phys,
	.send_IPI_mask = send_IPI_mask_flat,
	.send_IPI_self = send_IPI_self_legacy
};
