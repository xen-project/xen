#include <xen/cpumask.h>
#include <asm/current.h>
#include <asm/mpspec.h>
#include <asm/genapic.h>
#include <asm/fixmap.h>
#include <asm/apicdef.h>
#include <xen/kernel.h>
#include <xen/smp.h>
#include <xen/init.h>
#include <xen/dmi.h>
#include <asm/io_apic.h>

static int __init cf_check force_bigsmp(const struct dmi_system_id *d)
{
	printk(KERN_NOTICE "%s detected: force use of apic=bigsmp\n", d->ident);
	def_to_bigsmp = true;
	return 0;
}


static const struct dmi_system_id __initconstrel bigsmp_dmi_table[] = {
	{
	    .ident = "UNISYS ES7000-ONE",
	    .callback = force_bigsmp,
	    DMI_MATCH1(
		DMI_MATCH(DMI_PRODUCT_NAME, "ES7000-ONE")),
	},
	
	{ }
};


static int __init cf_check probe_bigsmp(void)
{ 
	/*
	 * We don't implement cluster mode, so force use of
	 * physical mode in both cases.
	 */
	if (acpi_gbl_FADT.flags &
	    (ACPI_FADT_APIC_CLUSTER | ACPI_FADT_APIC_PHYSICAL))
		def_to_bigsmp = true;
	else if (!def_to_bigsmp)
		dmi_check_system(bigsmp_dmi_table);
	return def_to_bigsmp;
} 

const struct genapic __initconst_cf_clobber apic_bigsmp = {
	APIC_INIT("bigsmp", probe_bigsmp),
	.int_delivery_mode = dest_Fixed,
	.int_dest_mode = 0, /* physical delivery */
	.init_apic_ldr = init_apic_ldr_phys,
	.vector_allocation_cpumask = vector_allocation_cpumask_phys,
	.cpu_mask_to_apicid = cpu_mask_to_apicid_phys,
	.send_IPI_mask = send_IPI_mask_phys,
	.send_IPI_self = send_IPI_self_legacy
};
