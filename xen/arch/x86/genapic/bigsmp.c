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
#include <asm/mach-default/mach_mpparse.h>
#include <asm/io_apic.h>

static __init int force_bigsmp(struct dmi_system_id *d)
{
	printk(KERN_NOTICE "%s detected: force use of apic=bigsmp\n", d->ident);
	def_to_bigsmp = true;
	return 0;
}


static struct dmi_system_id __initdata bigsmp_dmi_table[] = {
	{ force_bigsmp, "UNISYS ES7000-ONE", {
		DMI_MATCH(DMI_PRODUCT_NAME, "ES7000-ONE")
	 }},
	
	 { }
};


static __init int probe_bigsmp(void)
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

const struct genapic apic_bigsmp = {
	APIC_INIT("bigsmp", probe_bigsmp),
	GENAPIC_PHYS
};
