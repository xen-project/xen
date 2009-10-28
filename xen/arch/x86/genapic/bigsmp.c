#include <xen/config.h>
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

static int dmi_bigsmp; /* can be set by dmi scanners */

static __init int force_bigsmp(struct dmi_system_id *d)
{
	printk(KERN_NOTICE "%s detected: force use of apic=bigsmp\n", d->ident);
	dmi_bigsmp = 1;
	return 0;
}


static struct dmi_system_id __initdata bigsmp_dmi_table[] = {
	{ force_bigsmp, "HP ProLiant DL760 G2", {
		DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
		DMI_MATCH(DMI_BIOS_VERSION, "P44-"),
	}},

	{ force_bigsmp, "HP ProLiant DL740", {
		DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
		DMI_MATCH(DMI_BIOS_VERSION, "P47-"),
	 }},
	{ force_bigsmp, "UNISYS ES7000-ONE", {
		DMI_MATCH(DMI_PRODUCT_NAME, "ES7000-ONE")
	 }},
	
	 { }
};


static __init int probe_bigsmp(void)
{ 
	if (def_to_bigsmp)
		dmi_bigsmp = 1;
	else
		dmi_check_system(bigsmp_dmi_table);
	return dmi_bigsmp;
} 

const struct genapic apic_bigsmp = {
	APIC_INIT("bigsmp", probe_bigsmp),
	GENAPIC_PHYS
};
