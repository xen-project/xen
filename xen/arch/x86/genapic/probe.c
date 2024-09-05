/* Copyright 2003 Andi Kleen, SuSE Labs.
 * Subject to the GNU Public License, v.2
 *
 * Generic x86 APIC driver probe layer.
 */
#include <xen/bug.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/param.h>
#include <xen/sections.h>
#include <xen/string.h>
#include <xen/types.h>

#include <asm/apic.h>
#include <asm/genapic.h>

struct genapic __ro_after_init genapic;

static const struct genapic *const __initconstrel apic_probe[] = {
	&apic_bigsmp,
	&apic_default,	/* must be last */
	NULL,
};

static bool __initdata forced_apic;

void __init generic_bigsmp_probe(void)
{
	/*
	 * This routine is used to switch to bigsmp mode when
	 * - There is no apic= option specified by the user
	 * - generic_apic_probe() has choosen apic_default as the sub_arch
	 * - we find more than 8 CPUs in acpi LAPIC listing with xAPIC support
	 */

	if (!forced_apic && genapic.name == apic_default.name)
		if (apic_bigsmp.probe()) {
			genapic = apic_bigsmp;
			printk(KERN_INFO "Overriding APIC driver with %s\n",
			       genapic.name);
		}
}

static int __init cf_check genapic_apic_force(const char *str)
{
	int i, rc = -EINVAL;

	for (i = 0; apic_probe[i]; i++)
		if (!strcmp(apic_probe[i]->name, str)) {
			genapic = *apic_probe[i];
			rc = 0;
		}

	return rc;
}
custom_param("apic", genapic_apic_force);

void __init generic_apic_probe(void)
{
	int i;

	record_boot_APIC_mode();

	check_x2apic_preenabled();

	forced_apic = genapic.name;

	for (i = 0; !genapic.name && apic_probe[i]; i++) {
		if (!apic_probe[i]->probe || apic_probe[i]->probe())
			genapic = *apic_probe[i];
	}

	BUG_ON(!genapic.name);

	printk(KERN_INFO "Using APIC driver %s\n", genapic.name);
}
