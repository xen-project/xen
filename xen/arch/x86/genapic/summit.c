/* 
 * APIC driver for the IBM "Summit" chipset.
 */
#include <xen/config.h>
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
#include <asm/mach-summit/mach_mpparse.h>

static __init int probe_summit(void)
{ 
	/* probed later in mptable/ACPI hooks */
	return 0;
} 

const struct genapic apic_summit = {
	APIC_INIT("summit", probe_summit),
	GENAPIC_PHYS
};
