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
#include <asm/mach-default/mach_mpparse.h>

/* should be called last. */
static __init int probe_default(void)
{ 
	return 1;
} 

const struct genapic apic_default = {
	APIC_INIT("default", probe_default),
	GENAPIC_FLAT
};
