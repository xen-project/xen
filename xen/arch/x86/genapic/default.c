/* 
 * Default generic APIC driver. This handles upto 8 CPUs.
 */
#define APIC_DEFINITION 1
#include <xen/config.h>
#include <xen/cpumask.h>
#include <asm/current.h>
#include <asm/mpspec.h>
#include <asm/mach-default/mach_apicdef.h>
#include <asm/genapic.h>
#include <asm/fixmap.h>
#include <asm/apicdef.h>
#include <xen/kernel.h>
#include <xen/string.h>
#include <xen/smp.h>
#include <xen/init.h>
#include <asm/mach-default/mach_apic.h>
#include <asm/mach-default/mach_ipi.h>
#include <asm/mach-default/mach_mpparse.h>

#ifdef CONFIG_HOTPLUG_CPU
#define DEFAULT_SEND_IPI	(1)
#else
#define DEFAULT_SEND_IPI	(0)
#endif

int no_broadcast = DEFAULT_SEND_IPI;
integer_param("no_ipi_broadcast", no_broadcast);

/* should be called last. */
static __init int probe_default(void)
{ 
	return 1;
} 

struct genapic apic_default = APIC_INIT("default", probe_default); 

static int __init print_ipi_mode(void)
{
	if (genapic == &apic_default)
		printk("Using IPI %sShortcut mode\n",
		       no_broadcast ? "No-" : "");
	return 0;
}
__initcall(print_ipi_mode);
