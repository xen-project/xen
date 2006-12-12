
#include <xen/config.h>
#include <xen/init.h>
#include <xen/types.h>
#include <xen/cpumask.h>
#include <asm/cache.h>

/* representing HT siblings of each logical CPU */
cpumask_t cpu_sibling_map[NR_CPUS] __read_mostly;
EXPORT_SYMBOL(cpu_sibling_map);

/* representing HT and core siblings of each logical CPU */
cpumask_t cpu_core_map[NR_CPUS] __read_mostly;
EXPORT_SYMBOL(cpu_core_map);

/* bitmap of online cpus */
cpumask_t cpu_online_map __read_mostly;
EXPORT_SYMBOL(cpu_online_map);


#ifdef CONFIG_HOTPLUG_CPU
cpumask_t cpu_possible_map = CPU_MASK_ALL;
#else
cpumask_t cpu_possible_map;
#endif
EXPORT_SYMBOL(cpu_possible_map);

u8 x86_cpu_to_apicid[NR_CPUS] __read_mostly = { [0 ... NR_CPUS-1] = 0xff };
EXPORT_SYMBOL(x86_cpu_to_apicid);
