#ifndef __ASM_SMP_H
#define __ASM_SMP_H

/*
 * We need the APIC definitions automatically as part of 'smp.h'
 */
#ifndef __ASSEMBLY__
#include <xen/config.h>
#include <xen/kernel.h>
#include <xen/cpumask.h>
#include <asm/current.h>
#endif

#ifndef __ASSEMBLY__
#include <xen/bitops.h>
#include <asm/mpspec.h>
#endif

#define BAD_APICID   (-1U)
#define INVALID_CUID (~0U)   /* AMD Compute Unit ID */
#ifndef __ASSEMBLY__

/*
 * Private routines/data
 */
DECLARE_PER_CPU(cpumask_var_t, cpu_sibling_mask);
DECLARE_PER_CPU(cpumask_var_t, cpu_core_mask);

void smp_send_nmi_allbutself(void);

void send_IPI_mask(const cpumask_t *, int vector);
void send_IPI_self(int vector);

extern void (*mtrr_hook) (void);

extern void zap_low_mappings(void);

extern u32 x86_cpu_to_apicid[];

#define cpu_physical_id(cpu)	x86_cpu_to_apicid[cpu]

#define cpu_is_offline(cpu) unlikely(!cpu_online(cpu))
extern void cpu_exit_clear(unsigned int cpu);
extern void cpu_uninit(unsigned int cpu);
int cpu_add(uint32_t apic_id, uint32_t acpi_id, uint32_t pxm);

/*
 * This function is needed by all SMP systems. It must _always_ be valid
 * from the initial startup. We map APIC_BASE very early in page_setup(),
 * so this is correct in the x86 case.
 */
#define raw_smp_processor_id() (get_processor_id())

void __stop_this_cpu(void);

long cpu_up_helper(void *data);
long cpu_down_helper(void *data);

long core_parking_helper(void *data);
uint32_t get_cur_idle_nums(void);

/*
 * The value may be greater than the actual socket number in the system and
 * is required not to change from the initial startup.
 */
extern unsigned int nr_sockets;

void set_nr_sockets(void);

/* Representing HT and core siblings in each socket. */
extern cpumask_t **socket_cpumask;

#endif /* !__ASSEMBLY__ */

#endif
