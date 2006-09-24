/* from xen/include/asm-x86/percpu.h */

#ifndef __PPC_PERCPU_H__
#define __PPC_PERCPU_H__

#define PERCPU_SHIFT 12
#define PERCPU_SIZE  (1UL << PERCPU_SHIFT)

/* We care out NR_CPUS bytes below the reset vector (0x100) so we can
 * track per-cpu state that we wish we had a register for. Currently
 * it is only used to track Cache Inhibited Mode when a Machine Check
 * occurs. */
/* NOTE: This array is indexed by PIR NOT CPUID */
#define MCK_GOOD_HID4 (0x100 - 8)
#define MCK_CPU_STAT_BASE (MCK_GOOD_HID4 - NR_CPUS) /* accomodate a hid4 */
/* Currently, the only state we track, so lets make it easy */
#define MCK_CPU_STAT_CI -1

#ifndef __ASSEMBLY__
#define mck_cpu_stats ((char *)MCK_CPU_STAT_BASE)
#define mck_good_hid4 ((ulong *)MCK_GOOD_HID4)

/* Separate out the type, so (int[3], foo) works. */
#define DEFINE_PER_CPU(type, name)                      \
    __attribute__((__section__(".data.percpu")))        \
    __typeof__(type) per_cpu__##name

/* var is in discarded region: offset to particular copy we want */
#define per_cpu(var, cpu)  \
    (*RELOC_HIDE(&per_cpu__##var, ((unsigned int)(cpu))<<PERCPU_SHIFT))
#define __get_cpu_var(var) \
    (per_cpu(var, smp_processor_id()))

#define DECLARE_PER_CPU(type, name) extern __typeof__(type) per_cpu__##name
#endif  /* __ASSEMBLY__ */
#endif /* __PPC_PERCPU_H__ */
