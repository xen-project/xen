#ifndef __X86_PERCPU_H__
#define __X86_PERCPU_H__

#define PARK_OFFLINE_CPUS_VAR

/*
 * Force uses of per_cpu() with an invalid area to attempt to access the
 * middle of the non-canonical address space resulting in a #GP, rather than a
 * possible #PF at (NULL + a little) which has security implications in the
 * context of PV guests.
 */
#define INVALID_PERCPU_AREA (0x8000000000000000UL - (unsigned long)__per_cpu_start)

#endif /* __X86_PERCPU_H__ */
