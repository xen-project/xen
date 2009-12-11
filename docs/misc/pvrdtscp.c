/* pvrdtscp algorithm
 *
 * This sample code demonstrates the use of the paravirtualized rdtscp
 * algorithm.  Using this algorithm, an application may communicate with
 * the Xen hypervisor (version 4.0+) to obtain timestamp information which
 * is both monotonically increasing and has a fixed 1 GHz rate, even across
 * migrations between machines with different TSC rates and offsets.
 * Further,the algorithm provides performance near the performance of a
 * native rdtsc/rdtscp instruction -- much faster than emulation PROVIDED
 * the application is running on a machine on which the rdtscp instruction
 * is supported and TSC is "safe". The application must also be running in a
 * PV domain.  (HVM domains may be supported at a later time.) On machines
 * where TSC is unsafe or the rdtscp instruction is not supported, Xen
 * (v4.0+) provides emulation which is slower but consistent with the pvrdtscp
 * algorithm, thus providing support for the algorithm for live migration
 * across all machines.
 *
 * More information can be found within the Xen (4.0+) source tree at
 *  docs/misc/tscmode.txt
 *
 * Copyright (c) 2009 Oracle Corporation and/or its affiliates.
 * All rights reserved
 * Written by: Dan Magenheimer <dan.magenheimer@oracle.com>
 * 
 * This code is derived from code licensed under the GNU
 * General Public License ("GPL") version 2 and is therefore itself
 * also licensed under the GPL version 2.
 *
 * This code is known to compile and run on Oracle Enterprise Linux 5 Update 2
 * using gcc version 4.1.2, but its purpose is to describe the pvrdtscp
 * algorithm and its ABI to Xen version 4.0+ 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#ifdef __LP64__
#define __X86_64__
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef int i32;
typedef long i64;
#define NSEC_PER_SEC 1000000000
#else
#define __X86_32__
typedef unsigned int u16;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef long i32;
typedef long long i64;
#define NSEC_PER_SEC 1000000000L
#endif

static inline void hvm_cpuid(u32 idx, u32 sub,
				u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
	*eax = idx, *ecx = sub;
	asm("cpuid" : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
	    : "0" (*eax), "2" (*ecx));
}

static inline void pv_cpuid(u32 idx, u32 sub,
				u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
	*eax = idx, *ecx = sub;
	asm volatile ( "ud2a ; .ascii \"xen\"; cpuid" : "=a" (*eax),
            "=b" (*ebx), "=c" (*ecx), "=d" (*edx) : "0" (*eax), "2" (*ecx));
}

static inline u64 do_rdtscp(u32 *aux)
{
static u64 last = 0;
	u32 lo32, hi32;
	u64 val;

	asm volatile(".byte 0x0f,0x01,0xf9":"=a"(lo32),"=d"(hi32),"=c" (*aux));
	val = lo32 | ((u64)hi32 << 32);
	return val;
}

static inline int get_xen_tsc_mode(void)
{
	u32 val, dummy1, dummy2, dummy3;
	pv_cpuid(0x40000003,0,&dummy1,&val,&dummy2,&dummy3);
	return val;
}

static inline int get_xen_vtsc(void)
{
	u32 val, dummy1, dummy2, dummy3;
	pv_cpuid(0x40000003,0,&val,&dummy1,&dummy2,&dummy3);
	return val & 1;
}

static inline int get_xen_vtsc_khz(void)
{
	u32 val, dummy1, dummy2, dummy3;
	pv_cpuid(0x40000003,0,&dummy1,&dummy2,&val,&dummy3);
	return val;
}

static inline u32 get_xen_cpu_khz(void)
{
	u32 cpu_khz, dummy1, dummy2, dummy3;
	pv_cpuid(0x40000003,2,&cpu_khz,&dummy1,&dummy2,&dummy3);
	return cpu_khz;
}

static inline u32 get_xen_incarnation(void)
{
	u32 incarn, dummy1, dummy2, dummy3;
	pv_cpuid(0x40000003,0,&dummy1,&dummy2,&dummy3,&incarn);
	return incarn;
}

static inline void get_xen_time_values(u64 *offset, u32 *mul_frac, u32 *shift)
{
	u32 off_lo, off_hi, sys_lo, sys_hi, dummy;

	pv_cpuid(0x40000003,1,&off_lo,&off_hi,mul_frac,shift);
	*offset = off_lo | ((u64)off_hi << 32);
}

static inline u64 scale_delta(u64 delta, u32 tsc_mul_frac, i32 tsc_shift)
{
    u64 product;
#ifdef __X86_32__
    u32 tmp1, tmp2;
#endif

    if ( tsc_shift < 0 )
        delta >>= -tsc_shift;
    else
        delta <<= tsc_shift;

#ifdef __X86_32__
    asm (
        "mul  %5       ; "
        "mov  %4,%%eax ; "
        "mov  %%edx,%4 ; "
        "mul  %5       ; "
        "xor  %5,%5    ; "
        "add  %4,%%eax ; "
        "adc  %5,%%edx ; "
        : "=A" (product), "=r" (tmp1), "=r" (tmp2)
        : "a" ((u32)delta), "1" ((u32)(delta >> 32)), "2" (tsc_mul_frac) );
#else
    asm (
        "mul %%rdx ; shrd $32,%%rdx,%%rax"
        : "=a" (product) : "0" (delta), "d" ((u64)tsc_mul_frac) );
#endif

    return product;
}

static inline u64 get_pvrdtscp_timestamp(int *discontinuity)
{
	static int firsttime = 1;
	static u64 last_pvrdtscp_timestamp = 0;
	static u32 last_tsc_aux;
	static u64 xen_ns_offset;
	static u32 xen_tsc_to_ns_mul_frac, xen_tsc_to_ns_shift;
	u32 this_tsc_aux;
	u64 timestamp, cur_tsc, cur_ns;

	if (firsttime) {
		cur_tsc = do_rdtscp(&last_tsc_aux);
		get_xen_time_values(&xen_ns_offset, &xen_tsc_to_ns_mul_frac,
					&xen_tsc_to_ns_shift);
		cur_ns = scale_delta(cur_tsc, xen_tsc_to_ns_mul_frac,
					xen_tsc_to_ns_shift);
		timestamp = cur_ns - xen_ns_offset;
		last_pvrdtscp_timestamp = timestamp;
		firsttime = 0;
	}
	cur_tsc = do_rdtscp(&this_tsc_aux);
	*discontinuity = 0;
	while (this_tsc_aux != last_tsc_aux) {
		/* if tsc_aux changed, try again */
		last_tsc_aux = this_tsc_aux;
		get_xen_time_values(&xen_ns_offset, &xen_tsc_to_ns_mul_frac,
					&xen_tsc_to_ns_shift);
		cur_tsc = do_rdtscp(&this_tsc_aux);
		*discontinuity = 1;
	}

	/* compute nsec from TSC and Xen time values */
	cur_ns = scale_delta(cur_tsc, xen_tsc_to_ns_mul_frac,
					xen_tsc_to_ns_shift);
	timestamp = cur_ns - xen_ns_offset;

	/* enforce monotonicity just in case */
	if ((i64)(timestamp - last_pvrdtscp_timestamp) > 0)
		last_pvrdtscp_timestamp = timestamp;
	else {
		/* this should never happen but we'll check it anyway in
		 * case of some strange combination of scaling errors
		 * occurs across a very fast migration */
		printf("Time went backwards by %lluns\n",
		    (unsigned long long)(last_pvrdtscp_timestamp-timestamp));
		timestamp = ++last_pvrdtscp_timestamp;
	}
	return timestamp;
}

#define HVM 1
#define PVM 0

static int running_on_xen(int hvm, u16 *version_major, u16 *version_minor)
{
	u32 eax, ebx, ecx, edx, base;
	union { char csig[16]; u32 u[4]; } sig;

	for (base=0x40000000; base < 0x40010000; base += 0x100) {
		if (hvm==HVM)
			hvm_cpuid(base,0,&eax,&ebx,&ecx,&edx);
		else
			pv_cpuid(base,0,&eax,&ebx,&ecx,&edx);
		sig.u[0] = ebx; sig.u[1] = ecx; sig.u[2] = edx;
		sig.csig[12] = '\0';
		if (!strcmp("XenVMMXenVMM",&sig.csig[0]) && (eax >= (base+2))) {
				if (hvm==HVM)
					hvm_cpuid(base+1,0,&eax,&ebx,&ecx,&edx);
				else
					pv_cpuid(base+1,0,&eax,&ebx,&ecx,&edx);
				*version_major = (eax >> 16) & 0xffff;
				*version_minor = eax & 0xffff;
				return 1;
		}
	}
	return 0;
}

main(int ac, char **av)
{
	u32 dummy;
	u16 version_hi, version_lo;
	u64 ts, last_ts;
	int status, discontinuity = 0;
	pid_t pid;

	if (running_on_xen(HVM,&version_hi,&version_lo)) {
		printf("running on Xen v%d.%d as an HVM domain, "
			"pvrdtsc not supported, exiting\n",
			(int)version_hi, (int)version_lo);
		exit(0);
	}
	pid = fork();
	if (pid == -1) {
		fprintf(stderr,"Huh? Fork failed\n");
		return 0;
	}
	else if (pid == 0) { /* child */
		pv_cpuid(0x40000000,0,&dummy,&dummy,&dummy,&dummy);
		exit(0);
	}
	waitpid(pid,&status,0);
	if (!WIFEXITED(status))
		exit(0);
	if (!running_on_xen(PVM,&version_hi,&version_lo)) {
		printf("not running on Xen, exiting\n");
		exit(0);
	}
	printf("running on Xen v%d.%d as a PV domain\n",
		(int)version_hi, (int)version_lo);
	if ( version_hi <= 3 ) {
		printf("pvrdtscp requires Xen version 4.0 or greater\n");
		/* exit(0); FIXME after xen-unstable is officially v4.0 */
	}
	if ( get_xen_tsc_mode() != 3 )
		printf("tsc_mode not pvrdtscp, set tsc_mode=3, exiting\n");

	/* OK, we are on Xen, now loop forever checking timestamps */
	ts = get_pvrdtscp_timestamp(&discontinuity);
	printf("Starting with ts=%lluns 0x%llx (%llusec)\n",ts,ts,ts/NSEC_PER_SEC);
	printf("incarn=%d: vtsc=%d, vtsc_khz=%lu, phys cpu_khz=%lu\n",
				(unsigned long)get_xen_incarnation(),
				(unsigned long)get_xen_vtsc(),
				(unsigned long)get_xen_vtsc_khz(),
				(unsigned long)get_xen_cpu_khz());
	ts = get_pvrdtscp_timestamp(&discontinuity);
	last_ts = ts;
	while (1) {
		ts = get_pvrdtscp_timestamp(&discontinuity);
		if (discontinuity)
			printf("migrated/restored, incarn=%d: "
                               "vtsc now %d, vtsc_khz=%lu, phys cpu_khz=%lu\n",
				(unsigned long)get_xen_incarnation(),
				(unsigned long)get_xen_vtsc(),
				(unsigned long)get_xen_vtsc_khz(),
				(unsigned long)get_xen_cpu_khz());
		if (ts < last_ts)
			/* this should NEVER happen, especially since there
			 * is a check for it in get_pvrdtscp_timestamp() */
			printf("Time went backwards: %lluns (%llusec)\n",
				last_ts-ts,(last_ts-ts)/NSEC_PER_SEC);
		if (ts > last_ts + 200000000LL)
			/* this is OK, usually about 2sec for save/restore
			 * and a fraction of a second for live migrate */
			printf("Time jumped forward %lluns (%llusec)\n",
				ts-last_ts,(ts-last_ts)/NSEC_PER_SEC);
		last_ts = ts;
	}
}
