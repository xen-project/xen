/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef __XEN_PUBLIC_ARCH_PPC_64_H__
#define __XEN_PUBLIC_ARCH_PPC_64_H__

#define __DEFINE_XEN_GUEST_HANDLE(name, type) \
    typedef struct { \
        int __pad[(sizeof (long long) - sizeof (void *)) / sizeof (int)]; \
        type *p; \
    } __attribute__((__aligned__(8))) __guest_handle_ ## name

#define DEFINE_XEN_GUEST_HANDLE(name) __DEFINE_XEN_GUEST_HANDLE(name, name)
#define XEN_GUEST_HANDLE(name)        __guest_handle_ ## name
#define set_xen_guest_handle(hnd, val) \
    do { \
        if (sizeof ((hnd).__pad)) \
            (hnd).__pad[0] = 0; \
        (hnd).p = val; \
    } while (0)

#ifdef __XEN_TOOLS__
#define get_xen_guest_handle(val, hnd)  do { val = (hnd).p; } while (0)
#endif

#ifndef __ASSEMBLY__
/* Guest handles for primitive C types. */
__DEFINE_XEN_GUEST_HANDLE(uchar, unsigned char);
__DEFINE_XEN_GUEST_HANDLE(uint,  unsigned int);
__DEFINE_XEN_GUEST_HANDLE(ulong, unsigned long);
DEFINE_XEN_GUEST_HANDLE(char);
DEFINE_XEN_GUEST_HANDLE(int);
DEFINE_XEN_GUEST_HANDLE(long);
DEFINE_XEN_GUEST_HANDLE(void);

typedef unsigned long long xen_pfn_t;
DEFINE_XEN_GUEST_HANDLE(xen_pfn_t);
#endif

/*
 * Pointers and other address fields inside interface structures are padded to
 * 64 bits. This means that field alignments aren't different between 32- and
 * 64-bit architectures. 
 */
/* NB. Multi-level macro ensures __LINE__ is expanded before concatenation. */
#define __MEMORY_PADDING(_X)
#define _MEMORY_PADDING(_X)  __MEMORY_PADDING(_X)
#define MEMORY_PADDING       _MEMORY_PADDING(__LINE__)

/* And the trap vector is... */
#define TRAP_INSTR "li 0,-1; sc" /* XXX just "sc"? */

#ifndef __ASSEMBLY__

typedef uint64_t xen_ulong_t;

/* User-accessible registers: need to be saved/restored for every nested Xen
 * invocation. */
struct cpu_user_regs
{
    uint64_t gprs[32];
    uint64_t lr;
    uint64_t ctr;
    uint64_t srr0;
    uint64_t srr1;
    uint64_t pc;
    uint64_t msr;
    uint64_t fpscr;
    uint64_t xer;
    uint64_t hid4;
    uint32_t cr;
    uint32_t entry_vector;
};
typedef struct cpu_user_regs cpu_user_regs_t;

typedef uint64_t tsc_timestamp_t; /* RDTSC timestamp */ /* XXX timebase */

/* ONLY used to communicate with dom0! See also struct exec_domain. */
struct vcpu_guest_context {
    cpu_user_regs_t user_regs;         /* User-level CPU registers     */
    uint64_t sdr1;                     /* Pagetable base               */
    /* XXX etc */
};
typedef struct vcpu_guest_context vcpu_guest_context_t;
DEFINE_XEN_GUEST_HANDLE(vcpu_guest_context_t);

struct arch_shared_info {
    uint64_t pad[32];
};

struct arch_vcpu_info {
};

/* Support for multi-processor guests. */
#define MAX_VIRT_CPUS 32
#endif

#endif
