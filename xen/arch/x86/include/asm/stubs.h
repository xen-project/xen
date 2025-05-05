/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef X86_ASM_STUBS_H
#define X86_ASM_STUBS_H

/*
 * Xen has several per-cpu executable stubs which are written dynamically.
 * These are:
 *
 * - The SYSCALL entry stubs, LSTAR and CSTAR.  These are written on boot, and
 *   are responsible for moving back onto Xen's stack.
 *
 * - The emulation stub.  This is used to replay an instruction or sequence
 *   which trapped for emulation.
 *
 * The stubs have an executable alias in l2_xenmap[] (i.e. within 1G of the
 * rest of .text), and are written via map_domain_page().
 */

#include <xen/percpu.h>

/* Total size of syscall and emulation stubs. */
#define STUB_BUF_SHIFT (L1_CACHE_SHIFT > 7 ? L1_CACHE_SHIFT : 7)
#define STUB_BUF_SIZE  (1 << STUB_BUF_SHIFT)
#define STUBS_PER_PAGE (PAGE_SIZE / STUB_BUF_SIZE)

struct stubs {
    union {
        void (*func)(void);
        unsigned long addr;
    };
    unsigned long mfn;
};

DECLARE_PER_CPU(struct stubs, stubs);
unsigned long alloc_stub_page(unsigned int cpu, unsigned long *mfn);

#endif /* X86_ASM_STUBS_H */
