/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#ifndef __XEN_ARM_LIVEPATCH_H__
#define __XEN_ARM_LIVEPATCH_H__

#include <xen/sizes.h> /* For SZ_* macros. */
#include <asm/insn.h>

/*
 * The va of the hypervisor .text region. We need this as the
 * normal va are write protected.
 */
extern void *vmap_of_xen_text;

/* These ranges are only for unconditional branches. */
#ifdef CONFIG_ARM_32
/* ARM32: A4.3 IN ARM DDI 0406C.c -  we are using only ARM instructions in Xen.*/
#define ARCH_LIVEPATCH_RANGE SZ_32M
#else
/* ARM64: C1.3.2 in ARM DDI 0487A.j */
#define ARCH_LIVEPATCH_RANGE SZ_128M
#endif

#endif /* __XEN_ARM_LIVEPATCH_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
