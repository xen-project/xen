/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#ifndef __XEN_X86_LIVEPATCH_H__
#define __XEN_X86_LIVEPATCH_H__

#include <xen/sizes.h> /* For SZ_* macros. */

#define ARCH_PATCH_INSN_SIZE 5
#define ARCH_LIVEPATCH_RANGE SZ_2G
#define LIVEPATCH_FEATURE    X86_FEATURE_ALWAYS

#endif /* __XEN_X86_LIVEPATCH_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
