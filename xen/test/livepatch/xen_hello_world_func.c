/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include <xen/types.h>

#include <asm/alternative.h>
#include <asm/livepatch.h>
#ifdef CONFIG_X86
#include <asm/nops.h>
#include <asm/uaccess.h>

static unsigned long *non_canonical_addr = (unsigned long *)0xdead000000000000ULL;
#endif

/* Our replacement function for xen_extra_version. */
const char *xen_hello_world(void)
{
#ifdef CONFIG_X86
    unsigned long tmp;
    int rc;

    alternative(ASM_NOP8, ASM_NOP1, LIVEPATCH_FEATURE);
    /*
     * Any BUG, or WARN_ON will contain symbol and payload name. Furthermore
     * exceptions will be caught and processed properly.
     */
    rc = __get_user(tmp, non_canonical_addr);
    BUG_ON(rc != -EFAULT);
#endif
#if defined(CONFIG_ARM)
    asm(ALTERNATIVE("nop", "nop", LIVEPATCH_FEATURE));
#endif

    return "Hello World";
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
