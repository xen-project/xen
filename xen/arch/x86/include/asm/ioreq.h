/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ioreq.h: Hardware virtual machine assist interface definitions.
 *
 * This is a wrapper which purpose is to not include arch HVM specific header
 * from the common code.
 *
 * Copyright (c) 2016 Citrix Systems Inc.
 */

#ifndef __ASM_X86_IOREQ_H__
#define __ASM_X86_IOREQ_H__

#ifdef CONFIG_HVM
#include <asm/hvm/ioreq.h>
#endif

#endif /* __ASM_X86_IOREQ_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
