/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * hvm.h: Hardware virtual machine assist interface definitions.
 *
 * Copyright (c) 2016 Citrix Systems Inc.
 */

#ifndef __ASM_X86_HVM_IOREQ_H__
#define __ASM_X86_HVM_IOREQ_H__

/* This correlation must not be altered */
#define IOREQ_STATUS_HANDLED     X86EMUL_OKAY
#define IOREQ_STATUS_UNHANDLED   X86EMUL_UNHANDLEABLE
#define IOREQ_STATUS_RETRY       X86EMUL_RETRY

#endif /* __ASM_X86_HVM_IOREQ_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
