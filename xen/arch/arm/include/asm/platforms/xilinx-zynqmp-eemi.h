/*
 * Copyright (c) 2018 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __ASM_ARM_PLATFORMS_ZYNQMP_H
#define __ASM_ARM_PLATFORMS_ZYNQMP_H

#include <asm/processor.h>
#include <asm/smccc.h>

#define EEMI_FID(fid) ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, \
                                         ARM_SMCCC_CONV_64,   \
                                         ARM_SMCCC_OWNER_SIP, \
                                         fid)

enum pm_api_id {
    /* Miscellaneous API functions: */
    PM_GET_API_VERSION = 1, /* Do not change or move */
    PM_SET_CONFIGURATION,
    PM_GET_NODE_STATUS,
    PM_GET_OP_CHARACTERISTIC,
    PM_REGISTER_NOTIFIER,
    /* API for suspending of PUs: */
    PM_REQ_SUSPEND,
    PM_SELF_SUSPEND,
    PM_FORCE_POWERDOWN,
    PM_ABORT_SUSPEND,
    PM_REQ_WAKEUP,
    PM_SET_WAKEUP_SOURCE,
    PM_SYSTEM_SHUTDOWN,
    /* API for managing PM slaves: */
    PM_REQ_NODE,
    PM_RELEASE_NODE,
    PM_SET_REQUIREMENT,
    PM_SET_MAX_LATENCY,
    /* Direct control API functions: */
    PM_RESET_ASSERT,
    PM_RESET_GET_STATUS,
    PM_MMIO_WRITE,
    PM_MMIO_READ,
    PM_INIT,
    PM_FPGA_LOAD,
    PM_FPGA_GET_STATUS,
    PM_GET_CHIPID,
    /* ID 25 is been used by U-boot to process secure boot images */
    /* Secure library generic API functions */
    PM_SECURE_SHA = 26,
    PM_SECURE_RSA,
    /* Pin control API functions */
    PM_PINCTRL_REQUEST,
    PM_PINCTRL_RELEASE,
    PM_PINCTRL_GET_FUNCTION,
    PM_PINCTRL_SET_FUNCTION,
    PM_PINCTRL_CONFIG_PARAM_GET,
    PM_PINCTRL_CONFIG_PARAM_SET,
    /* PM IOCTL API */
    PM_IOCTL,
    /* API to query information from firmware */
    PM_QUERY_DATA,
    /* Clock control API functions */
    PM_CLOCK_ENABLE,
    PM_CLOCK_DISABLE,
    PM_CLOCK_GETSTATE,
    PM_CLOCK_SETDIVIDER,
    PM_CLOCK_GETDIVIDER,
    PM_CLOCK_SETRATE,
    PM_CLOCK_GETRATE,
    PM_CLOCK_SETPARENT,
    PM_CLOCK_GETPARENT,
    PM_GET_TRUSTZONE_VERSION = 2563,
    PM_API_MAX
};

/**
 * @XST_PM_SUCCESS:		Success
 * @XST_PM_INTERNAL:	Unexpected error
 * @XST_PM_CONFLICT:	Conflicting requirements
 * @XST_PM_NO_ACCESS:	Access rights violation
 * @XST_PM_INVALID_NODE:	Does not apply to node passed as argument
 * @XST_PM_DOUBLE_REQ:	Duplicate request
 * @XST_PM_ABORT_SUSPEND:	Target has aborted suspend
 */
enum pm_ret_status {
    XST_PM_SUCCESS = 0,
    XST_PM_INTERNAL = 2000,
    XST_PM_CONFLICT,
    XST_PM_NO_ACCESS,
    XST_PM_INVALID_NODE,
    XST_PM_DOUBLE_REQ,
    XST_PM_ABORT_SUSPEND,
};

/* IPI SMC function numbers enum definition and fids */
#define IPI_MAILBOX_FID(fid) ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, \
                                                ARM_SMCCC_CONV_32,   \
                                                ARM_SMCCC_OWNER_SIP, \
                                                fid)
enum ipi_api_id {
    IPI_MAILBOX_OPEN = 0x1000,
    IPI_MAILBOX_RELEASE,
    IPI_MAILBOX_STATUS_ENQUIRY,
    IPI_MAILBOX_NOTIFY,
    IPI_MAILBOX_ACK,
    IPI_MAILBOX_ENABLE_IRQ,
    IPI_MAILBOX_DISABLE_IRQ,
};

extern bool zynqmp_eemi(struct cpu_user_regs *regs);

#endif /* __ASM_ARM_PLATFORMS_ZYNQMP_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
