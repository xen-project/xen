/* SPDX-License-Identifier: GPL-2.0-only */
/******************************************************************************
 * Arch-specific physdev.c
 *
 * Copyright (c) 2012, Citrix Systems
 */

#include <xen/types.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/hypercall.h>


int do_arm_physdev_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
#ifdef CONFIG_HAS_PCI
    return pci_physdev_op(cmd, arg);
#else
    gdprintk(XENLOG_DEBUG, "PHYSDEVOP cmd=%d: not implemented\n", cmd);
    return -ENOSYS;
#endif
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
