/******************************************************************************
 * Arch-specific physdev.c
 *
 * Copyright (c) 2012, Citrix Systems
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <asm/hypercall.h>


int do_physdev_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    printk("%s %d cmd=%d: not implemented yet\n", __func__, __LINE__, cmd);
    return -ENOSYS;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
