/******************************************************************************
 * arch/xen/drivers/vnetif/backend/main.c
 * 
 * Back-end of the driver for virtual block devices. This portion of the
 * driver exports a 'unified' block-device interface that can be accessed
 * by any operating system that implements a compatible front end. A 
 * reference front-end implementation can be found in:
 *  arch/xen/drivers/vnetif/frontend
 * 
 * Copyright (c) 2004, K A Fraser
 */

#include <linux/config.h>
#include <linux/module.h>

static int __init init_module(void)
{
    return 0;
}

static void cleanup_module(void)
{
}

module_init(init_module);
module_exit(cleanup_module);
