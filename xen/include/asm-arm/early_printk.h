/*
 * printk() for use before the final page tables are setup.
 *
 * Copyright (C) 2012 Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __ARM_EARLY_PRINTK_H__
#define __ARM_EARLY_PRINTK_H__


#ifdef CONFIG_EARLY_PRINTK

/* need to add the uart address offset in page to the fixmap address */
#define EARLY_UART_VIRTUAL_ADDRESS \
    (FIXMAP_ADDR(FIXMAP_CONSOLE) + (CONFIG_EARLY_UART_BASE_ADDRESS & ~PAGE_MASK))

#endif /* !CONFIG_EARLY_PRINTK */

#endif
