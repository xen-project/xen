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

#include <xen/page-size.h>
#include <asm/arm64/mpu.h>
#include <asm/fixmap.h>

#ifdef CONFIG_EARLY_PRINTK

#if defined(CONFIG_MPU)

/*
 * For MPU systems, there is no VMSA support in EL2, so we use VA == PA
 * for EARLY_UART_VIRTUAL_ADDRESS.
 */
#define EARLY_UART_VIRTUAL_ADDRESS CONFIG_EARLY_UART_BASE_ADDRESS

/*
 * User-defined EARLY_UART_BASE_ADDRESS and EARLY_UART_SIZE must be aligned to
 * minimum size of MPU region.
 */
#if (CONFIG_EARLY_UART_BASE_ADDRESS % MPU_REGION_ALIGN) != 0
#error "EARLY_UART_BASE_ADDRESS must be aligned to minimum MPU region size"
#endif

#if (CONFIG_EARLY_UART_SIZE % MPU_REGION_ALIGN) != 0
#error "EARLY_UART_SIZE must be aligned to minimum MPU region size"
#endif

#elif defined(CONFIG_MMU)

/* need to add the uart address offset in page to the fixmap address */
#define EARLY_UART_VIRTUAL_ADDRESS \
    (FIXMAP_ADDR(FIX_CONSOLE) + (CONFIG_EARLY_UART_BASE_ADDRESS & ~PAGE_MASK))

#define TEMPORARY_EARLY_UART_VIRTUAL_ADDRESS \
    (TEMPORARY_FIXMAP_ADDR(FIX_CONSOLE) + (CONFIG_EARLY_UART_BASE_ADDRESS & ~PAGE_MASK))

#else
#error "Unknown Memory management system"
#endif

#endif /* !CONFIG_EARLY_PRINTK */
#endif
