/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_GENERIC_IRQ_DT_H__
#define __ASM_GENERIC_IRQ_DT_H__

/*
 * These defines correspond to the Xen internal representation of the
 * IRQ types. We choose to make them the same as the existing device
 * tree definitions for convenience.
 */
#define IRQ_TYPE_NONE           DT_IRQ_TYPE_NONE
#define IRQ_TYPE_EDGE_RISING    DT_IRQ_TYPE_EDGE_RISING
#define IRQ_TYPE_EDGE_FALLING   DT_IRQ_TYPE_EDGE_FALLING
#define IRQ_TYPE_EDGE_BOTH      DT_IRQ_TYPE_EDGE_BOTH
#define IRQ_TYPE_LEVEL_HIGH     DT_IRQ_TYPE_LEVEL_HIGH
#define IRQ_TYPE_LEVEL_LOW      DT_IRQ_TYPE_LEVEL_LOW
#define IRQ_TYPE_LEVEL_MASK     DT_IRQ_TYPE_LEVEL_MASK
#define IRQ_TYPE_SENSE_MASK     DT_IRQ_TYPE_SENSE_MASK
#define IRQ_TYPE_INVALID        DT_IRQ_TYPE_INVALID

#endif /* __ASM_GENERIC_IRQ_DT_H__ */
