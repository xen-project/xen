/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2004 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: physdev.h
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *        Date: Feb 2004
 * 
 * Description: Interface for domains to access physical devices on the PCI bus
 */

#ifndef __HYPERVISOR_IFS_PHYSDEV_H__
#define __HYPERVISOR_IFS_PHYSDEV_H__

/*
 * Commands to HYPERVISOR_physdev_op()
 */
#define PHYSDEVOP_CFGREG_READ   0
#define PHYSDEVOP_CFGREG_WRITE  1
#define PHYSDEVOP_FIND_IRQ      2
#define PHYSDEVOP_REQUEST_IRQ   3
#define PHYSDEVOP_FREE_IRQ      4
#define PHYSDEVOP_ENABLE_IRQ    5
#define PHYSDEVOP_DISABLE_IRQ   6
#define PHYSDEVOP_FINISHED_IRQ  7

/* read pci config */
typedef struct physdevop_cfgreg_read_st
{
    int seg;        /* IN */
    int bus;        /* IN */
    int dev;        /* IN */
    int func;       /* IN */
    int reg;        /* IN  */
    int len;        /* IN  */
    u32 value;      /* OUT */
} physdevop_cfgreg_read_t;

/* write pci config */
typedef struct physdevop_cfgred_write_st
{
    int seg;        /* IN */
    int bus;        /* IN */
    int dev;        /* IN */
    int func;       /* IN */
    int reg;        /* IN */
    int len;        /* IN */
    u32 value;      /* IN */
} physdevop_cfgreg_write_t;

/* get the real IRQ for a device */
typedef struct physdevop_find_irq_st
{
    int seg;      /* IN */
    int bus;      /* IN */
    int dev;      /* IN */
    int func;     /* IN */
    u32 irq;      /* OUT */
} physdevop_find_irq_t;

/* request physical IRQ to be routed to guest */
typedef struct physdevop_request_irq_st
{
    u32 irq;      /* IN */
} physdevop_request_irq_t;

/* stop routing physical interrupts to guest */
typedef struct physdevop_free_irq_st
{
    u32 irq;      /* IN */
} physdevop_free_irq_t;

/* enable IRQ for the caller  */
typedef struct physdevop_enable_irq_st
{
    u32 irq;      /* IN */
} physdevop_enable_irq_t;

/* disable interrupts */
typedef struct physdevop_disable_irq_st
{
    u32 irq;      /* IN */
} physdevop_disable_irq_t;

typedef struct physdevop_finished_irq_st
{
    u32 irq;      /* IN */
} physdevop_finished_irq_t;


typedef struct _physdev_op_st 
{
    unsigned long cmd;

    /* command parameters */
    union
    {
        physdevop_cfgreg_read_t  cfg_read;
        physdevop_cfgreg_write_t cfg_write;
        physdevop_find_irq_t     find_irq;
        physdevop_request_irq_t  request_irq;
        physdevop_free_irq_t     free_irq;
        physdevop_enable_irq_t   enable_irq;
        physdevop_disable_irq_t  disable_irq;
        physdevop_finished_irq_t finished_irq;
    } u;
} physdev_op_t;

#endif /* __HYPERVISOR_IFS_PHYSDEV_H__ */
