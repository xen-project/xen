/******************************************************************************
 * devinit.c
 * 
 * This is the watchdog timer routines, ripped from sch_generic.c
 * Original copyright notice appears below.
 * 
 */

/*
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *              Jamal Hadi Salim, <hadi@nortelnetworks.com> 990601
 *              - Ingress support
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/bitops.h>
#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/socket.h>
#include <xen/sockios.h>
#include <xen/errno.h>
#include <xen/interrupt.h>
#include <xen/netdevice.h>
#include <xen/skbuff.h>
#include <xen/init.h>

static void dev_watchdog(unsigned long arg)
{
    struct net_device *dev = (struct net_device *)arg;

    spin_lock(&dev->xmit_lock);
    if (netif_device_present(dev) &&
        netif_running(dev) &&
        netif_carrier_ok(dev)) {
        if (netif_queue_stopped(dev) &&
            (jiffies - dev->trans_start) > dev->watchdog_timeo) {
            printk(KERN_INFO "NETDEV WATCHDOG: %s: transmit timed out\n", dev->name);
            dev->tx_timeout(dev);
        }
        if (!mod_timer(&dev->watchdog_timer, jiffies + dev->watchdog_timeo))
            dev_hold(dev);
    }
    spin_unlock(&dev->xmit_lock);

    dev_put(dev);
}

static void dev_watchdog_init(struct net_device *dev)
{
    init_timer(&dev->watchdog_timer);
    dev->watchdog_timer.data = (unsigned long)dev;
    dev->watchdog_timer.function = dev_watchdog;
}

void __netdev_watchdog_up(struct net_device *dev)
{
    if (dev->tx_timeout) {
        if (dev->watchdog_timeo <= 0)
            dev->watchdog_timeo = 5*HZ;
        if (!mod_timer(&dev->watchdog_timer, jiffies + dev->watchdog_timeo))
            dev_hold(dev);
    }
}

static void dev_watchdog_up(struct net_device *dev)
{
    spin_lock_bh(&dev->xmit_lock);
    __netdev_watchdog_up(dev);
    spin_unlock_bh(&dev->xmit_lock);
}

static void dev_watchdog_down(struct net_device *dev)
{
    spin_lock_bh(&dev->xmit_lock);
    if (del_timer(&dev->watchdog_timer))
        __dev_put(dev);
    spin_unlock_bh(&dev->xmit_lock);
}

void dev_activate(struct net_device *dev)
{
    spin_lock_bh(&dev->queue_lock);
    dev->trans_start = jiffies;
    dev_watchdog_up(dev);
    spin_unlock_bh(&dev->queue_lock);
}

void dev_deactivate(struct net_device *dev)
{
    dev_watchdog_down(dev);
}

void dev_init_scheduler(struct net_device *dev)
{
    dev_watchdog_init(dev);
}

void dev_shutdown(struct net_device *dev)
{
}
