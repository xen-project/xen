/*
 * Copyright (c) 2006 Cisco Systems.  All rights reserved.
 *
 * This file is released under the GPLv2.
 */

/* mutex compatibility for pre-2.6.16 kernels */

#ifndef __LINUX_MUTEX_H
#define __LINUX_MUTEX_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#error "This version of Linux should not need compat mutex.h"
#endif

#include <linux/version.h>
#include <asm/semaphore.h>

#define mutex semaphore
#define DEFINE_MUTEX(foo) DECLARE_MUTEX(foo)
#define mutex_init(foo) init_MUTEX(foo)
#define mutex_lock(foo) down(foo)
#define mutex_lock_interruptible(foo) down_interruptible(foo)
/* this function follows the spin_trylock() convention, so        *
 * it is negated to the down_trylock() return values! Be careful  */
#define mutex_trylock(foo) !down_trylock(foo)
#define mutex_unlock(foo) up(foo)

#endif /* __LINUX_MUTEX_H */
