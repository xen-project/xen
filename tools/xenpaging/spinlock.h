/******************************************************************************
 * tools/xenpaging/spinlock.h
 *
 * Spinlock implementation.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__


#include "bitops.h"


#define SPIN_LOCK_UNLOCKED 0


typedef int spinlock_t;


static inline void spin_lock(spinlock_t *lock)
{
    while ( test_and_set_bit(1, lock) );
}

static inline void spin_lock_init(spinlock_t *lock)
{
    *lock = SPIN_LOCK_UNLOCKED;
}

static inline void spin_unlock(spinlock_t *lock)
{
    *lock = SPIN_LOCK_UNLOCKED;
}

static inline int spin_trylock(spinlock_t *lock)
{
    return !test_and_set_bit(1, lock);
}


#endif // __SPINLOCK_H__


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
