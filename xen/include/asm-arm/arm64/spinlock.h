/*
 * Derived from Linux arch64 spinlock.h which is:
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_ARM64_SPINLOCK_H
#define __ASM_ARM64_SPINLOCK_H

typedef struct {
    volatile unsigned int lock;
} raw_spinlock_t;

#define _RAW_SPIN_LOCK_UNLOCKED { 0 }

#define _raw_spin_is_locked(x)          ((x)->lock != 0)

static always_inline void _raw_spin_unlock(raw_spinlock_t *lock)
{
    ASSERT(_raw_spin_is_locked(lock));

    asm volatile(
        "       stlr    %w1, [%0]\n"
        : : "r" (&lock->lock), "r" (0) : "memory");
}

static always_inline int _raw_spin_trylock(raw_spinlock_t *lock)
{
    unsigned int tmp;

    asm volatile(
        "       ldaxr   %w0, [%1]\n"
        "       cbnz    %w0, 1f\n"
        "       stxr    %w0, %w2, [%1]\n"
        "1:\n"
        : "=&r" (tmp)
        : "r" (&lock->lock), "r" (1)
        : "memory");

    return !tmp;
}

typedef struct {
    volatile unsigned int lock;
} raw_rwlock_t;

#define _RAW_RW_LOCK_UNLOCKED { 0 }

static always_inline int _raw_read_trylock(raw_rwlock_t *rw)
{
    unsigned int tmp, tmp2 = 1;

    asm volatile(
        "       ldaxr   %w0, [%2]\n"
        "       add     %w0, %w0, #1\n"
        "       tbnz    %w0, #31, 1f\n"
        "       stxr    %w1, %w0, [%2]\n"
        "1:\n"
        : "=&r" (tmp), "+r" (tmp2)
        : "r" (&rw->lock)
        : "memory");

    return !tmp2;
}

static always_inline int _raw_write_trylock(raw_rwlock_t *rw)
{
    unsigned int tmp;

    asm volatile(
        "       ldaxr   %w0, [%1]\n"
        "       cbnz    %w0, 1f\n"
        "       stxr    %w0, %w2, [%1]\n"
        "1:\n"
        : "=&r" (tmp)
        : "r" (&rw->lock), "r" (0x80000000)
        : "memory");

    return !tmp;
}

static inline void _raw_read_unlock(raw_rwlock_t *rw)
{
    unsigned int tmp, tmp2;

    asm volatile(
        "1:     ldxr    %w0, [%2]\n"
        "       sub     %w0, %w0, #1\n"
        "       stlxr   %w1, %w0, [%2]\n"
        "       cbnz    %w1, 1b\n"
        : "=&r" (tmp), "=&r" (tmp2)
        : "r" (&rw->lock)
        : "memory");
}

static inline void _raw_write_unlock(raw_rwlock_t *rw)
{
    asm volatile(
        "       stlr    %w1, [%0]\n"
        : : "r" (&rw->lock), "r" (0) : "memory");
}

#define _raw_rw_is_locked(x) ((x)->lock != 0)
#define _raw_rw_is_write_locked(x) ((x)->lock == 0x80000000)

#endif /* __ASM_SPINLOCK_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
