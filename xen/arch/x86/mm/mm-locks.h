/******************************************************************************
 * arch/x86/mm/mm-locks.h
 *
 * Spinlocks used by the code in arch/x86/mm.
 *
 * Copyright (c) 2011 Citrix Systems, inc. 
 * Copyright (c) 2007 Advanced Micro Devices (Wei Huang)
 * Copyright (c) 2006-2007 XenSource Inc.
 * Copyright (c) 2006 Michael A Fetterman
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

#ifndef _MM_LOCKS_H
#define _MM_LOCKS_H

#include <asm/mem_sharing.h>

/* Per-CPU variable for enforcing the lock ordering */
DECLARE_PER_CPU(int, mm_lock_level);
#define __get_lock_level()  (this_cpu(mm_lock_level))

static inline void mm_lock_init(mm_lock_t *l)
{
    spin_lock_init(&l->lock);
    l->locker = -1;
    l->locker_function = "nobody";
    l->unlock_level = 0;
}

static inline int mm_locked_by_me(mm_lock_t *l) 
{
    return (l->lock.recurse_cpu == current->processor);
}

/* If you see this crash, the numbers printed are lines in this file 
 * where the offending locks are declared. */
#define __check_lock_level(l)                           \
do {                                                    \
    if ( unlikely(__get_lock_level()) > (l) )           \
        panic("mm locking order violation: %i > %i\n",  \
              __get_lock_level(), (l));                 \
} while(0)

#define __set_lock_level(l)         \
do {                                \
    __get_lock_level() = (l);       \
} while(0)

static inline void _mm_lock(mm_lock_t *l, const char *func, int level, int rec)
{
    if ( !((mm_locked_by_me(l)) && rec) ) 
        __check_lock_level(level);
    spin_lock_recursive(&l->lock);
    if ( l->lock.recurse_cnt == 1 )
    {
        l->locker_function = func;
        l->unlock_level = __get_lock_level();
    }
    else if ( (unlikely(!rec)) )
        panic("mm lock already held by %s\n", l->locker_function);
    __set_lock_level(level);
}

static inline void _mm_enforce_order_lock_pre(int level)
{
    __check_lock_level(level);
}

static inline void _mm_enforce_order_lock_post(int level, int *unlock_level,
                                                unsigned short *recurse_count)
{
    if ( recurse_count )
    {
        if ( (*recurse_count)++ == 0 )
        {
            *unlock_level = __get_lock_level();
        }
    } else {
        *unlock_level = __get_lock_level();
    }
    __set_lock_level(level);
}

/* This wrapper uses the line number to express the locking order below */
#define declare_mm_lock(name)                                                 \
    static inline void mm_lock_##name(mm_lock_t *l, const char *func, int rec)\
    { _mm_lock(l, func, __LINE__, rec); }
/* These capture the name of the calling function */
#define mm_lock(name, l) mm_lock_##name(l, __func__, 0)
#define mm_lock_recursive(name, l) mm_lock_##name(l, __func__, 1)

/* This wrapper is intended for "external" locks which do not use
 * the mm_lock_t types. Such locks inside the mm code are also subject
 * to ordering constraints. */
#define declare_mm_order_constraint(name)                                   \
    static inline void mm_enforce_order_lock_pre_##name(void)               \
    { _mm_enforce_order_lock_pre(__LINE__); }                               \
    static inline void mm_enforce_order_lock_post_##name(                   \
                        int *unlock_level, unsigned short *recurse_count)   \
    { _mm_enforce_order_lock_post(__LINE__, unlock_level, recurse_count); } \

static inline void mm_unlock(mm_lock_t *l)
{
    if ( l->lock.recurse_cnt == 1 )
    {
        l->locker_function = "nobody";
        __set_lock_level(l->unlock_level);
    }
    spin_unlock_recursive(&l->lock);
}

static inline void mm_enforce_order_unlock(int unlock_level, 
                                            unsigned short *recurse_count)
{
    if ( recurse_count )
    {
        BUG_ON(*recurse_count == 0);
        if ( (*recurse_count)-- == 1 )
        {
            __set_lock_level(unlock_level);
        }
    } else {
        __set_lock_level(unlock_level);
    }
}

/************************************************************************
 *                                                                      *
 * To avoid deadlocks, these locks _MUST_ be taken in the order they're *
 * declared in this file.  The locking functions will enforce this.     *
 *                                                                      *
 ************************************************************************/

/* Sharing per page lock
 *
 * This is an external lock, not represented by an mm_lock_t. The memory
 * sharing lock uses it to protect addition and removal of (gfn,domain)
 * tuples to a shared page. We enforce order here against the p2m lock,
 * which is taken after the page_lock to change the gfn's p2m entry.
 *
 * The lock is recursive because during share we lock two pages. */

declare_mm_order_constraint(per_page_sharing)
#define page_sharing_mm_pre_lock()   mm_enforce_order_lock_pre_per_page_sharing()
#define page_sharing_mm_post_lock(l, r) \
        mm_enforce_order_lock_post_per_page_sharing((l), (r))
#define page_sharing_mm_unlock(l, r) mm_enforce_order_unlock((l), (r))

/* Nested P2M lock (per-domain)
 *
 * A per-domain lock that protects the mapping from nested-CR3 to 
 * nested-p2m.  In particular it covers:
 * - the array of nested-p2m tables, and all LRU activity therein; and
 * - setting the "cr3" field of any p2m table to a non-CR3_EADDR value. 
 *   (i.e. assigning a p2m table to be the shadow of that cr3 */

declare_mm_lock(nestedp2m)
#define nestedp2m_lock(d)   mm_lock(nestedp2m, &(d)->arch.nested_p2m_lock)
#define nestedp2m_unlock(d) mm_unlock(&(d)->arch.nested_p2m_lock)

/* P2M lock (per-p2m-table)
 * 
 * This protects all updates to the p2m table.  Updates are expected to
 * be safe against concurrent reads, which do *not* require the lock. */

declare_mm_lock(p2m)
#define p2m_lock(p)           mm_lock(p2m, &(p)->lock)
#define p2m_lock_recursive(p) mm_lock_recursive(p2m, &(p)->lock)
#define p2m_unlock(p)         mm_unlock(&(p)->lock)
#define p2m_locked_by_me(p)   mm_locked_by_me(&(p)->lock)

/* Page alloc lock (per-domain)
 *
 * This is an external lock, not represented by an mm_lock_t. However, 
 * pod code uses it in conjunction with the p2m lock, and expecting
 * the ordering which we enforce here.
 * The lock is not recursive. */

declare_mm_order_constraint(page_alloc)
#define page_alloc_mm_pre_lock()   mm_enforce_order_lock_pre_page_alloc()
#define page_alloc_mm_post_lock(l) mm_enforce_order_lock_post_page_alloc(&(l), NULL)
#define page_alloc_mm_unlock(l)    mm_enforce_order_unlock((l), NULL)

/* Paging lock (per-domain)
 *
 * For shadow pagetables, this lock protects
 *   - all changes to shadow page table pages
 *   - the shadow hash table
 *   - the shadow page allocator 
 *   - all changes to guest page table pages
 *   - all changes to the page_info->tlbflush_timestamp
 *   - the page_info->count fields on shadow pages 
 * 
 * For HAP, it protects the NPT/EPT tables and mode changes. 
 * 
 * It also protects the log-dirty bitmap from concurrent accesses (and
 * teardowns, etc). */

declare_mm_lock(paging)
#define paging_lock(d)         mm_lock(paging, &(d)->arch.paging.lock)
#define paging_lock_recursive(d) \
                    mm_lock_recursive(paging, &(d)->arch.paging.lock)
#define paging_unlock(d)       mm_unlock(&(d)->arch.paging.lock)
#define paging_locked_by_me(d) mm_locked_by_me(&(d)->arch.paging.lock)

#endif /* _MM_LOCKS_H */
