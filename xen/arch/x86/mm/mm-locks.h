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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
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
    if ( unlikely(__get_lock_level() > (l)) )           \
    {                                                   \
        printk("mm locking order violation: %i > %i\n", \
               __get_lock_level(), (l));                \
        BUG();                                          \
    }                                                   \
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
        panic("mm lock already held by %s", l->locker_function);
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


static inline void mm_rwlock_init(mm_rwlock_t *l)
{
    rwlock_init(&l->lock);
    l->locker = -1;
    l->locker_function = "nobody";
    l->unlock_level = 0;
}

static inline int mm_write_locked_by_me(mm_rwlock_t *l)
{
    return (l->locker == get_processor_id());
}

static inline void _mm_write_lock(mm_rwlock_t *l, const char *func, int level)
{
    if ( !mm_write_locked_by_me(l) )
    {
        __check_lock_level(level);
        write_lock(&l->lock);
        l->locker = get_processor_id();
        l->locker_function = func;
        l->unlock_level = __get_lock_level();
        __set_lock_level(level);
    }
    l->recurse_count++;
}

static inline void mm_write_unlock(mm_rwlock_t *l)
{
    if ( --(l->recurse_count) != 0 )
        return;
    l->locker = -1;
    l->locker_function = "nobody";
    __set_lock_level(l->unlock_level);
    write_unlock(&l->lock);
}

static inline void _mm_read_lock(mm_rwlock_t *l, int level)
{
    __check_lock_level(level);
    read_lock(&l->lock);
    /* There's nowhere to store the per-CPU unlock level so we can't
     * set the lock level. */
}

static inline void mm_read_unlock(mm_rwlock_t *l)
{
    read_unlock(&l->lock);
}

/* This wrapper uses the line number to express the locking order below */
#define declare_mm_lock(name)                                                 \
    static inline void mm_lock_##name(mm_lock_t *l, const char *func, int rec)\
    { _mm_lock(l, func, __LINE__, rec); }
#define declare_mm_rwlock(name)                                               \
    static inline void mm_write_lock_##name(mm_rwlock_t *l, const char *func) \
    { _mm_write_lock(l, func, __LINE__); }                                    \
    static inline void mm_read_lock_##name(mm_rwlock_t *l)                    \
    { _mm_read_lock(l, __LINE__); }
/* These capture the name of the calling function */
#define mm_lock(name, l) mm_lock_##name(l, __func__, 0)
#define mm_lock_recursive(name, l) mm_lock_##name(l, __func__, 1)
#define mm_write_lock(name, l) mm_write_lock_##name(l, __func__)
#define mm_read_lock(name, l) mm_read_lock_##name(l)

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

/* Nested P2M lock (per-domain)
 *
 * A per-domain lock that protects the mapping from nested-CR3 to
 * nested-p2m.  In particular it covers:
 * - the array of nested-p2m tables, and all LRU activity therein; and
 * - setting the "cr3" field of any p2m table to a non-P2M_BASE_EAADR value.
 *   (i.e. assigning a p2m table to be the shadow of that cr3 */

declare_mm_lock(nestedp2m)
#define nestedp2m_lock(d)   mm_lock(nestedp2m, &(d)->arch.nested_p2m_lock)
#define nestedp2m_unlock(d) mm_unlock(&(d)->arch.nested_p2m_lock)

/* P2M lock (per-non-alt-p2m-table)
 *
 * This protects all queries and updates to the p2m table.
 * Queries may be made under the read lock but all modifications
 * need the main (write) lock.
 *
 * The write lock is recursive as it is common for a code path to look
 * up a gfn and later mutate it.
 *
 * Note that this lock shares its implementation with the altp2m
 * lock (not the altp2m list lock), so the implementation
 * is found there.
 *
 * Changes made to the host p2m when in altp2m mode are propagated to the
 * altp2ms synchronously in ept_set_entry().  At that point, we will hold
 * the host p2m lock; propagating this change involves grabbing the
 * altp2m_list lock, and the locks of the individual alternate p2ms.  In
 * order to allow us to maintain locking order discipline, we split the p2m
 * lock into p2m (for host p2ms) and altp2m (for alternate p2ms), putting
 * the altp2mlist lock in the middle.
 */

declare_mm_rwlock(p2m);

/* Alternate P2M list lock (per-domain)
 *
 * A per-domain lock that protects the list of alternate p2m's.
 * Any operation that walks the list needs to acquire this lock.
 * Additionally, before destroying an alternate p2m all VCPU's
 * in the target domain must be paused.
 */

declare_mm_lock(altp2mlist)
#define altp2m_list_lock(d)   mm_lock(altp2mlist, &(d)->arch.altp2m_list_lock)
#define altp2m_list_unlock(d) mm_unlock(&(d)->arch.altp2m_list_lock)

/* P2M lock (per-altp2m-table)
 *
 * This protects all queries and updates to the p2m table.
 * Queries may be made under the read lock but all modifications
 * need the main (write) lock.
 *
 * The write lock is recursive as it is common for a code path to look
 * up a gfn and later mutate it.
 */

declare_mm_rwlock(altp2m);
#define p2m_lock(p)                         \
{                                           \
    if ( p2m_is_altp2m(p) )                 \
        mm_write_lock(altp2m, &(p)->lock);  \
    else                                    \
        mm_write_lock(p2m, &(p)->lock);     \
}
#define p2m_unlock(p)         mm_write_unlock(&(p)->lock);
#define gfn_lock(p,g,o)       p2m_lock(p)
#define gfn_unlock(p,g,o)     p2m_unlock(p)
#define p2m_read_lock(p)      mm_read_lock(p2m, &(p)->lock)
#define p2m_read_unlock(p)    mm_read_unlock(&(p)->lock)
#define p2m_locked_by_me(p)   mm_write_locked_by_me(&(p)->lock)
#define gfn_locked_by_me(p,g) p2m_locked_by_me(p)

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

/* PoD lock (per-p2m-table)
 * 
 * Protects private PoD data structs: entry and cache
 * counts, page lists, sweep parameters. */

declare_mm_lock(pod)
#define pod_lock(p)           mm_lock(pod, &(p)->pod.lock)
#define pod_unlock(p)         mm_unlock(&(p)->pod.lock)
#define pod_locked_by_me(p)   mm_locked_by_me(&(p)->pod.lock)

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
