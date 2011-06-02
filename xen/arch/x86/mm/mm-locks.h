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

/* Per-CPU variable for enforcing the lock ordering */
DECLARE_PER_CPU(int, mm_lock_level);

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

static inline void _mm_lock(mm_lock_t *l, const char *func, int level, int rec)
{
    /* If you see this crash, the numbers printed are lines in this file 
     * where the offending locks are declared. */
    if ( unlikely(this_cpu(mm_lock_level) > level) )
        panic("mm locking order violation: %i > %i\n", 
              this_cpu(mm_lock_level), level);
    spin_lock_recursive(&l->lock);
    if ( l->lock.recurse_cnt == 1 )
    {
        l->locker_function = func;
        l->unlock_level = this_cpu(mm_lock_level);
    }
    else if ( (unlikely(!rec)) )
        panic("mm lock already held by %s\n", l->locker_function);
    this_cpu(mm_lock_level) = level;
}
/* This wrapper uses the line number to express the locking order below */
#define declare_mm_lock(name)                                                 \
    static inline void mm_lock_##name(mm_lock_t *l, const char *func, int rec)\
    { _mm_lock(l, func, __LINE__, rec); }
/* These capture the name of the calling function */
#define mm_lock(name, l) mm_lock_##name(l, __func__, 0)
#define mm_lock_recursive(name, l) mm_lock_##name(l, __func__, 1)

static inline void mm_unlock(mm_lock_t *l)
{
    if ( l->lock.recurse_cnt == 1 )
    {
        l->locker_function = "nobody";
        this_cpu(mm_lock_level) = l->unlock_level;
    }
    spin_unlock_recursive(&l->lock);
}

/************************************************************************
 *                                                                      *
 * To avoid deadlocks, these locks _MUST_ be taken in the order they're *
 * declared in this file.  The locking functions will enforce this.     *
 *                                                                      *
 ************************************************************************/

/* Page-sharing lock (global) 
 *
 * A single global lock that protects the memory-sharing code's
 * hash tables. */

declare_mm_lock(shr)
#define shr_lock()         mm_lock(shr, &shr_lock)
#define shr_unlock()       mm_unlock(&shr_lock)
#define shr_locked_by_me() mm_locked_by_me(&shr_lock)

/* Nested P2M lock (per-domain)
 *
 * A per-domain lock that protects some of the nested p2m datastructures.
 * TODO: find out exactly what needs to be covered by this lock */

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

/* Shadow lock (per-domain)
 *
 * This lock is intended to allow us to make atomic updates to the
 * software TLB that the shadow pagetables provide.
 *
 * Specifically, it protects:
 *   - all changes to shadow page table pages
 *   - the shadow hash table
 *   - the shadow page allocator 
 *   - all changes to guest page table pages
 *   - all changes to the page_info->tlbflush_timestamp
 *   - the page_info->count fields on shadow pages */

declare_mm_lock(shadow)
#define shadow_lock(d)         mm_lock(shadow, &(d)->arch.paging.shadow.lock)
#define shadow_lock_recursive(d) \
                     mm_lock_recursive(shadow, &(d)->arch.paging.shadow.lock)
#define shadow_unlock(d)       mm_unlock(&(d)->arch.paging.shadow.lock)
#define shadow_locked_by_me(d) mm_locked_by_me(&(d)->arch.paging.shadow.lock)

/* HAP lock (per-domain)
 * 
 * Equivalent of the shadow lock for HAP.  Protects updates to the
 * NPT and EPT tables, and the HAP page allocator. */

declare_mm_lock(hap)
#define hap_lock(d)         mm_lock(hap, &(d)->arch.paging.hap.lock)
#define hap_lock_recursive(d) \
                  mm_lock_recursive(hap, &(d)->arch.paging.hap.lock)
#define hap_unlock(d)       mm_unlock(&(d)->arch.paging.hap.lock)
#define hap_locked_by_me(d) mm_locked_by_me(&(d)->arch.paging.hap.lock)

/* Log-dirty lock (per-domain) 
 * 
 * Protects the log-dirty bitmap from concurrent accesses (and teardowns, etc).
 *
 * Because mark_dirty is called from a lot of places, the log-dirty lock
 * may be acquired with the shadow or HAP locks already held.  When the
 * log-dirty code makes callbacks into HAP or shadow code to reset
 * various traps that will trigger the mark_dirty calls, it must *not*
 * have the log-dirty lock held, or it risks deadlock.  Because the only
 * purpose of those calls is to make sure that *guest* actions will
 * cause mark_dirty to be called (hypervisor actions explictly call it
 * anyway), it is safe to release the log-dirty lock before the callback
 * as long as the domain is paused for the entire operation. */

declare_mm_lock(log_dirty)
#define log_dirty_lock(d) mm_lock(log_dirty, &(d)->arch.paging.log_dirty.lock)
#define log_dirty_unlock(d) mm_unlock(&(d)->arch.paging.log_dirty.lock)


#endif /* _MM_LOCKS_H */
