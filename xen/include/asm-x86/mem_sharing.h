/******************************************************************************
 * include/asm-x86/mem_sharing.h
 *
 * Memory sharing support.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Grzegorz Milos)
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
#ifndef __MEM_SHARING_H__
#define __MEM_SHARING_H__

#include <public/domctl.h>
#include <public/memory.h>

/* Auditing of memory sharing code? */
#define MEM_SHARING_AUDIT 1

typedef uint64_t shr_handle_t; 

typedef struct rmap_hashtab {
    struct list_head *bucket;
    /* Overlaps with prev pointer of list_head in union below.
     * Unlike the prev pointer, this can be NULL. */
    void *flag;
} rmap_hashtab_t;

struct page_sharing_info
{
    struct page_info *pg;   /* Back pointer to the page. */
    shr_handle_t handle;    /* Globally unique version / handle. */
#if MEM_SHARING_AUDIT
    struct list_head entry; /* List of all shared pages (entry). */
    struct rcu_head rcu_head; /* List of all shared pages (entry). */
#endif
    /* Reverse map of <domain,gfn> tuples for this shared frame. */
    union {
        struct list_head    gfns;
        rmap_hashtab_t      hash_table;
    };
};

#define sharing_supported(_d) \
    (is_hvm_domain(_d) && paging_mode_hap(_d)) 

unsigned int mem_sharing_get_nr_saved_mfns(void);
unsigned int mem_sharing_get_nr_shared_mfns(void);
int mem_sharing_nominate_page(struct domain *d, 
                              unsigned long gfn,
                              int expected_refcnt,
                              shr_handle_t *phandle);

#define MEM_SHARING_DESTROY_GFN       (1<<1)
/* Only fails with -ENOMEM. Enforce it with a BUG_ON wrapper. */
int __mem_sharing_unshare_page(struct domain *d,
                             unsigned long gfn, 
                             uint16_t flags);
static inline int mem_sharing_unshare_page(struct domain *d,
                                           unsigned long gfn,
                                           uint16_t flags)
{
    int rc = __mem_sharing_unshare_page(d, gfn, flags);
    BUG_ON( rc && (rc != -ENOMEM) );
    return rc;
}

/* If called by a foreign domain, possible errors are
 *   -EBUSY -> ring full
 *   -ENOSYS -> no ring to begin with
 * and the foreign mapper is responsible for retrying.
 *
 * If called by the guest vcpu itself and allow_sleep is set, may 
 * sleep on a wait queue, so the caller is responsible for not 
 * holding locks on entry. It may only fail with ENOSYS 
 *
 * If called by the guest vcpu itself and allow_sleep is not set,
 * then it's the same as a foreign domain.
 */
int mem_sharing_notify_enomem(struct domain *d, unsigned long gfn,
                                bool_t allow_sleep);
int mem_sharing_sharing_resume(struct domain *d);
int mem_sharing_memop(struct domain *d, 
                       xen_mem_sharing_op_t *mec);
int mem_sharing_domctl(struct domain *d, 
                       xen_domctl_mem_sharing_op_t *mec);
int mem_sharing_audit(void);
void mem_sharing_init(void);

/* Scans the p2m and relinquishes any shared pages, destroying 
 * those for which this domain holds the final reference.
 * Preemptible.
 */
int relinquish_shared_pages(struct domain *d);

#endif /* __MEM_SHARING_H__ */
