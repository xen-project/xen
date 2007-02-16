/******************************************************************************
 * tlb_track.c
 *
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
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
 *
 */

#include <asm/tlb_track.h>
#include <asm/p2m_entry.h>
#include <asm/vmx_mm_def.h>  /* for IA64_RR_SHIFT */
#include <asm/vmx_vcpu.h>    /* for VRN7 */
#include <asm/vcpu.h>        /* for PSCB() */

#define CONFIG_TLB_TRACK_DEBUG
#ifdef CONFIG_TLB_TRACK_DEBUG
# define tlb_track_printd(fmt, ...)     \
    dprintk(XENLOG_DEBUG, fmt, ##__VA_ARGS__)
#else
# define tlb_track_printd(fmt, ...)     do { } while (0)
#endif

static int
tlb_track_allocate_entries(struct tlb_track* tlb_track)
{
    struct page_info* entry_page;
    struct tlb_track_entry* track_entries;
    unsigned int allocated;
    unsigned long i;

    BUG_ON(tlb_track->num_free > 0);
    if (tlb_track->num_entries >= tlb_track->limit) {
        dprintk(XENLOG_WARNING, "%s: num_entries %d limit %d\n",
                __func__, tlb_track->num_entries, tlb_track->limit);
        return -ENOMEM;
    }
    entry_page = alloc_domheap_page(NULL);
    if (entry_page == NULL) {
        dprintk(XENLOG_WARNING,
                "%s: domheap page failed. num_entries %d limit %d\n",
                __func__, tlb_track->num_entries, tlb_track->limit);
        return -ENOMEM;
    }

    list_add(&entry_page->list, &tlb_track->page_list);
    track_entries = (struct tlb_track_entry*)page_to_virt(entry_page);
    allocated = PAGE_SIZE / sizeof(track_entries[0]);
    tlb_track->num_entries += allocated;
    tlb_track->num_free += allocated;
    for (i = 0; i < allocated; i++) {
        list_add(&track_entries[i].list, &tlb_track->free_list);
        // tlb_track_printd("track_entries[%ld] 0x%p\n", i, &track_entries[i]);
    }
    tlb_track_printd("allocated %d num_entries %d num_free %d\n",
                     allocated, tlb_track->num_entries, tlb_track->num_free);
    return 0;
}


int
tlb_track_create(struct domain* d)
{
    struct tlb_track* tlb_track = NULL;
    struct page_info* hash_page = NULL;
    unsigned int hash_size;
    unsigned int hash_shift;
    unsigned int i;

    tlb_track = xmalloc(struct tlb_track);
    if (tlb_track == NULL)
        goto out;

    hash_page = alloc_domheap_page(NULL);
    if (hash_page == NULL)
        goto out;

    spin_lock_init(&tlb_track->free_list_lock);
    INIT_LIST_HEAD(&tlb_track->free_list);
    tlb_track->limit = TLB_TRACK_LIMIT_ENTRIES;
    tlb_track->num_entries = 0;
    tlb_track->num_free = 0;
    INIT_LIST_HEAD(&tlb_track->page_list);
    if (tlb_track_allocate_entries(tlb_track) < 0)
        goto out;

    spin_lock_init(&tlb_track->hash_lock);
    /* XXX hash size optimization */
    hash_size = PAGE_SIZE / sizeof(tlb_track->hash[0]);
    for (hash_shift = 0; (1 << (hash_shift + 1)) < hash_size; hash_shift++)
        /* nothing */;
    tlb_track->hash_size = (1 << hash_shift);
    tlb_track->hash_shift = hash_shift;
    tlb_track->hash_mask = (1 << hash_shift) - 1;
    tlb_track->hash = page_to_virt(hash_page);
    for (i = 0; i < tlb_track->hash_size; i++)
        INIT_LIST_HEAD(&tlb_track->hash[i]);

    smp_mb(); /* make initialization visible before use. */
    d->arch.tlb_track = tlb_track;
    dprintk(XENLOG_DEBUG, "hash 0x%p hash_size %d\n",
            tlb_track->hash, tlb_track->hash_size);

    return 0;

out:
    if (hash_page != NULL)
        free_domheap_page(hash_page);

    if (tlb_track != NULL)
        xfree(tlb_track);

    return -ENOMEM;
}

void
tlb_track_destroy(struct domain* d)
{
    struct tlb_track* tlb_track = d->arch.tlb_track;
    struct page_info* page;
    struct page_info* next;

    spin_lock(&tlb_track->free_list_lock);
    BUG_ON(tlb_track->num_free != tlb_track->num_entries);

    list_for_each_entry_safe(page, next, &tlb_track->page_list, list) {
        list_del(&page->list);
        free_domheap_page(page);
    }

    free_domheap_page(virt_to_page(tlb_track->hash));
    xfree(tlb_track);
    // d->tlb_track = NULL;
}

static struct tlb_track_entry*
tlb_track_get_entry(struct tlb_track* tlb_track)
{
    struct tlb_track_entry* entry = NULL;
    spin_lock(&tlb_track->free_list_lock);
    if (tlb_track->num_free == 0)
        (void)tlb_track_allocate_entries(tlb_track);

    if (tlb_track->num_free > 0) {
        BUG_ON(list_empty(&tlb_track->free_list));
        entry = list_entry(tlb_track->free_list.next,
                           struct tlb_track_entry, list);
        tlb_track->num_free--;
        list_del(&entry->list);
    }
    spin_unlock(&tlb_track->free_list_lock);
    return entry;
}

void
tlb_track_free_entry(struct tlb_track* tlb_track,
                     struct tlb_track_entry* entry)
{
    spin_lock(&tlb_track->free_list_lock);
    list_add(&entry->list, &tlb_track->free_list);
    tlb_track->num_free++;
    spin_unlock(&tlb_track->free_list_lock);
}


#include <linux/hash.h>
/* XXX hash function. */
static struct list_head*
tlb_track_hash_head(struct tlb_track* tlb_track, volatile pte_t* ptep)
{
    unsigned long hash = hash_long((unsigned long)ptep, tlb_track->hash_shift);
    BUG_ON(hash >= tlb_track->hash_size);
    BUG_ON((hash & tlb_track->hash_mask) != hash);
    return &tlb_track->hash[hash];
}

static int
tlb_track_pte_zapped(pte_t old_pte, pte_t ret_pte)
{
    if (pte_pfn(old_pte) != pte_pfn(ret_pte) ||
        (pte_val(old_pte) & ~(_PFN_MASK | _PAGE_TLB_TRACK_MASK)) !=
        (pte_val(ret_pte) & ~(_PFN_MASK | _PAGE_TLB_TRACK_MASK))) {
        /* Other thread zapped the p2m entry. */
        return 1;
    }
    return 0;
}

static TLB_TRACK_RET_T
tlb_track_insert_or_dirty(struct tlb_track* tlb_track, struct mm_struct* mm,
                          volatile pte_t* ptep, pte_t old_pte,
                          unsigned long vaddr, unsigned long rid)
{
    unsigned long mfn = pte_pfn(old_pte);
    struct list_head* head = tlb_track_hash_head(tlb_track, ptep);
    struct tlb_track_entry* entry;
    struct tlb_track_entry* new_entry = NULL;
    unsigned long bit_to_be_set = _PAGE_TLB_INSERTED;
    pte_t new_pte;
    pte_t ret_pte;

    struct vcpu* v = current;
    TLB_TRACK_RET_T ret = TLB_TRACK_NOT_FOUND;

#if 0 /* this is done at vcpu_tlb_track_insert_or_dirty() */
    perfc_incrc(tlb_track_iod);
    if (!pte_tlb_tracking(old_pte)) {
        perfc_incrc(tlb_track_iod_not_tracked);
        return TLB_TRACK_NOT_TRACKED;
    }
#endif
    if (pte_tlb_inserted_many(old_pte)) {
        perfc_incrc(tlb_track_iod_tracked_many);
        return TLB_TRACK_MANY;
    }

    /* vaddr must be normalized so that it is in vrn7 and page aligned. */
    BUG_ON((vaddr >> IA64_RR_SHIFT) != VRN7);
    BUG_ON((vaddr & ~PAGE_MASK) != 0);
#if 0
    tlb_track_printd("\n"
                     "\tmfn 0x%016lx\n"
                     "\told_pte 0x%016lx ptep 0x%p\n"
                     "\tptep_val 0x%016lx vaddr 0x%016lx rid %ld\n"
                     "\ttlb_track 0x%p head 0x%p\n",
                     mfn,
                     pte_val(old_pte), ptep, pte_val(*ptep),
                     vaddr, rid,
                     tlb_track, head);
#endif

 again:
    /*
     * zapping side may zap the p2m entry and then remove tlb track entry
     * non-atomically. We may see the stale tlb track entry here.
     * p2m_entry_retry() handles such a case.
     * Or other thread may zap the p2m entry and remove tlb track entry
     * and inserted new tlb track entry.
     */
    spin_lock(&tlb_track->hash_lock);
    list_for_each_entry(entry, head, list) {
        if (entry->ptep != ptep)
            continue;

        if (pte_pfn(entry->pte_val) == mfn) {
            // tlb_track_entry_printf(entry);
            if (entry->vaddr == vaddr && entry->rid == rid) {
                // tlb_track_printd("TLB_TRACK_FOUND\n");
                ret = TLB_TRACK_FOUND;
                perfc_incrc(tlb_track_iod_found);
#ifdef CONFIG_TLB_TRACK_CNT
                entry->cnt++;
                if (entry->cnt > TLB_TRACK_CNT_FORCE_MANY) {
                    /*
                     * heuristics:
                     * If a page is used to transfer data by dev channel,
                     * it would be unmapped with small amount access
                     * (once or twice tlb insert) after real device
                     * I/O completion. It would be short period.
                     * However this page seems to be accessed many times.
                     * We guess that this page is used I/O ring
                     * so that tracking this entry might be useless.
                     */
                     // tlb_track_entry_printf(entry);
                     // tlb_track_printd("cnt = %ld\n", entry->cnt);
                    perfc_incrc(tlb_track_iod_force_many);
                    goto force_many;
                }
#endif
                goto found;
            } else {
#ifdef CONFIG_TLB_TRACK_CNT
            force_many:
#endif
                if (!pte_tlb_inserted(old_pte)) {
                    printk("%s:%d racy update\n", __func__, __LINE__);
                    old_pte = __pte(pte_val(old_pte) | _PAGE_TLB_INSERTED);
                }
                new_pte = __pte(pte_val(old_pte) | _PAGE_TLB_INSERTED_MANY);
                ret_pte = ptep_cmpxchg_rel(mm, vaddr, ptep, old_pte, new_pte);
                if (pte_val(ret_pte) != pte_val(old_pte)) {
                    // tlb_track_printd("TLB_TRACK_AGAIN\n");
                    ret = TLB_TRACK_AGAIN;
                    perfc_incrc(tlb_track_iod_again);
                } else {
                    // tlb_track_printd("TLB_TRACK_MANY del entry 0x%p\n",
                    //                  entry);
                    ret = TLB_TRACK_MANY;
                    list_del(&entry->list);
                    // tlb_track_entry_printf(entry);
                    perfc_incrc(tlb_track_iod_tracked_many_del);
                }
                goto out;
            }
        }

        /*
         * Other thread changed the p2m entry and removed and inserted new
         * tlb tracn entry after we get old_pte, but before we get
         * spinlock.
         */
        // tlb_track_printd("TLB_TRACK_AGAIN\n");
        ret = TLB_TRACK_AGAIN;
        perfc_incrc(tlb_track_iod_again);
        goto out;
    }

    entry = NULL; // prevent freeing entry.
    if (pte_tlb_inserted(old_pte)) {
        /* Other thread else removed the tlb_track_entry after we got old_pte
           before we got spin lock. */
        ret = TLB_TRACK_AGAIN;
        perfc_incrc(tlb_track_iod_again);
        goto out;
    }
    if (new_entry == NULL && bit_to_be_set == _PAGE_TLB_INSERTED) {
        spin_unlock(&tlb_track->hash_lock);
        new_entry = tlb_track_get_entry(tlb_track);
        if (new_entry == NULL) {
            tlb_track_printd("get_entry failed\n");
            /* entry can't be allocated.
               fall down into full flush mode. */
            bit_to_be_set |= _PAGE_TLB_INSERTED_MANY;
            perfc_incrc(tlb_track_iod_new_failed);
        }
        // tlb_track_printd("new_entry 0x%p\n", new_entry);
        perfc_incrc(tlb_track_iod_new_entry);
        goto again;
    }

    BUG_ON(pte_tlb_inserted_many(old_pte));
    new_pte = __pte(pte_val(old_pte) | bit_to_be_set);
    ret_pte = ptep_cmpxchg_rel(mm, vaddr, ptep, old_pte, new_pte);
    if (pte_val(old_pte) != pte_val(ret_pte)) {
        if (tlb_track_pte_zapped(old_pte, ret_pte)) {
            // tlb_track_printd("zapped TLB_TRACK_AGAIN\n");
            ret = TLB_TRACK_AGAIN;
            perfc_incrc(tlb_track_iod_again);
            goto out;
        }

        /* Other thread set _PAGE_TLB_INSERTED and/or _PAGE_TLB_INSERTED_MANY */
        if (pte_tlb_inserted_many(ret_pte)) {
            /* Other thread already set _PAGE_TLB_INSERTED_MANY and
               removed the entry. */
            // tlb_track_printd("iserted TLB_TRACK_MANY\n");
            BUG_ON(!pte_tlb_inserted(ret_pte));
            ret = TLB_TRACK_MANY;
            perfc_incrc(tlb_track_iod_new_many);
            goto out;
        }
        BUG_ON(pte_tlb_inserted(ret_pte));
        BUG();
    }
    if (new_entry) {
        // tlb_track_printd("iserting new_entry 0x%p\n", new_entry);
        entry = new_entry;
        new_entry = NULL;

        entry->ptep = ptep;
        entry->pte_val = old_pte;
        entry->vaddr = vaddr;
        entry->rid = rid;
        cpus_clear(entry->pcpu_dirty_mask);
        vcpus_clear(entry->vcpu_dirty_mask);
        list_add(&entry->list, head);

#ifdef CONFIG_TLB_TRACK_CNT
        entry->cnt = 0;
#endif
        perfc_incrc(tlb_track_iod_insert);
        // tlb_track_entry_printf(entry);
    } else {
        goto out;
    }

 found:
    BUG_ON(v->processor >= NR_CPUS);
    cpu_set(v->processor, entry->pcpu_dirty_mask);
    BUG_ON(v->vcpu_id >= NR_CPUS);
    vcpu_set(v->vcpu_id, entry->vcpu_dirty_mask);
    perfc_incrc(tlb_track_iod_dirtied);

 out:
    spin_unlock(&tlb_track->hash_lock);
    if (ret == TLB_TRACK_MANY && entry != NULL)
        tlb_track_free_entry(tlb_track, entry);
    if (new_entry != NULL)
        tlb_track_free_entry(tlb_track, new_entry);
    return ret;
}

void
__vcpu_tlb_track_insert_or_dirty(struct vcpu *vcpu, unsigned long vaddr,
                                 struct p2m_entry* entry)
{
    unsigned long vrn = vaddr >> IA64_RR_SHIFT;
    unsigned long rid = PSCB(vcpu, rrs[vrn]);
    TLB_TRACK_RET_T ret;

    /* normalize vrn7
       When linux dom0 case, vrn7 is the most common case. */
    vaddr |= VRN7 << VRN_SHIFT;
    vaddr &= PAGE_MASK;
    ret = tlb_track_insert_or_dirty(vcpu->domain->arch.tlb_track,
                                    &vcpu->domain->arch.mm,
                                    entry->ptep, entry->used,
                                    vaddr, rid);
    if (ret == TLB_TRACK_AGAIN)
        p2m_entry_set_retry(entry);
}

TLB_TRACK_RET_T
tlb_track_search_and_remove(struct tlb_track* tlb_track,
                            volatile pte_t* ptep, pte_t old_pte,
                            struct tlb_track_entry** entryp)
{
    unsigned long mfn = pte_pfn(old_pte);
    struct list_head* head = tlb_track_hash_head(tlb_track, ptep);
    struct tlb_track_entry* entry;

    perfc_incrc(tlb_track_sar);
    if (!pte_tlb_tracking(old_pte)) {
        perfc_incrc(tlb_track_sar_not_tracked);
        return TLB_TRACK_NOT_TRACKED;
    }
    if (!pte_tlb_inserted(old_pte)) {
        BUG_ON(pte_tlb_inserted_many(old_pte));
        perfc_incrc(tlb_track_sar_not_found);
        return TLB_TRACK_NOT_FOUND;
    }
    if (pte_tlb_inserted_many(old_pte)) {
        BUG_ON(!pte_tlb_inserted(old_pte));
        perfc_incrc(tlb_track_sar_many);
        return TLB_TRACK_MANY;
    }

    spin_lock(&tlb_track->hash_lock);
    list_for_each_entry(entry, head, list) {
        if (entry->ptep != ptep)
            continue;

        if (pte_pfn(entry->pte_val) == mfn) {
            /*
             * PARANOIA
             * We're here after zapping p2m entry.  However another pCPU
             * may update the same p2m entry entry the same mfn at the
             * same time in theory.  In such a case, we can't determine
             * whether this entry is for us or for the racy p2m update.
             * Such a guest domain's racy behaviour doesn't make sense,
             * but is allowed.  Go the very pessimistic way.  Leave this
             * entry to be found later and do full flush at this time.
             *
             * NOTE: Updating tlb tracking hash is protected by spin lock and
             *       setting _PAGE_TLB_INSERTED and_PAGE_TLB_INSERTED_MANY bits
             *       is serialized by the same spin lock.
             *       See tlb_track_insert_or_dirty().
             */
            pte_t current_pte = *ptep;
            if (unlikely(pte_pfn(current_pte) == mfn &&
                         pte_tlb_tracking(current_pte) &&
                         pte_tlb_inserted(current_pte))) {
                BUG_ON(pte_tlb_inserted_many(current_pte));
                spin_unlock(&tlb_track->hash_lock);
                perfc_incrc(tlb_track_sar_many);
                return TLB_TRACK_MANY;
            }

            list_del(&entry->list);
            spin_unlock(&tlb_track->hash_lock);
            *entryp = entry;
            perfc_incrc(tlb_track_sar_found);
            // tlb_track_entry_printf(entry);
#ifdef CONFIG_TLB_TRACK_CNT
            // tlb_track_printd("cnt = %ld\n", entry->cnt);
#endif
            return TLB_TRACK_FOUND;
        }
        BUG();
    }
    BUG();
    spin_unlock(&tlb_track->hash_lock);
    return TLB_TRACK_NOT_TRACKED;
}

/* for debug */
void
__tlb_track_entry_printf(const char* func, int line,
                         const struct tlb_track_entry* entry)
{
    char pcpumask_buf[NR_CPUS + 1];
    char vcpumask_buf[MAX_VIRT_CPUS + 1];
    cpumask_scnprintf(pcpumask_buf, sizeof(pcpumask_buf),
                      entry->pcpu_dirty_mask);
    vcpumask_scnprintf(vcpumask_buf, sizeof(vcpumask_buf),
                       entry->vcpu_dirty_mask);
    printk("%s:%d\n"
           "\tmfn 0x%016lx\n"
           "\told_pte 0x%016lx ptep 0x%p\n"
           "\tpte_val 0x%016lx vaddr 0x%016lx rid %ld\n"
           "\tpcpu_dirty_mask %s vcpu_dirty_mask %s\n"
           "\tentry 0x%p\n",
           func, line,
           pte_pfn(entry->pte_val),
           pte_val(entry->pte_val), entry->ptep, pte_val(*entry->ptep),
           entry->vaddr, entry->rid,
           pcpumask_buf, vcpumask_buf,
           entry);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
