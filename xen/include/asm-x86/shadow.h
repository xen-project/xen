/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */

#ifndef _XEN_SHADOW_H
#define _XEN_SHADOW_H

#include <xen/config.h>
#include <xen/types.h>
#include <xen/perfc.h>
#include <asm/processor.h>

/* Shadow PT flag bits in pfn_info */
#define PSH_shadowed    (1<<31) /* page has a shadow. PFN points to shadow */
#define PSH_pfn_mask    ((1<<21)-1)

/* Shadow PT operation mode : shadowmode variable in mm_struct */
#define SHM_test        (1) /* just run domain on shadow PTs */
#define SHM_logdirty    (2) /* log pages that are dirtied */
#define SHM_translate   (3) /* lookup machine pages in translation table */
#define SHM_cow         (4) /* copy on write all dirtied pages */

#define shadow_linear_pg_table ((l1_pgentry_t *)SH_LINEAR_PT_VIRT_START)
#define shadow_linear_l2_table ((l2_pgentry_t *)(SH_LINEAR_PT_VIRT_START + \
     (SH_LINEAR_PT_VIRT_START >> (L2_PAGETABLE_SHIFT - L1_PAGETABLE_SHIFT))))

#define shadow_mode(_d)      ((_d)->mm.shadow_mode)
#define shadow_lock_init(_d) spin_lock_init(&(_d)->mm.shadow_lock)
#define shadow_lock(_m)      spin_lock(&(_m)->shadow_lock)
#define shadow_unlock(_m)    spin_unlock(&(_m)->shadow_lock)

extern void shadow_mode_init(void);
extern int shadow_mode_control(struct domain *p, dom0_shadow_control_t *sc);
extern int shadow_fault(unsigned long va, long error_code);
extern void shadow_l1_normal_pt_update(
    unsigned long pa, unsigned long gpte, 
    unsigned long *prev_spfn_ptr, l1_pgentry_t **prev_spl1e_ptr);
extern void shadow_l2_normal_pt_update(unsigned long pa, unsigned long gpte);
extern void unshadow_table(unsigned long gpfn, unsigned int type);
extern int shadow_mode_enable(struct domain *p, unsigned int mode);

extern void __shadow_mode_disable(struct domain *d);
static inline void shadow_mode_disable(struct domain *d)
{
    if ( shadow_mode(d) )
        __shadow_mode_disable(d);
}

extern unsigned long shadow_l2_table( 
    struct mm_struct *m, unsigned long gpfn);

#define SHADOW_DEBUG      0
#define SHADOW_HASH_DEBUG 0

struct shadow_status {
    unsigned long pfn;            /* Guest pfn.             */
    unsigned long spfn_and_flags; /* Shadow pfn plus flags. */
    struct shadow_status *next;   /* Pull-to-front list.    */
};

#define shadow_ht_extra_size 128
#define shadow_ht_buckets    256

#ifdef VERBOSE
#define SH_LOG(_f, _a...)                             \
printk("DOM%u: (file=shadow.c, line=%d) " _f "\n",    \
       current->id , __LINE__ , ## _a )
#else
#define SH_LOG(_f, _a...) 
#endif

#if SHADOW_DEBUG
#define SH_VLOG(_f, _a...)                             \
    printk("DOM%u: (file=shadow.c, line=%d) " _f "\n", \
           current->id , __LINE__ , ## _a )
#else
#define SH_VLOG(_f, _a...) 
#endif

#if 0
#define SH_VVLOG(_f, _a...)                             \
    printk("DOM%u: (file=shadow.c, line=%d) " _f "\n",  \
           current->id , __LINE__ , ## _a )
#else
#define SH_VVLOG(_f, _a...) 
#endif


/************************************************************************/

static inline int __mark_dirty( struct mm_struct *m, unsigned int mfn)
{
    unsigned long pfn;
    int           rc = 0;

    ASSERT(spin_is_locked(&m->shadow_lock));
    ASSERT(m->shadow_dirty_bitmap != NULL);

    pfn = machine_to_phys_mapping[mfn];

    /*
     * Values with the MSB set denote MFNs that aren't really part of the 
     * domain's pseudo-physical memory map (e.g., the shared info frame).
     * Nothing to do here...
     */
    if ( unlikely(pfn & 0x80000000UL) )
        return rc;

    if ( likely(pfn < m->shadow_dirty_bitmap_size) )
    {
        /* N.B. Can use non-atomic TAS because protected by shadow_lock. */
        if ( !__test_and_set_bit(pfn, m->shadow_dirty_bitmap) )
        {
            m->shadow_dirty_count++;
            rc = 1;
        }
    }
#ifndef NDEBUG
    else if ( mfn < max_page )
    {
        SH_LOG("mark_dirty OOR! mfn=%x pfn=%lx max=%x (mm %p)",
               mfn, pfn, m->shadow_dirty_bitmap_size, m );
        SH_LOG("dom=%p caf=%08x taf=%08x\n", 
               frame_table[mfn].u.inuse.domain,
               frame_table[mfn].count_info, 
               frame_table[mfn].u.inuse.type_info );
        {
            extern void show_trace(unsigned long *esp);
            unsigned long *esp;
            __asm__ __volatile__ ("movl %%esp,%0" : "=r" (esp) : );
            show_trace(esp);
        }
    }
#endif

    return rc;
}


static inline int mark_dirty(struct mm_struct *m, unsigned int mfn)
{
    int rc;
    shadow_lock(m);
    rc = __mark_dirty(m, mfn);
    shadow_unlock(m);
    return rc;
}


/************************************************************************/

static inline void l1pte_write_fault(
    struct mm_struct *m, unsigned long *gpte_p, unsigned long *spte_p)
{ 
    unsigned long gpte = *gpte_p;
    unsigned long spte = *spte_p;

    ASSERT(gpte & _PAGE_RW);

    gpte |= _PAGE_DIRTY | _PAGE_ACCESSED;

    switch ( m->shadow_mode )
    {
    case SHM_test:
        spte = gpte | _PAGE_RW;
        break;

    case SHM_logdirty:
        spte = gpte | _PAGE_RW;
        __mark_dirty(m, gpte >> PAGE_SHIFT);
        break;
    }

    *gpte_p = gpte;
    *spte_p = spte;
}

static inline void l1pte_read_fault(
    struct mm_struct *m, unsigned long *gpte_p, unsigned long *spte_p)
{ 
    unsigned long gpte = *gpte_p;
    unsigned long spte = *spte_p;

    gpte |= _PAGE_ACCESSED;

    switch ( m->shadow_mode )
    {
    case SHM_test:
        spte = (gpte & _PAGE_DIRTY) ? gpte : (gpte & ~_PAGE_RW);
        break;

    case SHM_logdirty:
        spte = gpte & ~_PAGE_RW;
        break;
    }

    *gpte_p = gpte;
    *spte_p = spte;
}

static inline void l1pte_propagate_from_guest(
    struct mm_struct *m, unsigned long *gpte_p, unsigned long *spte_p)
{ 
    unsigned long gpte = *gpte_p;
    unsigned long spte = *spte_p;

    switch ( m->shadow_mode )
    {
    case SHM_test:
        spte = 0;
        if ( (gpte & (_PAGE_PRESENT|_PAGE_ACCESSED) ) == 
             (_PAGE_PRESENT|_PAGE_ACCESSED) )
            spte = (gpte & _PAGE_DIRTY) ? gpte : (gpte & ~_PAGE_RW);
        break;

    case SHM_logdirty:
        spte = 0;
        if ( (gpte & (_PAGE_PRESENT|_PAGE_ACCESSED) ) == 
             (_PAGE_PRESENT|_PAGE_ACCESSED) )
            spte = gpte & ~_PAGE_RW;
        break;
    }

    *gpte_p = gpte;
    *spte_p = spte;
}

static inline void l2pde_general(
    struct mm_struct *m,
    unsigned long *gpde_p,
    unsigned long *spde_p,
    unsigned long sl1pfn)
{
    unsigned long gpde = *gpde_p;
    unsigned long spde = *spde_p;

    spde = 0;

    if ( sl1pfn != 0 )
    {
        spde = (gpde & ~PAGE_MASK) | (sl1pfn << PAGE_SHIFT) | 
            _PAGE_RW | _PAGE_ACCESSED | _PAGE_DIRTY;
        gpde |= _PAGE_ACCESSED | _PAGE_DIRTY;

        /* Detect linear p.t. mappings and write-protect them. */
        if ( (frame_table[sl1pfn].u.inuse.type_info & PGT_type_mask) ==
             PGT_l2_page_table )
            spde = gpde & ~_PAGE_RW;
    }

    *gpde_p = gpde;
    *spde_p = spde;
}

/*********************************************************************/

#if SHADOW_HASH_DEBUG
static void shadow_audit(struct mm_struct *m, int print)
{
    int live = 0, free = 0, j = 0, abs;
    struct shadow_status *a;

    for ( j = 0; j < shadow_ht_buckets; j++ )
    {
        a = &m->shadow_ht[j];        
        if ( a->pfn ) { live++; ASSERT(a->spfn_and_flags & PSH_pfn_mask); }
        ASSERT(a->pfn < 0x00100000UL);
        a = a->next;
        while ( a && (live < 9999) )
        { 
            live++; 
            if ( (a->pfn == 0) || (a->spfn_and_flags == 0) )
            {
                printk("XXX live=%d pfn=%08lx sp=%08lx next=%p\n",
                       live, a->pfn, a->spfn_and_flags, a->next);
                BUG();
            }
            ASSERT(a->pfn < 0x00100000UL);
            ASSERT(a->spfn_and_flags & PSH_pfn_mask);
            a = a->next; 
        }
        ASSERT(live < 9999);
    }

    for ( a = m->shadow_ht_free; a != NULL; a = a->next )
        free++; 

    if ( print)
        printk("Xlive=%d free=%d\n",live,free);

    abs = (perfc_value(shadow_l1_pages) + perfc_value(shadow_l2_pages)) - live;
    if ( (abs < -1) || (abs > 1) )
    {
        printk("live=%d free=%d l1=%d l2=%d\n",live,free,
               perfc_value(shadow_l1_pages), perfc_value(shadow_l2_pages) );
        BUG();
    }
}
#else
#define shadow_audit(p, print) ((void)0)
#endif



static inline struct shadow_status *hash_bucket(
    struct mm_struct *m, unsigned int gpfn)
{
    return &m->shadow_ht[gpfn % shadow_ht_buckets];
}


static inline unsigned long __shadow_status(
    struct mm_struct *m, unsigned int gpfn)
{
    struct shadow_status *p, *x, *head;

    x = head = hash_bucket(m, gpfn);
    p = NULL;

    SH_VVLOG("lookup gpfn=%08x bucket=%p", gpfn, x);
    shadow_audit(m, 0);

    do
    {
        ASSERT(x->pfn || ((x == head) && (x->next == NULL)));

        if ( x->pfn == gpfn )
        {
            /* Pull-to-front if 'x' isn't already the head item. */
            if ( unlikely(x != head) )
            {
                /* Delete 'x' from list and reinsert immediately after head. */
                p->next = x->next;
                x->next = head->next;
                head->next = x;

                /* Swap 'x' contents with head contents. */
                SWAP(head->pfn, x->pfn);
                SWAP(head->spfn_and_flags, x->spfn_and_flags);
            }

            return head->spfn_and_flags;
        }

        p = x;
        x = x->next;
    }
    while ( x != NULL );

    return 0;
}

/*
 * N.B. We can make this locking more fine grained (e.g., per shadow page) if
 * it ever becomes a problem, but since we need a spin lock on the hash table 
 * anyway it's probably not worth being too clever.
 */
static inline unsigned long get_shadow_status(
    struct mm_struct *m, unsigned int gpfn )
{
    unsigned long res;

    ASSERT(m->shadow_mode);

    /*
     * If we get here we know that some sort of update has happened to the
     * underlying page table page: either a PTE has been updated, or the page
     * has changed type. If we're in log dirty mode, we should set the
     * appropriate bit in the dirty bitmap.
     * N.B. The VA update path doesn't use this and is handled independently. 
     */

    shadow_lock(m);

    if ( m->shadow_mode == SHM_logdirty )
        __mark_dirty( m, gpfn );

    if ( !(res = __shadow_status(m, gpfn)) )
        shadow_unlock(m);

    return res;
}


static inline void put_shadow_status(
    struct mm_struct *m)
{
    shadow_unlock(m);
}


static inline void delete_shadow_status( 
    struct mm_struct *m, unsigned int gpfn)
{
    struct shadow_status *p, *x, *n, *head;

    ASSERT(spin_is_locked(&m->shadow_lock));
    ASSERT(gpfn != 0);

    head = hash_bucket(m, gpfn);

    SH_VVLOG("delete gpfn=%08x bucket=%p", gpfn, b);
    shadow_audit(m, 0);

    /* Match on head item? */
    if ( head->pfn == gpfn )
    {
        if ( (n = head->next) != NULL )
        {
            /* Overwrite head with contents of following node. */
            head->pfn            = n->pfn;
            head->spfn_and_flags = n->spfn_and_flags;

            /* Delete following node. */
            head->next           = n->next;

            /* Add deleted node to the free list. */
            n->pfn            = 0;
            n->spfn_and_flags = 0;
            n->next           = m->shadow_ht_free;
            m->shadow_ht_free = n;
        }
        else
        {
            /* This bucket is now empty. Initialise the head node. */
            head->pfn            = 0;
            head->spfn_and_flags = 0;
        }

        goto found;
    }

    p = head;
    x = head->next;

    do
    {
        if ( x->pfn == gpfn )
        {
            /* Delete matching node. */
            p->next = x->next;

            /* Add deleted node to the free list. */
            x->pfn            = 0;
            x->spfn_and_flags = 0;
            x->next           = m->shadow_ht_free;
            m->shadow_ht_free = x;

            goto found;
        }

        p = x;
        x = x->next;
    }
    while ( x != NULL );

    /* If we got here, it wasn't in the list! */
    BUG();

 found:
    shadow_audit(m, 0);
}


static inline void set_shadow_status(
    struct mm_struct *m, unsigned int gpfn, unsigned long s)
{
    struct shadow_status *x, *head, *extra;
    int i;

    ASSERT(spin_is_locked(&m->shadow_lock));
    ASSERT(gpfn != 0);
    ASSERT(s & PSH_shadowed);

    x = head = hash_bucket(m, gpfn);
   
    SH_VVLOG("set gpfn=%08x s=%08lx bucket=%p(%p)", gpfn, s, b, b->next);
    shadow_audit(m, 0);

    /*
     * STEP 1. If page is already in the table, update it in place.
     */

    do
    {
        if ( x->pfn == gpfn )
        {
            x->spfn_and_flags = s;
            goto done;
        }

        x = x->next;
    }
    while ( x != NULL );

    /*
     * STEP 2. The page must be inserted into the table.
     */

    /* If the bucket is empty then insert the new page as the head item. */
    if ( head->pfn == 0 )
    {
        head->pfn            = gpfn;
        head->spfn_and_flags = s;
        ASSERT(head->next == NULL);
        goto done;
    }

    /* We need to allocate a new node. Ensure the quicklist is non-empty. */
    if ( unlikely(m->shadow_ht_free == NULL) )
    {
        SH_LOG("Allocate more shadow hashtable blocks.");

        extra = xmalloc(
            sizeof(void *) + (shadow_ht_extra_size * sizeof(*x)));

        /* XXX Should be more graceful here. */
        if ( extra == NULL )
            BUG();

        memset(extra, 0, sizeof(void *) + (shadow_ht_extra_size * sizeof(*x)));

        /* Record the allocation block so it can be correctly freed later. */
        m->shadow_extras_count++;
        *((struct shadow_status **)&extra[shadow_ht_extra_size]) = 
            m->shadow_ht_extras;
        m->shadow_ht_extras = &extra[0];

        /* Thread a free chain through the newly-allocated nodes. */
        for ( i = 0; i < (shadow_ht_extra_size - 1); i++ )
            extra[i].next = &extra[i+1];
        extra[i].next = NULL;

        /* Add the new nodes to the free list. */
        m->shadow_ht_free = &extra[0];
    }

    /* Allocate a new node from the quicklist. */
    x                 = m->shadow_ht_free;
    m->shadow_ht_free = x->next;

    /* Initialise the new node and insert directly after the head item. */
    x->pfn            = gpfn;
    x->spfn_and_flags = s;
    x->next           = head->next;
    head->next        = x;

 done:
    shadow_audit(m, 0);
}

static inline void __shadow_mk_pagetable(struct mm_struct *mm)
{
    unsigned long gpfn = pagetable_val(mm->pagetable) >> PAGE_SHIFT;
    unsigned long spfn = __shadow_status(mm, gpfn);

    if ( unlikely(spfn == 0) )
        spfn = shadow_l2_table(mm, gpfn);

    mm->shadow_table = mk_pagetable(spfn << PAGE_SHIFT);
}

static inline void shadow_mk_pagetable(struct mm_struct *mm)
{
    SH_VVLOG("shadow_mk_pagetable( gptbase=%08lx, mode=%d )",
             pagetable_val(mm->pagetable), mm->shadow_mode );

    if ( unlikely(mm->shadow_mode) )
    {
        shadow_lock(mm);
        __shadow_mk_pagetable(mm);
        shadow_unlock(mm);
    }

    SH_VVLOG("leaving shadow_mk_pagetable( gptbase=%08lx, mode=%d ) sh=%08lx",
             pagetable_val(mm->pagetable), mm->shadow_mode, 
             pagetable_val(mm->shadow_table) );
}

#if SHADOW_DEBUG
extern int check_pagetable(struct mm_struct *m, pagetable_t pt, char *s);
#else
#define check_pagetable(m, pt, s) ((void)0)
#endif

#endif /* XEN_SHADOW_H */
