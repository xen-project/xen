/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */

#ifndef _XEN_SHADOW_H
#define _XEN_SHADOW_H

#include <xen/config.h>
#include <xen/types.h>
#include <xen/perfc.h>
#include <asm/processor.h>

#ifdef CONFIG_VMX
#include <asm/domain_page.h>
#endif

/* Shadow PT flag bits in pfn_info */
#define PSH_shadowed    (1<<31) /* page has a shadow. PFN points to shadow */
#define PSH_pfn_mask    ((1<<21)-1)

/* Shadow PT operation mode : shadow-mode variable in arch_domain. */

#define SHM_enable    (1<<0) /* we're in one of the shadow modes */
#define SHM_log_dirty (1<<1) /* enable log dirty mode */
#define SHM_translate (1<<2) /* do p2m tranaltion on guest tables */
#define SHM_external  (1<<3) /* external page table, not used by Xen */

#define shadow_mode_enabled(_d)   ((_d)->arch.shadow_mode)
#define shadow_mode_log_dirty(_d) ((_d)->arch.shadow_mode & SHM_log_dirty)
#define shadow_mode_translate(_d) ((_d)->arch.shadow_mode & SHM_translate)
#define shadow_mode_external(_d)  ((_d)->arch.shadow_mode & SHM_external)

#define shadow_linear_pg_table ((l1_pgentry_t *)SH_LINEAR_PT_VIRT_START)
#define shadow_linear_l2_table ((l2_pgentry_t *)(SH_LINEAR_PT_VIRT_START + \
     (SH_LINEAR_PT_VIRT_START >> (L2_PAGETABLE_SHIFT - L1_PAGETABLE_SHIFT))))

#define shadow_lock_init(_d) spin_lock_init(&(_d)->arch.shadow_lock)
#define shadow_lock(_d)      spin_lock(&(_d)->arch.shadow_lock)
#define shadow_unlock(_d)    spin_unlock(&(_d)->arch.shadow_lock)

extern void shadow_mode_init(void);
extern int shadow_mode_control(struct domain *p, dom0_shadow_control_t *sc);
extern int shadow_fault(unsigned long va, long error_code);
extern void shadow_l1_normal_pt_update(
    unsigned long pa, unsigned long gpte, 
    unsigned long *prev_spfn_ptr, l1_pgentry_t **prev_spl1e_ptr);
extern void shadow_l2_normal_pt_update(unsigned long pa, unsigned long gpde);
extern void unshadow_table(unsigned long gpfn, unsigned int type);
extern int shadow_mode_enable(struct domain *p, unsigned int mode);
extern void free_shadow_state(struct domain *d);
extern void shadow_invlpg(struct exec_domain *, unsigned long);

#ifdef CONFIG_VMX
extern void vmx_shadow_clear_state(struct domain *);
#endif

#define __mfn_to_gpfn(_d, mfn)                         \
    ( (shadow_mode_translate(_d))                      \
      ? machine_to_phys_mapping[(mfn)]                 \
      : (mfn) )

#define __gpfn_to_mfn(_d, gpfn)                        \
    ( (shadow_mode_translate(_d))                      \
      ? phys_to_machine_mapping(gpfn)                  \
      : (gpfn) )

extern void __shadow_mode_disable(struct domain *d);
static inline void shadow_mode_disable(struct domain *d)
{
    if ( shadow_mode_enabled(d) )
        __shadow_mode_disable(d);
}

extern unsigned long shadow_l2_table( 
    struct domain *d, unsigned long gpfn);
  
static inline void shadow_invalidate(struct exec_domain *ed) {
    if ( !shadow_mode_translate(ed->domain))
        BUG();
    memset(ed->arch.shadow_vtable, 0, PAGE_SIZE);
}

#define SHADOW_DEBUG 0
#define SHADOW_VERBOSE_DEBUG 0
#define SHADOW_HASH_DEBUG 0

#if SHADOW_DEBUG
extern int shadow_status_noswap;
#endif

struct shadow_status {
    unsigned long pfn;            /* Guest pfn.             */
    unsigned long smfn_and_flags; /* Shadow mfn plus flags. */
    struct shadow_status *next;   /* Pull-to-front list.    */
};

#define shadow_ht_extra_size 128
#define shadow_ht_buckets    256

#ifdef VERBOSE
#define SH_LOG(_f, _a...)                                               \
    printk("DOM%uP%u: SH_LOG(%d): " _f "\n",                            \
       current->domain->id , current->processor, __LINE__ , ## _a )
#else
#define SH_LOG(_f, _a...) 
#endif

#if SHADOW_DEBUG
#define SH_VLOG(_f, _a...)                                              \
    printk("DOM%uP%u: SH_VLOG(%d): " _f "\n",                           \
           current->domain->id, current->processor, __LINE__ , ## _a )
#else
#define SH_VLOG(_f, _a...) 
#endif

#if SHADOW_VERBOSE_DEBUG
#define SH_VVLOG(_f, _a...)                                             \
    printk("DOM%uP%u: SH_VVLOG(%d): " _f "\n",                          \
           current->domain->id, current->processor, __LINE__ , ## _a )
#else
#define SH_VVLOG(_f, _a...)
#endif

// BUG: mafetter: this assumes ed == current, so why pass ed?
static inline void __shadow_get_l2e(
    struct exec_domain *ed, unsigned long va, unsigned long *sl2e)
{
    if ( likely(shadow_mode_enabled(ed->domain)) ) {
        if ( shadow_mode_translate(ed->domain) )
            *sl2e = l2_pgentry_val(
                ed->arch.shadow_vtable[l2_table_offset(va)]);       
        else 
            *sl2e = l2_pgentry_val(
                shadow_linear_l2_table[l2_table_offset(va)]);
    }
    else
        BUG();
}

static inline void __shadow_set_l2e(
    struct exec_domain *ed, unsigned long va, unsigned long value)
{
    if ( likely(shadow_mode_enabled(ed->domain)) ) {
        if ( shadow_mode_translate(ed->domain) ) 
            ed->arch.shadow_vtable[l2_table_offset(va)] = mk_l2_pgentry(value);
        else 
            shadow_linear_l2_table[l2_table_offset(va)] = mk_l2_pgentry(value);
    }
    else
        BUG();
}

static inline void __guest_get_l2e(
    struct exec_domain *ed, unsigned long va, unsigned long *l2e)
{
    *l2e = ( shadow_mode_translate(ed->domain) ) ?
        l2_pgentry_val(ed->arch.guest_vtable[l2_table_offset(va)]) :
        l2_pgentry_val(linear_l2_table[l2_table_offset(va)]);
}

static inline void __guest_set_l2e(
    struct exec_domain *ed, unsigned long va, unsigned long value)
{
    if ( shadow_mode_translate(ed->domain) )
    {
        unsigned long pfn;

        pfn = phys_to_machine_mapping(value >> PAGE_SHIFT);
        ed->arch.hl2_vtable[l2_table_offset(va)] =
            mk_l2_pgentry((pfn << PAGE_SHIFT) | __PAGE_HYPERVISOR);

        ed->arch.guest_vtable[l2_table_offset(va)] = mk_l2_pgentry(value);
    }
    else
    {
        linear_l2_table[l2_table_offset(va)] = mk_l2_pgentry(value);
    }
}

/************************************************************************/

static inline int __mark_dirty(struct domain *d, unsigned int mfn)
{
    unsigned long pfn;
    int           rc = 0;

    ASSERT(spin_is_locked(&d->arch.shadow_lock));
    ASSERT(d->arch.shadow_dirty_bitmap != NULL);

    pfn = machine_to_phys_mapping[mfn];

    /*
     * Values with the MSB set denote MFNs that aren't really part of the 
     * domain's pseudo-physical memory map (e.g., the shared info frame).
     * Nothing to do here...
     */
    if ( unlikely(IS_INVALID_M2P_ENTRY(pfn)) )
        return rc;

    if ( likely(pfn < d->arch.shadow_dirty_bitmap_size) )
    {
        /* N.B. Can use non-atomic TAS because protected by shadow_lock. */
        if ( !__test_and_set_bit(pfn, d->arch.shadow_dirty_bitmap) )
        {
            d->arch.shadow_dirty_count++;
            rc = 1;
        }
    }
#ifndef NDEBUG
    else if ( mfn < max_page )
    {
        SH_LOG("mark_dirty OOR! mfn=%x pfn=%lx max=%x (dom %p)",
               mfn, pfn, d->arch.shadow_dirty_bitmap_size, d);
        SH_LOG("dom=%p caf=%08x taf=%08x\n", 
               page_get_owner(&frame_table[mfn]),
               frame_table[mfn].count_info, 
               frame_table[mfn].u.inuse.type_info );
    }
#endif

    return rc;
}


static inline int mark_dirty(struct domain *d, unsigned int mfn)
{
    int rc;
    shadow_lock(d);
    rc = __mark_dirty(d, mfn);
    shadow_unlock(d);
    return rc;
}


/************************************************************************/

static inline void l1pte_write_fault(
    struct domain *d, unsigned long *gpte_p, unsigned long *spte_p)
{ 
    unsigned long gpte = *gpte_p;
    unsigned long spte = *spte_p;
    unsigned long pfn = gpte >> PAGE_SHIFT;
    unsigned long mfn = __gpfn_to_mfn(d, pfn);

    ASSERT(gpte & _PAGE_RW);
    gpte |= _PAGE_DIRTY | _PAGE_ACCESSED;

    if ( shadow_mode_log_dirty(d) )
        __mark_dirty(d, pfn);

    spte = (mfn << PAGE_SHIFT) | (gpte & ~PAGE_MASK);

    SH_VVLOG("l1pte_write_fault: updating spte=0x%p gpte=0x%p", spte, gpte);
    *gpte_p = gpte;
    *spte_p = spte;
}

static inline void l1pte_read_fault(
    struct domain *d, unsigned long *gpte_p, unsigned long *spte_p)
{ 
    unsigned long gpte = *gpte_p;
    unsigned long spte = *spte_p;
    unsigned long pfn = gpte >> PAGE_SHIFT;
    unsigned long mfn = __gpfn_to_mfn(d, pfn);

    gpte |= _PAGE_ACCESSED;
    spte = (mfn << PAGE_SHIFT) | (gpte & ~PAGE_MASK);

    if ( shadow_mode_log_dirty(d) || !(gpte & _PAGE_DIRTY) )
        spte &= ~_PAGE_RW;

    SH_VVLOG("l1pte_read_fault: updating spte=0x%p gpte=0x%p", spte, gpte);
    *gpte_p = gpte;
    *spte_p = spte;
}

static inline void l1pte_propagate_from_guest(
    struct domain *d, unsigned long *gpte_p, unsigned long *spte_p)
{ 
    unsigned long gpte = *gpte_p;
    unsigned long spte = *spte_p;
    unsigned long pfn = gpte >> PAGE_SHIFT;
    unsigned long mfn = __gpfn_to_mfn(d, pfn);

#if SHADOW_VERBOSE_DEBUG
    unsigned long old_spte = spte;
#endif

    if ( shadow_mode_external(d) && mmio_space(gpte & 0xFFFFF000) ) {
        *spte_p = 0;
        return;
    }
    
    spte = 0;
    if ( (gpte & (_PAGE_PRESENT|_PAGE_ACCESSED) ) == 
         (_PAGE_PRESENT|_PAGE_ACCESSED) ) {
        
        spte = (mfn << PAGE_SHIFT) | (gpte & ~PAGE_MASK);
        
        if ( shadow_mode_log_dirty(d) || !(gpte & _PAGE_DIRTY) )
            spte &= ~_PAGE_RW;
    }
        
#if SHADOW_VERBOSE_DEBUG
    if ( old_spte || spte || gpte )
        SH_VVLOG("l1pte_propagate_from_guest: gpte=0x%p, old spte=0x%p, new spte=0x%p ", gpte, old_spte, spte);
#endif

    *gpte_p = gpte;
    *spte_p = spte;
}



static inline void l2pde_general(
    struct domain *d,
    unsigned long *gpde_p,
    unsigned long *spde_p,
    unsigned long sl1mfn)
{
    unsigned long gpde = *gpde_p;
    unsigned long spde = *spde_p;

    spde = 0;

    if ( sl1mfn != 0 )
    {
        spde = (gpde & ~PAGE_MASK) | (sl1mfn << PAGE_SHIFT) | 
            _PAGE_RW | _PAGE_ACCESSED | _PAGE_DIRTY;
        gpde |= _PAGE_ACCESSED; /* N.B. PDEs do not have a dirty bit. */

        /* Detect linear p.t. mappings and write-protect them. */
        if ( (frame_table[sl1mfn].u.inuse.type_info & PGT_type_mask) ==
             PGT_l2_page_table ) 
        {
            if ( !shadow_mode_translate(d) )
                spde = gpde & ~_PAGE_RW;

        }
    }

    *gpde_p = gpde;
    *spde_p = spde;
}

/*********************************************************************/

#if SHADOW_HASH_DEBUG
static void shadow_audit(struct domain *d, int print)
{
    int live = 0, free = 0, j = 0, abs;
    struct shadow_status *a;

    for ( j = 0; j < shadow_ht_buckets; j++ )
    {
        a = &d->arch.shadow_ht[j];        
        if ( a->pfn ) { live++; ASSERT(a->smfn_and_flags & PSH_pfn_mask); }
        ASSERT(a->pfn < 0x00100000UL);
        a = a->next;
        while ( a && (live < 9999) )
        { 
            live++; 
            if ( (a->pfn == 0) || (a->smfn_and_flags == 0) )
            {
                printk("XXX live=%d pfn=%p sp=%p next=%p\n",
                       live, a->pfn, a->smfn_and_flags, a->next);
                BUG();
            }
            ASSERT(a->pfn < 0x00100000UL);
            ASSERT(a->smfn_and_flags & PSH_pfn_mask);
            a = a->next; 
        }
        ASSERT(live < 9999);
    }

    for ( a = d->arch.shadow_ht_free; a != NULL; a = a->next )
        free++; 

    if ( print)
        printk("Xlive=%d free=%d\n",live,free);

    abs = (perfc_value(shadow_l1_pages) + perfc_value(shadow_l2_pages)) - live;
#ifdef PERF_COUNTERS
    if ( (abs < -1) || (abs > 1) )
    {
        printk("live=%d free=%d l1=%d l2=%d\n",live,free,
               perfc_value(shadow_l1_pages), perfc_value(shadow_l2_pages) );
        BUG();
    }
#endif
}
#else
#define shadow_audit(p, print) ((void)0)
#endif


static inline struct shadow_status *hash_bucket(
    struct domain *d, unsigned int gpfn)
{
    return &d->arch.shadow_ht[gpfn % shadow_ht_buckets];
}


/*
 * N.B. This takes a guest pfn (i.e. a pfn in the guest's namespace,
 *      which, depending on full shadow mode, may or may not equal
 *      its mfn).
 *      The shadow status it returns is a mfn.
 */
static inline unsigned long __shadow_status(
    struct domain *d, unsigned int gpfn)
{
    struct shadow_status *p, *x, *head;

    x = head = hash_bucket(d, gpfn);
    p = NULL;

    //SH_VVLOG("lookup gpfn=%08x bucket=%p", gpfn, x);
    shadow_audit(d, 0);

    do
    {
        ASSERT(x->pfn || ((x == head) && (x->next == NULL)));

        if ( x->pfn == gpfn )
        {
#if SHADOW_DEBUG
            if ( unlikely(shadow_status_noswap) )
                return x->smfn_and_flags;
#endif
            /* Pull-to-front if 'x' isn't already the head item. */
            if ( unlikely(x != head) )
            {
                /* Delete 'x' from list and reinsert immediately after head. */
                p->next = x->next;
                x->next = head->next;
                head->next = x;

                /* Swap 'x' contents with head contents. */
                SWAP(head->pfn, x->pfn);
                SWAP(head->smfn_and_flags, x->smfn_and_flags);
            }

            SH_VVLOG("lookup gpfn=%p => status=%p",
                     gpfn, head->smfn_and_flags);
            return head->smfn_and_flags;
        }

        p = x;
        x = x->next;
    }
    while ( x != NULL );

    SH_VVLOG("lookup gpfn=%p => status=0", gpfn);
    return 0;
}

/*
 * N.B. We can make this locking more fine grained (e.g., per shadow page) if
 * it ever becomes a problem, but since we need a spin lock on the hash table 
 * anyway it's probably not worth being too clever.
 */
static inline unsigned long get_shadow_status(
    struct domain *d, unsigned int gpfn )
{
    unsigned long res;

    ASSERT(shadow_mode_enabled(d));

    /*
     * If we get here we know that some sort of update has happened to the
     * underlying page table page: either a PTE has been updated, or the page
     * has changed type. If we're in log dirty mode, we should set the
     * appropriate bit in the dirty bitmap.
     * N.B. The VA update path doesn't use this and is handled independently. 

     XXX need to think this through for vmx guests, but probably OK
     */

    shadow_lock(d);

    if ( shadow_mode_log_dirty(d) )
        __mark_dirty(d, gpfn);

    if ( !(res = __shadow_status(d, gpfn)) )
        shadow_unlock(d);

    return res;
}


static inline void put_shadow_status(
    struct domain *d)
{
    shadow_unlock(d);
}


static inline void delete_shadow_status( 
    struct domain *d, unsigned int gpfn)
{
    struct shadow_status *p, *x, *n, *head;

    ASSERT(spin_is_locked(&d->arch.shadow_lock));
    ASSERT(gpfn != 0);

    head = hash_bucket(d, gpfn);

    SH_VVLOG("delete gpfn=%08x bucket=%p", gpfn, head);
    shadow_audit(d, 0);

    /* Match on head item? */
    if ( head->pfn == gpfn )
    {
        if ( (n = head->next) != NULL )
        {
            /* Overwrite head with contents of following node. */
            head->pfn            = n->pfn;
            head->smfn_and_flags = n->smfn_and_flags;

            /* Delete following node. */
            head->next           = n->next;

            /* Add deleted node to the free list. */
            n->pfn            = 0;
            n->smfn_and_flags = 0;
            n->next           = d->arch.shadow_ht_free;
            d->arch.shadow_ht_free = n;
        }
        else
        {
            /* This bucket is now empty. Initialise the head node. */
            head->pfn            = 0;
            head->smfn_and_flags = 0;
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
            x->smfn_and_flags = 0;
            x->next           = d->arch.shadow_ht_free;
            d->arch.shadow_ht_free = x;

            goto found;
        }

        p = x;
        x = x->next;
    }
    while ( x != NULL );

    /* If we got here, it wasn't in the list! */
    BUG();

 found:
    shadow_audit(d, 0);
}


static inline void set_shadow_status(
    struct domain *d, unsigned int gpfn, unsigned long s)
{
    struct shadow_status *x, *head, *extra;
    int i;

    ASSERT(spin_is_locked(&d->arch.shadow_lock));
    ASSERT(gpfn != 0);
    ASSERT(s & PSH_shadowed);

    x = head = hash_bucket(d, gpfn);
   
    SH_VVLOG("set gpfn=%08x s=%p bucket=%p(%p)", gpfn, s, x, x->next);
    shadow_audit(d, 0);

    /*
     * STEP 1. If page is already in the table, update it in place.
     */

    do
    {
        if ( x->pfn == gpfn )
        {
            x->smfn_and_flags = s;
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
        head->smfn_and_flags = s;
        ASSERT(head->next == NULL);
        goto done;
    }

    /* We need to allocate a new node. Ensure the quicklist is non-empty. */
    if ( unlikely(d->arch.shadow_ht_free == NULL) )
    {
        SH_LOG("Allocate more shadow hashtable blocks.");

        extra = xmalloc_bytes(
            sizeof(void *) + (shadow_ht_extra_size * sizeof(*x)));

        /* XXX Should be more graceful here. */
        if ( extra == NULL )
            BUG();

        memset(extra, 0, sizeof(void *) + (shadow_ht_extra_size * sizeof(*x)));

        /* Record the allocation block so it can be correctly freed later. */
        d->arch.shadow_extras_count++;
        *((struct shadow_status **)&extra[shadow_ht_extra_size]) = 
            d->arch.shadow_ht_extras;
        d->arch.shadow_ht_extras = &extra[0];

        /* Thread a free chain through the newly-allocated nodes. */
        for ( i = 0; i < (shadow_ht_extra_size - 1); i++ )
            extra[i].next = &extra[i+1];
        extra[i].next = NULL;

        /* Add the new nodes to the free list. */
        d->arch.shadow_ht_free = &extra[0];
    }

    /* Allocate a new node from the quicklist. */
    x                      = d->arch.shadow_ht_free;
    d->arch.shadow_ht_free = x->next;

    /* Initialise the new node and insert directly after the head item. */
    x->pfn            = gpfn;
    x->smfn_and_flags = s;
    x->next           = head->next;
    head->next        = x;

 done:
    shadow_audit(d, 0);
}
  
#ifdef CONFIG_VMX

static inline void vmx_update_shadow_state(
    struct exec_domain *ed, unsigned long gpfn, unsigned long smfn)
{

    l2_pgentry_t *mpl2e = 0;
    l2_pgentry_t *gpl2e, *spl2e;

    /* unmap the old mappings */
    if ( ed->arch.shadow_vtable )
        unmap_domain_mem(ed->arch.shadow_vtable);
    if ( ed->arch.guest_vtable )
        unmap_domain_mem(ed->arch.guest_vtable);

    /* new mapping */
    mpl2e = (l2_pgentry_t *)
        map_domain_mem(pagetable_val(ed->arch.monitor_table));

    // mafetter: why do we need to keep setting up shadow_linear_pg_table for
    // this monitor page table?  Seems unnecessary...
    //
    mpl2e[l2_table_offset(SH_LINEAR_PT_VIRT_START)] =
        mk_l2_pgentry((smfn << PAGE_SHIFT) | __PAGE_HYPERVISOR);
    __flush_tlb_one(SH_LINEAR_PT_VIRT_START);

    spl2e = (l2_pgentry_t *)map_domain_mem(smfn << PAGE_SHIFT);
    gpl2e = (l2_pgentry_t *)map_domain_mem(gpfn << PAGE_SHIFT);
    memset(spl2e, 0, L2_PAGETABLE_ENTRIES * sizeof(l2_pgentry_t));

    ed->arch.shadow_vtable = spl2e;
    ed->arch.guest_vtable = gpl2e; /* expect the guest did clean this up */
    unmap_domain_mem(mpl2e);
}

static inline unsigned long gva_to_gpte(unsigned long gva)
{
    unsigned long gpde, gpte, pfn, index;
    struct exec_domain *ed = current;

    __guest_get_l2e(ed, gva, &gpde);
    if (!(gpde & _PAGE_PRESENT))
        return 0;

    index = (gva >> L2_PAGETABLE_SHIFT);

    if (!l2_pgentry_val(ed->arch.hl2_vtable[index])) {
        pfn = phys_to_machine_mapping(gpde >> PAGE_SHIFT);
        ed->arch.hl2_vtable[index] = 
            mk_l2_pgentry((pfn << PAGE_SHIFT) | __PAGE_HYPERVISOR);
    }

    if ( unlikely(__get_user(gpte, (unsigned long *)
                             &linear_pg_table[gva >> PAGE_SHIFT])) )
        return 0;

    return gpte;
}

static inline unsigned long gva_to_gpa(unsigned long gva)
{
    unsigned long gpte;

    gpte = gva_to_gpte(gva);
    if ( !(gpte & _PAGE_PRESENT) )
        return 0;

    return (gpte & PAGE_MASK) + (gva & ~PAGE_MASK); 
}

#endif /* CONFIG_VMX */

static inline void __update_pagetables(struct exec_domain *ed)
{
    struct domain *d = ed->domain;
    unsigned long gpfn = pagetable_val(ed->arch.guest_table) >> PAGE_SHIFT;
    unsigned long smfn = __shadow_status(d, gpfn) & PSH_pfn_mask;

    SH_VVLOG("0: __update_pagetables(gpfn=%p, smfn=%p)", gpfn, smfn);

    if ( unlikely(smfn == 0) )
        smfn = shadow_l2_table(d, gpfn);
#ifdef CONFIG_VMX
    else if ( shadow_mode_translate(ed->domain) )
        vmx_update_shadow_state(ed, gpfn, smfn);
#endif

    ed->arch.shadow_table = mk_pagetable(smfn<<PAGE_SHIFT);

    if ( !shadow_mode_external(ed->domain) )
        // mafetter: why do we need to keep overwriting
        // ed->arch.monitor_table?  Seems unnecessary...
        //
        ed->arch.monitor_table = ed->arch.shadow_table;
}

static inline void update_pagetables(struct exec_domain *ed)
{
     if ( unlikely(shadow_mode_enabled(ed->domain)) )
     {
         shadow_lock(ed->domain);
         __update_pagetables(ed);
         shadow_unlock(ed->domain);
     }
#ifdef __x86_64__
     else if ( !(ed->arch.flags & TF_kernel_mode) )
         // mafetter: why do we need to keep overwriting
         // ed->arch.monitor_table?  Seems unnecessary...
         //
         ed->arch.monitor_table = ed->arch.guest_table_user;
#endif
     else
         // mafetter: why do we need to keep overwriting
         // ed->arch.monitor_table?  Seems unnecessary...
         //
         ed->arch.monitor_table = ed->arch.guest_table;
}

#if SHADOW_DEBUG
extern int _check_pagetable(struct domain *d, pagetable_t pt, char *s);
extern int _check_all_pagetables(struct domain *d, char *s);

#define check_pagetable(_d, _pt, _s) _check_pagetable(_d, _pt, _s)
//#define check_pagetable(_d, _pt, _s) _check_all_pagetables(_d, _s)

#else
#define check_pagetable(_d, _pt, _s) ((void)0)
#endif

#endif /* XEN_SHADOW_H */
