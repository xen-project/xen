/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */

#ifndef _XEN_SHADOW_H
#define _XEN_SHADOW_H

#include <xen/config.h>
#include <xen/types.h>
#include <xen/perfc.h>
#include <asm/processor.h>


/* Shadow PT flag bits in pfn_info */
#define PSH_shadowed    (1<<31) /* page has a shadow. PFN points to shadow */
#define PSH_pending     (1<<29) /* page is in the process of being shadowed */
#define PSH_pfn_mask    ((1<<21)-1)

/* Shadow PT operation mode : shadowmode variable in mm_struct */
#define SHM_test        (1) /* just run domain on shadow PTs */
#define SHM_logdirty    (2) /* log pages that are dirtied */
#define SHM_translate   (3) /* lookup machine pages in translation table */
//#define SHM_cow       (4) /* copy on write all dirtied pages */


#define shadow_linear_pg_table ((l1_pgentry_t *)SH_LINEAR_PT_VIRT_START)
#define shadow_linear_l2_table ((l2_pgentry_t *)(SH_LINEAR_PT_VIRT_START+(SH_LINEAR_PT_VIRT_START>>(L2_PAGETABLE_SHIFT-L1_PAGETABLE_SHIFT))))

#define shadow_mode(_d)      ((_d)->mm.shadow_mode)
#define shadow_lock_init(_d) spin_lock_init(&(_d)->mm.shadow_lock)
#define shadow_lock(_m)      spin_lock_nochecking(&(_m)->shadow_lock)
#define shadow_unlock(_m)    spin_unlock_nochecking(&(_m)->shadow_lock)

extern void shadow_mode_init(void);
extern int shadow_mode_control(struct domain *p, dom0_shadow_control_t *sc);
extern int shadow_fault(unsigned long va, long error_code);
extern void shadow_l1_normal_pt_update(unsigned long pa, unsigned long gpte, 
                                       unsigned long *prev_spfn_ptr,
                                       l1_pgentry_t **prev_spl1e_ptr);
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
    struct mm_struct *m, unsigned long gpfn );

#define SHADOW_DEBUG 0
#define SHADOW_HASH_DEBUG 0
#define SHADOW_OPTIMISE 1

struct shadow_status {
    unsigned long pfn;            // gpfn 
    unsigned long spfn_and_flags; // spfn plus flags
    struct shadow_status *next;   // use pull-to-front list.
};

#define shadow_ht_extra_size         128 /*128*/
#define shadow_ht_buckets            256 /*256*/

#ifdef VERBOSE
#define SH_LOG(_f, _a...)                             \
printk("DOM%u: (file=shadow.c, line=%d) " _f "\n",    \
       current->domain , __LINE__ , ## _a )
#else
#define SH_LOG(_f, _a...) 
#endif

#if SHADOW_DEBUG
#define SH_VLOG(_f, _a...)                             \
    printk("DOM%u: (file=shadow.c, line=%d) " _f "\n", \
           current->domain , __LINE__ , ## _a )
#else
#define SH_VLOG(_f, _a...) 
#endif

#if 0
#define SH_VVLOG(_f, _a...)                             \
    printk("DOM%u: (file=shadow.c, line=%d) " _f "\n",  \
           current->domain , __LINE__ , ## _a )
#else
#define SH_VVLOG(_f, _a...) 
#endif


/************************************************************************/

static inline int __mark_dirty( struct mm_struct *m, unsigned int mfn )
{
    unsigned int pfn;
    int rc = 0;

    ASSERT(spin_is_locked(&m->shadow_lock));

    pfn = machine_to_phys_mapping[mfn];

    /* We use values with the top bit set to mark MFNs that aren't
       really part of the domain's psuedo-physical memory map e.g.
       the shared info frame. Nothing to do here...
    */
    if ( unlikely(pfn & 0x80000000U) ) return rc; 

    ASSERT(m->shadow_dirty_bitmap);
    if( likely(pfn<m->shadow_dirty_bitmap_size) )
    {
        /* These updates occur with mm.shadow_lock held, so use 
           (__) version of test_and_set */
        if ( __test_and_set_bit( pfn, m->shadow_dirty_bitmap ) == 0 )
        {
            // if we set it
            m->shadow_dirty_count++;
            rc = 1;
        }
    }
    else
    {
		if ( mfn < max_page )
		{
			SH_LOG("mark_dirty OOR! mfn=%x pfn=%x max=%x (mm %p)",
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
    }

    return rc;
}


static inline int mark_dirty( struct mm_struct *m, unsigned int mfn )
{
    int rc;
    //ASSERT(local_irq_is_enabled());
    //if(spin_is_locked(&m->shadow_lock)) printk("+");
    shadow_lock(m);
    rc = __mark_dirty( m, mfn );
    shadow_unlock(m);
    return rc;
}


/************************************************************************/

static inline void l1pte_write_fault(
    struct mm_struct *m, unsigned long *gpte_p, unsigned long *spte_p)
{ 
    unsigned long gpte = *gpte_p;
    unsigned long spte = *spte_p;

    switch ( m->shadow_mode )
    {
    case SHM_test:
        spte = gpte;
        gpte |= _PAGE_DIRTY | _PAGE_ACCESSED;
        spte |= _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED;
        break;

    case SHM_logdirty:
        spte = gpte;
        gpte |= _PAGE_DIRTY | _PAGE_ACCESSED;
        spte |= _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED;
        __mark_dirty( m, (gpte >> PAGE_SHIFT) );
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

    switch ( m->shadow_mode )
    {
    case SHM_test:
        spte = gpte;
        gpte |= _PAGE_ACCESSED;
        spte |= _PAGE_ACCESSED;
        if ( ! (gpte & _PAGE_DIRTY ) )
            spte &= ~ _PAGE_RW;
        break;

    case SHM_logdirty:
        spte = gpte;
        gpte |= _PAGE_ACCESSED;
        spte |= _PAGE_ACCESSED;
        spte &= ~ _PAGE_RW;
        break;
    }

    *gpte_p = gpte;
    *spte_p = spte;
}

static inline void l1pte_no_fault(
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
        {
            spte = gpte;
            if ( ! (gpte & _PAGE_DIRTY ) )
                spte &= ~ _PAGE_RW;
        }
        break;

    case SHM_logdirty:
        spte = 0;
        if ( (gpte & (_PAGE_PRESENT|_PAGE_ACCESSED) ) == 
             (_PAGE_PRESENT|_PAGE_ACCESSED) )
        {
            spte = gpte;
            spte &= ~ _PAGE_RW;
        }

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

    if ( sl1pfn )
    {
        spde = (gpde & ~PAGE_MASK) | (sl1pfn<<PAGE_SHIFT) | 
            _PAGE_RW | _PAGE_ACCESSED | _PAGE_DIRTY;
        gpde = gpde | _PAGE_ACCESSED | _PAGE_DIRTY;

        if ( unlikely( (sl1pfn<<PAGE_SHIFT) == (gpde & PAGE_MASK)  ) )
        {   
            // detect linear map, and keep pointing at guest
            SH_VLOG("4c: linear mapping ( %08lx )",sl1pfn);
            spde = gpde & ~_PAGE_RW;
        }
    }

    *gpde_p = gpde;
    *spde_p = spde;
}

/*********************************************************************/

#if SHADOW_HASH_DEBUG
static void shadow_audit(struct mm_struct *m, int print)
{
    int live=0, free=0, j=0, abs;
    struct shadow_status *a;

    for( j = 0; j < shadow_ht_buckets; j++ )
    {
        a = &m->shadow_ht[j];        
        if(a->pfn){live++; ASSERT(a->spfn_and_flags&PSH_pfn_mask);}
        ASSERT((a->pfn&0xf0000000)==0);
        ASSERT(a->pfn<0x00100000);
        a=a->next;
        while(a && live<9999)
        { 
            live++; 
            if(a->pfn == 0 || a->spfn_and_flags == 0)
            {
                printk("XXX live=%d pfn=%08lx sp=%08lx next=%p\n",
                       live, a->pfn, a->spfn_and_flags, a->next);
                BUG();
            }
            ASSERT(a->pfn);
            ASSERT((a->pfn&0xf0000000)==0);
            ASSERT(a->pfn<0x00100000);
            ASSERT(a->spfn_and_flags&PSH_pfn_mask);
            a=a->next; 
        }
        ASSERT(live<9999);
    }

    a = m->shadow_ht_free;
    while(a) { free++; a=a->next; }

    if(print) printk("Xlive=%d free=%d\n",live,free);

    abs=(perfc_value(shadow_l1_pages)+perfc_value(shadow_l2_pages))-live;
    if( abs < -1 || abs > 1 )
    {
        printk("live=%d free=%d l1=%d l2=%d\n",live,free,
               perfc_value(shadow_l1_pages), perfc_value(shadow_l2_pages) );
        BUG();
    }

}

#else
#define shadow_audit(p, print)
#endif



static inline struct shadow_status* hash_bucket( struct mm_struct *m,
                                                 unsigned int gpfn )
{
    return &(m->shadow_ht[gpfn % shadow_ht_buckets]);
}


static inline unsigned long __shadow_status( struct mm_struct *m,
                                             unsigned int gpfn )
{
    struct shadow_status **ob, *b, *B = hash_bucket( m, gpfn );

    b = B;
    ob = NULL;

    SH_VVLOG("lookup gpfn=%08x bucket=%p", gpfn, b );
    shadow_audit(m,0);  // if in debug mode

    do
    {
        if ( b->pfn == gpfn )
        {
            unsigned long t;
            struct shadow_status *x;

            // swap with head
            t=B->pfn; B->pfn=b->pfn; b->pfn=t;
            t=B->spfn_and_flags; B->spfn_and_flags=b->spfn_and_flags; 
            b->spfn_and_flags=t;

            if( ob )
            {   // pull to front
                *ob=b->next;
                x=B->next;
                B->next=b;
                b->next=x;
            }
            return B->spfn_and_flags;
        }
#if SHADOW_HASH_DEBUG
        else
        {
            if(b!=B)ASSERT(b->pfn);
        }
#endif
        ob=&b->next;
        b=b->next;
    }
    while (b);

    return 0;
}

/* we can make this locking more fine grained e.g. per shadow page if it 
ever becomes a problem, but since we need a spin lock on the hash table 
anyway its probably not worth being too clever. */

static inline unsigned long get_shadow_status( struct mm_struct *m,
                                               unsigned int gpfn )
{
    unsigned long res;

    /* If we get here, we know that this domain is running in shadow mode. 
       We also know that some sort of update has happened to the underlying
       page table page: either a PTE has been updated, or the page has
       changed type. If we're in log dirty mode, we should set the approrpiate
       bit in the dirty bitmap.
       NB: the VA update path doesn't use this so needs to be handled 
       independnetly. 
    */

    //ASSERT(local_irq_is_enabled());
    //if(spin_is_locked(&m->shadow_lock)) printk("*");
    shadow_lock(m);

    if( m->shadow_mode == SHM_logdirty )
        __mark_dirty( m, gpfn );

    res = __shadow_status( m, gpfn );
    if (!res) 
        shadow_unlock(m);
    return res;
}


static inline void put_shadow_status( struct mm_struct *m )
{
    shadow_unlock(m);
}


static inline void delete_shadow_status( struct mm_struct *m,
                                         unsigned int gpfn )
{
    struct shadow_status *b, *B, **ob;

    ASSERT(spin_is_locked(&m->shadow_lock));

    B = b = hash_bucket( m, gpfn );

    SH_VVLOG("delete gpfn=%08x bucket=%p", gpfn, b );
    shadow_audit(m,0);
    ASSERT(gpfn);

    if( b->pfn == gpfn )
    {
        if (b->next)
        {
            struct shadow_status *D=b->next;
            b->spfn_and_flags = b->next->spfn_and_flags;
            b->pfn = b->next->pfn;

            b->next = b->next->next;
            D->next = m->shadow_ht_free;
            D->pfn = 0;
            D->spfn_and_flags = 0;
            m->shadow_ht_free = D;
        }
        else
        {
            b->pfn = 0;
            b->spfn_and_flags = 0;
        }

#if SHADOW_HASH_DEBUG
        if( __shadow_status(m,gpfn) ) BUG();  
        shadow_audit(m,0);
#endif
        return;
    }

    ob = &b->next;
    b=b->next;

    do
    {
        if ( b->pfn == gpfn )
        {
            b->pfn = 0;
            b->spfn_and_flags = 0;

            // b is in the list
            *ob=b->next;
            b->next = m->shadow_ht_free;
            m->shadow_ht_free = b;

#if SHADOW_HASH_DEBUG
            if( __shadow_status(m,gpfn) ) BUG();
#endif
            shadow_audit(m,0);
            return;
        }

        ob = &b->next;
        b=b->next;
    }
    while (b);

    // if we got here, it wasn't in the list
    BUG();
}


static inline void set_shadow_status( struct mm_struct *m,
                                      unsigned int gpfn, unsigned long s )
{
    struct shadow_status *b, *B, *extra, **fptr;
    int i;

    ASSERT(spin_is_locked(&m->shadow_lock));

    B = b = hash_bucket( m, gpfn );
   
    ASSERT(gpfn);
    SH_VVLOG("set gpfn=%08x s=%08lx bucket=%p(%p)", gpfn, s, b, b->next );

    shadow_audit(m,0);

    do
    {
        if ( b->pfn == gpfn )
        {
            b->spfn_and_flags = s;
            shadow_audit(m,0);
            return;
        }

        b=b->next;
    }
    while (b);

    // if we got here, this is an insert rather than update

    ASSERT( s );  // deletes must have succeeded by here

    if ( B->pfn == 0 )
    {
        // we can use this head
        ASSERT( B->next == 0 );
        B->pfn = gpfn;
        B->spfn_and_flags = s;
        shadow_audit(m,0);
        return;
    }

    if( unlikely(m->shadow_ht_free == NULL) )
    {
        SH_LOG("allocate more shadow hashtable blocks");

        // we need to allocate more space
        extra = xmalloc(sizeof(void*) + (shadow_ht_extra_size * 
                                         sizeof(struct shadow_status)));

        if( ! extra ) BUG(); // should be more graceful here....

        memset(extra, 0, sizeof(void*) + (shadow_ht_extra_size * 
                                          sizeof(struct shadow_status)));

        m->shadow_extras_count++;

        // add extras to free list
        fptr = &m->shadow_ht_free;
        for ( i=0; i<shadow_ht_extra_size; i++ )
        {
            *fptr = &extra[i];
            fptr = &(extra[i].next);
        }
        *fptr = NULL;

        *((struct shadow_status ** ) &extra[shadow_ht_extra_size]) = 
            m->shadow_ht_extras;
        m->shadow_ht_extras = extra;

    }

    // should really put this in B to go right to front
    b = m->shadow_ht_free;
    m->shadow_ht_free = b->next;
    b->spfn_and_flags = s;
    b->pfn = gpfn;
    b->next = B->next;
    B->next = b;

    shadow_audit(m,0);

    return;
}

static inline void __shadow_mk_pagetable( struct mm_struct *mm )
{
    unsigned long gpfn, spfn=0;

    gpfn =  pagetable_val(mm->pagetable) >> PAGE_SHIFT;

    if ( unlikely((spfn=__shadow_status(mm, gpfn)) == 0 ) )
    {
        spfn = shadow_l2_table(mm, gpfn );
    }      
    mm->shadow_table = mk_pagetable(spfn<<PAGE_SHIFT);
}

static inline void shadow_mk_pagetable( struct mm_struct *mm )
{
    SH_VVLOG("shadow_mk_pagetable( gptbase=%08lx, mode=%d )",
             pagetable_val(mm->pagetable), mm->shadow_mode );

    if ( unlikely(mm->shadow_mode) )
    {
        //ASSERT(local_irq_is_enabled());
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


