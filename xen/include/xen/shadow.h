/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*- */

#ifndef _XENO_SHADOW_H
#define _XENO_SHADOW_H

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/perfc.h>

/* Shadow PT flag bits in pfn_info */
#define PSH_shadowed	(1<<31) /* page has a shadow. PFN points to shadow */
#define PSH_pending	    (1<<29) /* page is in the process of being shadowed */
#define PSH_pfn_mask	((1<<21)-1)

/* Shadow PT operation mode : shadowmode variable in mm_struct */
#define SHM_test        (1<<0) /* just run domain on shadow PTs */
#define SHM_logdirty    (1<<1) /* log pages that are dirtied */
#define SHM_cow         (1<<2) /* copy on write all dirtied pages */
#define SHM_translate   (1<<3) /* lookup machine pages in translation table */

#define shadow_linear_pg_table ((l1_pgentry_t *)SH_LINEAR_PT_VIRT_START)
#define shadow_linear_l2_table ((l2_pgentry_t *)(SH_LINEAR_PT_VIRT_START+(SH_LINEAR_PT_VIRT_START>>(L2_PAGETABLE_SHIFT-L1_PAGETABLE_SHIFT))))

extern int shadow_mode_control( struct task_struct *p, unsigned int op );
extern pagetable_t shadow_mk_pagetable( struct task_struct *p, 
										unsigned long gptbase);
extern int shadow_fault( unsigned long va, long error_code );
extern void shadow_l1_normal_pt_update( unsigned long pa, unsigned long gpte, 
										unsigned long *prev_spfn_ptr,
										l1_pgentry_t **prev_spl1e_ptr  );
extern void shadow_l2_normal_pt_update( unsigned long pa, unsigned long gpte );
extern void unshadow_table( unsigned long gpfn, unsigned int type );
extern int shadow_mode_enable( struct task_struct *p, unsigned int mode );

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

#ifndef NDEBUG
#define SH_LOG(_f, _a...)                             \
  printk("DOM%llu: (file=shadow.c, line=%d) " _f "\n", \
         current->domain , __LINE__ , ## _a )
#else
#define SH_LOG(_f, _a...) 
#endif

#if SHADOW_DEBUG
#define SH_VLOG(_f, _a...)                             \
  printk("DOM%llu: (file=shadow.c, line=%d) " _f "\n", \
         current->domain , __LINE__ , ## _a )
#else
#define SH_VLOG(_f, _a...) 
#endif

#if 0
#define SH_VVLOG(_f, _a...)                             \
  printk("DOM%llu: (file=shadow.c, line=%d) " _f "\n", \
         current->domain , __LINE__ , ## _a )
#else
#define SH_VVLOG(_f, _a...) 
#endif



#if SHADOW_HASH_DEBUG
static void shadow_audit(struct task_struct *p, int print)
{
	int live=0, free=0, j=0, abs;
	struct shadow_status *a;
	
    for(j=0;j<shadow_ht_buckets;j++)
    {
        a = &p->mm.shadow_ht[j];        
		if(a->pfn) live++;
        while(a->next && live<9999)
		{ 
			live++; 
			if(a->pfn == 0)
			{
				printk("XXX live=%d pfn=%08lx sp=%08lx next=%p\n",
					   live, a->pfn, a->spfn_and_flags, a->next);
				BUG();
			}
			a=a->next; 
		}
		ASSERT(live<9999);
	}

    a = p->mm.shadow_ht_free;
    while(a) { free++; a=a->next; }

    if(print) printk("live=%d free=%d\n",live,free);

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

static inline struct shadow_status* hash_bucket( struct task_struct *p,
												 unsigned int gpfn )
{
    return &(p->mm.shadow_ht[gpfn % shadow_ht_buckets]);
}


static inline unsigned long __shadow_status( struct task_struct *p,
										   unsigned int gpfn )
{
	struct shadow_status **ob, *b, *B = hash_bucket( p, gpfn );

    b = B;
    ob = NULL;

	SH_VVLOG("lookup gpfn=%08lx bucket=%08lx", gpfn, b );
	shadow_audit(p,0);  // if in debug mode

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

			if(ob)
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

static inline unsigned long get_shadow_status( struct task_struct *p,
										   unsigned int gpfn )
{
	unsigned long res;

	spin_lock(&p->mm.shadow_lock);
	res = __shadow_status( p, gpfn );
	if (!res) spin_unlock(&p->mm.shadow_lock);
	return res;
}


static inline void put_shadow_status( struct task_struct *p )
{
	spin_unlock(&p->mm.shadow_lock);
}


static inline void delete_shadow_status( struct task_struct *p,
									  unsigned int gpfn )
{
	struct shadow_status *b, *B, **ob;

	B = b = hash_bucket( p, gpfn );

	SH_VVLOG("delete gpfn=%08x bucket=%p", gpfn, b );
	shadow_audit(p,0);
	ASSERT(gpfn);

	if( b->pfn == gpfn )
    {
		if (b->next)
		{
			struct shadow_status *D=b->next;
			b->spfn_and_flags = b->next->spfn_and_flags;
			b->pfn = b->next->pfn;

			b->next = b->next->next;
			D->next = p->mm.shadow_ht_free;
			p->mm.shadow_ht_free = D;
		}
		else
		{
			b->pfn = 0;
			b->spfn_and_flags = 0;
		}

#if SHADOW_HASH_DEBUG
		if( __shadow_status(p,gpfn) ) BUG();  
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
			b->next = p->mm.shadow_ht_free;
			p->mm.shadow_ht_free = b;

#if SHADOW_HASH_DEBUG
			if( __shadow_status(p,gpfn) ) BUG();
#endif
			return;
		}

		ob = &b->next;
		b=b->next;
	}
	while (b);

	// if we got here, it wasn't in the list
    BUG();
}


static inline void set_shadow_status( struct task_struct *p,
									  unsigned int gpfn, unsigned long s )
{
	struct shadow_status *b, *B, *extra, **fptr;
    int i;

	B = b = hash_bucket( p, gpfn );
   
    ASSERT(gpfn);
    ASSERT(s);
    SH_VVLOG("set gpfn=%08x s=%08lx bucket=%p(%p)", gpfn, s, b, b->next );
    shadow_audit(p,0);

	do
	{
		if ( b->pfn == gpfn )			
		{
			b->spfn_and_flags = s;
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
		return;
	}

    if( unlikely(p->mm.shadow_ht_free == NULL) )
    {
        SH_LOG("allocate more shadow hashtable blocks");

        // we need to allocate more space
        extra = kmalloc( sizeof(void*) + (shadow_ht_extra_size * 
							   sizeof(struct shadow_status)), GFP_KERNEL );

	    if( ! extra ) BUG(); // should be more graceful here....

	    memset( extra, 0, sizeof(void*) + (shadow_ht_extra_size * 
							   sizeof(struct shadow_status)) );
	
        // add extras to free list
	    fptr = &p->mm.shadow_ht_free;
	    for ( i=0; i<shadow_ht_extra_size; i++ )
 	    {
		    *fptr = &extra[i];
		    fptr = &(extra[i].next);
	    }
	    *fptr = NULL;

	    *((struct shadow_status ** ) &p->mm.shadow_ht[shadow_ht_extra_size]) = 
                                            p->mm.shadow_ht_extras;
        p->mm.shadow_ht_extras = extra;

    }

	// should really put this in B to go right to front
	b = p->mm.shadow_ht_free;
    p->mm.shadow_ht_free = b->next;
    b->spfn_and_flags = s;
	b->pfn = gpfn;
	b->next = B->next;
	B->next = b;

	return;
}



#if SHADOW_DEBUG
extern int check_pagetable( struct task_struct *p, pagetable_t pt, char *s );
#else
#define check_pagetable( p, pt, s )
#endif


#endif
