/******************************************************************************
 * gnttab.c
 * 
 * Two sets of functionality:
 * 1. Granting foreign access to our memory reservation.
 * 2. Accessing others' memory reservations via grant references.
 * (i.e., mechanisms for both sender and recipient of grant references)
 * 
 * Copyright (c) 2004, K A Fraser
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <asm/pgtable.h>
#include <asm/fixmap.h>
#include <asm-xen/gnttab.h>

#ifndef set_fixmap_ma
#define set_fixmap_ma set_fixmap
#endif

#if 1
#define ASSERT(_p) \
    if ( !(_p) ) { printk(KERN_ALERT"Assertion '%s': line %d, file %s\n", \
    #_p , __LINE__, __FILE__); *(int*)0=0; }
#else
#define ASSERT(_p) ((void)0)
#endif

EXPORT_SYMBOL(gnttab_grant_foreign_access);
EXPORT_SYMBOL(gnttab_end_foreign_access);
EXPORT_SYMBOL(gnttab_grant_foreign_transfer);
EXPORT_SYMBOL(gnttab_end_foreign_transfer);

struct gntent_auxinfo {
    u16         write_pin, read_pin; /* reference counts */
    u16         inuse;
    grant_ref_t next;                /* hash chain       */
};

#define NR_GRANT_REFS 512

static struct gntent_auxinfo auxtab[NR_GRANT_REFS];
static grant_ref_t gnttab_free_head;
static spinlock_t gnttab_lock;

#define HASH_INVALID (0xFFFFU)
#define GNTTAB_HASH_SZ 512
#define GNTTAB_HASH(_f) ((_f) & (GNTTAB_HASH_SZ-1))
static grant_ref_t gnttab_hash[GNTTAB_HASH_SZ];

static grant_entry_t *shared;

/*
 * Lock-free grant-entry allocator
 */

static inline grant_ref_t
get_free_entry(
    void)
{
    grant_ref_t fh, nfh = gnttab_free_head;
    do { fh = nfh; }
    while ( unlikely((nfh = cmpxchg(&gnttab_free_head, fh,
                                    auxtab[fh].next)) != fh) );
    return fh;
}

static inline void
put_free_entry(
    grant_ref_t ref)
{
    grant_ref_t fh, nfh = gnttab_free_head;
    do { auxtab[ref].next = fh = nfh; wmb(); }
    while ( unlikely((nfh = cmpxchg(&gnttab_free_head, fh, ref)) != fh) );
}

/*
 * Public interface functions
 */

grant_ref_t
gnttab_grant_foreign_access(
    domid_t domid, unsigned long frame, int readonly)
{
    unsigned long flags;
    grant_ref_t   ref;

    spin_lock_irqsave(&gnttab_lock, flags);

    for ( ref  = gnttab_hash[GNTTAB_HASH(frame)];
          ref != HASH_INVALID;
          ref  = auxtab[ref].next )
    {
        if ( auxtab[ref].inuse && (shared[ref].frame == frame) )
        {
            if ( readonly )
                auxtab[ref].read_pin++;
            else if ( auxtab[ref].write_pin++ == 0 )
                clear_bit(_GTF_readonly, (unsigned long *)&shared[ref].flags);
            goto done;
        }
    }

    ref = get_free_entry();
    auxtab[ref].inuse     = 1;
    auxtab[ref].read_pin  = !!readonly;
    auxtab[ref].write_pin =  !readonly;
    auxtab[ref].next = gnttab_hash[GNTTAB_HASH(frame)];
    gnttab_hash[GNTTAB_HASH(frame)] = ref;

    shared[ref].frame = frame;
    shared[ref].domid = domid;
    wmb();
    shared[ref].flags = GTF_permit_access | (readonly ? GTF_readonly : 0);

 done:
    spin_unlock_irqrestore(&gnttab_lock, flags);
    return 0;
}

void
gnttab_end_foreign_access(
    grant_ref_t ref, int readonly)
{
    unsigned long flags, frame = shared[ref].frame;
    grant_ref_t  *pref;
    u16           sflags, nsflags;

    spin_lock_irqsave(&gnttab_lock, flags);

    if ( readonly )
    {
        if ( (auxtab[ref].read_pin-- == 0) && (auxtab[ref].write_pin == 0) )
            goto delete;
    }
    else if ( auxtab[ref].write_pin-- == 0 )
    {
        if ( auxtab[ref].read_pin == 0 )
            goto delete;
        nsflags = shared[ref].flags;
        do {
            if ( (sflags = nsflags) & GTF_writing )
                printk(KERN_ALERT "WARNING: g.e. still in use for writing!\n");
        }
        while ( (nsflags = cmpxchg(&shared[ref].flags, sflags, 
                                   sflags | GTF_readonly)) != sflags );
    }

    goto out;

 delete:
    nsflags = shared[ref].flags;
    do {
        if ( (sflags = nsflags) & (GTF_reading|GTF_writing) )
            printk(KERN_ALERT "WARNING: g.e. still in use!\n");
    }
    while ( (nsflags = cmpxchg(&shared[ref].flags, sflags, 0)) != sflags );

    pref = &gnttab_hash[GNTTAB_HASH(frame)];
    while ( *pref != ref )
        pref = &auxtab[*pref].next;
    *pref = auxtab[ref].next;

    auxtab[ref].inuse = 0;
    put_free_entry(ref);

 out:
    spin_unlock_irqrestore(&gnttab_lock, flags);
}

grant_ref_t
gnttab_grant_foreign_transfer(
    domid_t domid)
{
    grant_ref_t ref = get_free_entry();

    shared[ref].frame = 0;
    shared[ref].domid = domid;
    wmb();
    shared[ref].flags = GTF_accept_transfer;

    return ref;
}

unsigned long
gnttab_end_foreign_transfer(
    grant_ref_t ref)
{
    unsigned long frame = 0;
    u16           flags;

    flags = shared[ref].flags;
    ASSERT(flags == (GTF_accept_transfer | GTF_transfer_committed));

    /*
     * If a transfer is committed then wait for the frame address to appear.
     * Otherwise invalidate the grant entry against future use.
     */
    if ( likely(flags != GTF_accept_transfer) ||
         (cmpxchg(&shared[ref].flags, flags, 0) != GTF_accept_transfer) )
        while ( unlikely((frame = shared[ref].frame) == 0) )
            cpu_relax();

    put_free_entry(ref);

    return frame;
}

void __init gnttab_init(void)
{
    int               i;
    gnttab_op_t       gntop;
    unsigned long     frame;

    spin_lock_init(&gnttab_lock);

    for ( i = 0; i < GNTTAB_HASH_SZ; i++ )
    {
        gnttab_hash[i] = HASH_INVALID;
        auxtab[i].next = i+1;
    }

    gntop.cmd = GNTTABOP_setup_table;
    gntop.u.setup_table.dom        = DOMID_SELF;
    gntop.u.setup_table.nr_frames  = 1;
    gntop.u.setup_table.frame_list = &frame;
    if ( HYPERVISOR_grant_table_op(&gntop) != 0 )
        BUG();

    set_fixmap_ma(FIX_GNTTAB, frame << PAGE_SHIFT);
    shared = (grant_entry_t *)fix_to_virt(FIX_GNTTAB);
}
