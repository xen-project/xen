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

#define NR_GRANT_REFS 512
static grant_ref_t gnttab_free_list[NR_GRANT_REFS];
static grant_ref_t gnttab_free_head;

static grant_entry_t *shared;

/*
 * Lock-free grant-entry allocator
 */

static inline int
get_free_entry(
    void)
{
    grant_ref_t fh, nfh = gnttab_free_head;
    do { if ( unlikely((fh = nfh) == NR_GRANT_REFS) ) return -1; }
    while ( unlikely((nfh = cmpxchg(&gnttab_free_head, fh,
                                    gnttab_free_list[fh])) != fh) );
    return fh;
}

static inline void
put_free_entry(
    grant_ref_t ref)
{
    grant_ref_t fh, nfh = gnttab_free_head;
    do { gnttab_free_list[ref] = fh = nfh; wmb(); }
    while ( unlikely((nfh = cmpxchg(&gnttab_free_head, fh, ref)) != fh) );
}

/*
 * Public grant-issuing interface functions
 */

int
gnttab_grant_foreign_access(
    domid_t domid, unsigned long frame, int readonly)
{
    int ref;
    
    if ( unlikely((ref = get_free_entry()) == -1) )
        return -ENOSPC;

    shared[ref].frame = frame;
    shared[ref].domid = domid;
    wmb();
    shared[ref].flags = GTF_permit_access | (readonly ? GTF_readonly : 0);

    return ref;
}

void
gnttab_end_foreign_access(
    grant_ref_t ref, int readonly)
{
    u16 flags, nflags;

    nflags = shared[ref].flags;
    do {
        if ( (flags = nflags) & (GTF_reading|GTF_writing) )
            printk(KERN_ALERT "WARNING: g.e. still in use!\n");
    }
    while ( (nflags = cmpxchg(&shared[ref].flags, flags, 0)) != flags );

    put_free_entry(ref);
}

int
gnttab_grant_foreign_transfer(
    domid_t domid)
{
    int ref;

    if ( unlikely((ref = get_free_entry()) == -1) )
        return -ENOSPC;

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
    gnttab_setup_table_t setup;
    unsigned long        frame;
    int                  i;

    for ( i = 0; i < NR_GRANT_REFS; i++ )
        gnttab_free_list[i] = i + 1;

    setup.dom        = DOMID_SELF;
    setup.nr_frames  = 1;
    setup.frame_list = &frame;
    if ( HYPERVISOR_grant_table_op(GNTTABOP_setup_table, &setup, 1) != 0 )
        BUG();
    if ( setup.status != 0 )
        BUG();

    set_fixmap_ma(FIX_GNTTAB, frame << PAGE_SHIFT);
    shared = (grant_entry_t *)fix_to_virt(FIX_GNTTAB);
}
