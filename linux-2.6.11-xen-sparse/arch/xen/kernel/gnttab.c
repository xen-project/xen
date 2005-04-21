/******************************************************************************
 * gnttab.c
 * 
 * Two sets of functionality:
 * 1. Granting foreign access to our memory reservation.
 * 2. Accessing others' memory reservations via grant references.
 * (i.e., mechanisms for both sender and recipient of grant references)
 * 
 * Copyright (c) 2005, Christopher Clark
 * Copyright (c) 2004, K A Fraser
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <asm/pgtable.h>
#include <asm/fixmap.h>
#include <asm/uaccess.h>
#include <asm-xen/xen_proc.h>
#include <asm-xen/linux-public/privcmd.h>
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

#define WPRINTK(fmt, args...) \
    printk(KERN_WARNING "xen_grant: " fmt, ##args)


EXPORT_SYMBOL(gnttab_grant_foreign_access);
EXPORT_SYMBOL(gnttab_end_foreign_access);
EXPORT_SYMBOL(gnttab_query_foreign_access);
EXPORT_SYMBOL(gnttab_grant_foreign_transfer);
EXPORT_SYMBOL(gnttab_end_foreign_transfer);
EXPORT_SYMBOL(gnttab_alloc_grant_references);
EXPORT_SYMBOL(gnttab_free_grant_references);
EXPORT_SYMBOL(gnttab_claim_grant_reference);
EXPORT_SYMBOL(gnttab_release_grant_reference);
EXPORT_SYMBOL(gnttab_grant_foreign_access_ref);
EXPORT_SYMBOL(gnttab_grant_foreign_transfer_ref);

static grant_ref_t gnttab_free_list[NR_GRANT_ENTRIES];
static grant_ref_t gnttab_free_head;

static grant_entry_t *shared;

/* /proc/xen/grant */
static struct proc_dir_entry *grant_pde;


/*
 * Lock-free grant-entry allocator
 */

static inline int
get_free_entry(
    void)
{
    grant_ref_t fh, nfh = gnttab_free_head;
    do { if ( unlikely((fh = nfh) == NR_GRANT_ENTRIES) ) return -1; }
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
gnttab_grant_foreign_access_ref(
    grant_ref_t ref, domid_t domid, unsigned long frame, int readonly)
{
    shared[ref].frame = frame;
    shared[ref].domid = domid;
    wmb();
    shared[ref].flags = GTF_permit_access | (readonly ? GTF_readonly : 0);
}


int
gnttab_query_foreign_access( grant_ref_t ref )
{
    u16 nflags;

    nflags = shared[ref].flags;

    return ( nflags & (GTF_reading|GTF_writing) );
}

void
gnttab_end_foreign_access( grant_ref_t ref, int readonly )
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
    domid_t domid, unsigned long pfn )
{
    int ref;

    if ( unlikely((ref = get_free_entry()) == -1) )
        return -ENOSPC;

    shared[ref].frame = pfn;
    shared[ref].domid = domid;
    wmb();
    shared[ref].flags = GTF_accept_transfer;

    return ref;
}

void
gnttab_grant_foreign_transfer_ref(
    grant_ref_t ref, domid_t domid, unsigned long pfn )
{
    shared[ref].frame = pfn;
    shared[ref].domid = domid;
    wmb();
    shared[ref].flags = GTF_accept_transfer;
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

void
gnttab_free_grant_references( u16 count, grant_ref_t head )
{
    /* TODO: O(N)...? */
    grant_ref_t to_die = 0, next = head;
    int i;

    for ( i = 0; i < count; i++ )
        to_die = next;
        next = gnttab_free_list[next];
        put_free_entry( to_die );
}

int
gnttab_alloc_grant_references( u16 count,
                               grant_ref_t *head,
                               grant_ref_t *terminal )
{
    int i;
    grant_ref_t h = gnttab_free_head;

    for ( i = 0; i < count; i++ )
        if ( unlikely(get_free_entry() == -1) )
            goto not_enough_refs;

    *head = h;
    *terminal = gnttab_free_head;

    return 0;

not_enough_refs:
    gnttab_free_head = h;
    return -ENOSPC;
}

int
gnttab_claim_grant_reference( grant_ref_t *private_head,
                              grant_ref_t  terminal )
{
    grant_ref_t g;
    if ( unlikely((g = *private_head) == terminal) )
        return -ENOSPC;
    *private_head = gnttab_free_list[g];
    return g;
}

void
gnttab_release_grant_reference( grant_ref_t *private_head,
                                grant_ref_t  release )
{
    gnttab_free_list[release] = *private_head;
    *private_head = release;
}

static int grant_ioctl(struct inode *inode, struct file *file,
                       unsigned int cmd, unsigned long data)
{
    int                     ret;
    privcmd_hypercall_t     hypercall;

    /* XXX Need safety checks here if using for anything other
     *     than debugging */
    return -ENOSYS;

    if ( cmd != IOCTL_PRIVCMD_HYPERCALL )
        return -ENOSYS;

    if ( copy_from_user(&hypercall, (void *)data, sizeof(hypercall)) )
        return -EFAULT;

    if ( hypercall.op != __HYPERVISOR_grant_table_op )
        return -ENOSYS;

    /* hypercall-invoking asm taken from privcmd.c */
    __asm__ __volatile__ (
        "pushl %%ebx; pushl %%ecx; pushl %%edx; pushl %%esi; pushl %%edi; "
        "movl  4(%%eax),%%ebx ;"
        "movl  8(%%eax),%%ecx ;"
        "movl 12(%%eax),%%edx ;"
        "movl 16(%%eax),%%esi ;"
        "movl 20(%%eax),%%edi ;"
        "movl   (%%eax),%%eax ;"
        TRAP_INSTR "; "
        "popl %%edi; popl %%esi; popl %%edx; popl %%ecx; popl %%ebx"
        : "=a" (ret) : "0" (&hypercall) : "memory" );

    return ret;
}

static struct file_operations grant_file_ops = {
    ioctl:  grant_ioctl,
};

static int grant_read(char *page, char **start, off_t off,
                      int count, int *eof, void *data)
{
    int             len;
    unsigned int    i;
    grant_entry_t  *gt;

    gt = (grant_entry_t *)shared;
    len = 0;

    for ( i = 0; i < NR_GRANT_ENTRIES; i++ )
        /* TODO: safety catch here until this can handle >PAGE_SIZE output */
        if (len > (PAGE_SIZE - 200))
        {
            len += sprintf( page + len, "Truncated.\n");
            break;
        }

        if ( gt[i].flags )
            len += sprintf( page + len,
                    "Grant: ref (0x%x) flags (0x%hx) dom (0x%hx) frame (0x%x)\n", 
                    i,
                    gt[i].flags,
                    gt[i].domid,
                    gt[i].frame );

    *eof = 1;
    return len;
}

static int grant_write(struct file *file, const char __user *buffer,
                       unsigned long count, void *data)
{
    /* TODO: implement this */
    return -ENOSYS;
}


int gnttab_resume(void)
{
    gnttab_setup_table_t setup;
    unsigned long        frames[NR_GRANT_FRAMES];
    int                  i;

    setup.dom        = DOMID_SELF;
    setup.nr_frames  = NR_GRANT_FRAMES;
    setup.frame_list = frames;

    BUG_ON(HYPERVISOR_grant_table_op(GNTTABOP_setup_table, &setup, 1) != 0);
    BUG_ON(setup.status != 0);

    for ( i = 0; i < NR_GRANT_FRAMES; i++ )
        set_fixmap_ma(FIX_GNTTAB_END - i, frames[i] << PAGE_SHIFT);

    return 0;
}

int gnttab_suspend(void)
{
    int i;

    for ( i = 0; i < NR_GRANT_FRAMES; i++ )
	clear_fixmap(FIX_GNTTAB_END - i);

    return 0;
}

static int __init gnttab_init(void)
{
    int i;

    BUG_ON(gnttab_resume());

    shared = (grant_entry_t *)fix_to_virt(FIX_GNTTAB_END);

    for ( i = 0; i < NR_GRANT_ENTRIES; i++ )
        gnttab_free_list[i] = i + 1;
    
    /*
     *  /proc/xen/grant : used by libxc to access grant tables
     */
    if ( (grant_pde = create_xen_proc_entry("grant", 0600)) == NULL )
    {
        WPRINTK("Unable to create grant xen proc entry\n");
        return -1;
    }

    grant_file_ops.read   = grant_pde->proc_fops->read;
    grant_file_ops.write  = grant_pde->proc_fops->write;

    grant_pde->proc_fops  = &grant_file_ops;

    grant_pde->read_proc  = &grant_read;
    grant_pde->write_proc = &grant_write;

    printk("Grant table initialized\n");
    return 0;
}

__initcall(gnttab_init);
