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

#define NR_GRANT_REFS 512
static grant_ref_t gnttab_free_list[NR_GRANT_REFS];
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

static int grant_ioctl(struct inode *inode, struct file *file,
                       unsigned int cmd, unsigned long data)
{
    int                     ret;
    privcmd_hypercall_t     hypercall;
                                                                                        
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

    for ( i = 0; i < NR_GRANT_REFS; i++ )
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

static int __init gnttab_init(void)
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

    return 0;
}

__initcall(gnttab_init);
