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
#include <asm-xen/synch_bitops.h>

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
EXPORT_SYMBOL(gnttab_end_foreign_access_ref);
EXPORT_SYMBOL(gnttab_end_foreign_access);
EXPORT_SYMBOL(gnttab_query_foreign_access);
EXPORT_SYMBOL(gnttab_grant_foreign_transfer);
EXPORT_SYMBOL(gnttab_end_foreign_transfer_ref);
EXPORT_SYMBOL(gnttab_end_foreign_transfer);
EXPORT_SYMBOL(gnttab_alloc_grant_references);
EXPORT_SYMBOL(gnttab_free_grant_references);
EXPORT_SYMBOL(gnttab_free_grant_reference);
EXPORT_SYMBOL(gnttab_claim_grant_reference);
EXPORT_SYMBOL(gnttab_release_grant_reference);
EXPORT_SYMBOL(gnttab_grant_foreign_access_ref);
EXPORT_SYMBOL(gnttab_grant_foreign_transfer_ref);

#define NR_GRANT_ENTRIES (NR_GRANT_FRAMES * PAGE_SIZE / sizeof(grant_entry_t))
#define GNTTAB_LIST_END (NR_GRANT_ENTRIES + 1)

static grant_ref_t gnttab_list[NR_GRANT_ENTRIES];
static int gnttab_free_count = NR_GRANT_ENTRIES;
static grant_ref_t gnttab_free_head;
static spinlock_t gnttab_list_lock = SPIN_LOCK_UNLOCKED;

static grant_entry_t *shared;

static struct gnttab_free_callback *gnttab_free_callback_list = NULL;

static int
get_free_entries(int count)
{
    unsigned long flags;
    int ref;
    grant_ref_t head;
    spin_lock_irqsave(&gnttab_list_lock, flags);
    if (gnttab_free_count < count) {
	spin_unlock_irqrestore(&gnttab_list_lock, flags);
	return -1;
    }
    ref = head = gnttab_free_head;
    gnttab_free_count -= count;
    while (count-- > 1)
	head = gnttab_list[head];
    gnttab_free_head = gnttab_list[head];
    gnttab_list[head] = GNTTAB_LIST_END;
    spin_unlock_irqrestore(&gnttab_list_lock, flags);
    return ref;
}

#define get_free_entry() get_free_entries(1)

static void
do_free_callbacks(void)
{
    struct gnttab_free_callback *callback = gnttab_free_callback_list, *next;
    gnttab_free_callback_list = NULL;
    while (callback) {
	next = callback->next;
	if (gnttab_free_count >= callback->count) {
	    callback->next = NULL;
	    callback->fn(callback->arg);
	} else {
	    callback->next = gnttab_free_callback_list;
	    gnttab_free_callback_list = callback;
	}
	callback = next;
    }
}

static inline void
check_free_callbacks(void)
{
    if (unlikely(gnttab_free_callback_list))
	do_free_callbacks();
}

static void
put_free_entry(grant_ref_t ref)
{
    unsigned long flags;
    spin_lock_irqsave(&gnttab_list_lock, flags);
    gnttab_list[ref] = gnttab_free_head;
    gnttab_free_head = ref;
    gnttab_free_count++;
    check_free_callbacks();
    spin_unlock_irqrestore(&gnttab_list_lock, flags);
}

/*
 * Public grant-issuing interface functions
 */

int
gnttab_grant_foreign_access(domid_t domid, unsigned long frame, int readonly)
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
gnttab_grant_foreign_access_ref(grant_ref_t ref, domid_t domid,
				unsigned long frame, int readonly)
{
    shared[ref].frame = frame;
    shared[ref].domid = domid;
    wmb();
    shared[ref].flags = GTF_permit_access | (readonly ? GTF_readonly : 0);
}


int
gnttab_query_foreign_access(grant_ref_t ref)
{
    u16 nflags;

    nflags = shared[ref].flags;

    return ( nflags & (GTF_reading|GTF_writing) );
}

void
gnttab_end_foreign_access_ref(grant_ref_t ref, int readonly)
{
    u16 flags, nflags;

    nflags = shared[ref].flags;
    do {
        if ( (flags = nflags) & (GTF_reading|GTF_writing) )
            printk(KERN_ALERT "WARNING: g.e. still in use!\n");
    }
    while ( (nflags = synch_cmpxchg(&shared[ref].flags, flags, 0)) != flags );
}

void
gnttab_end_foreign_access(grant_ref_t ref, int readonly)
{
    gnttab_end_foreign_access_ref(ref, readonly);
    put_free_entry(ref);
}

int
gnttab_grant_foreign_transfer(domid_t domid, unsigned long pfn)
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
gnttab_grant_foreign_transfer_ref(grant_ref_t ref, domid_t domid,
				  unsigned long pfn)
{
    shared[ref].frame = pfn;
    shared[ref].domid = domid;
    wmb();
    shared[ref].flags = GTF_accept_transfer;
}

unsigned long
gnttab_end_foreign_transfer_ref(grant_ref_t ref)
{
    unsigned long frame = 0;
    u16           flags;

    flags = shared[ref].flags;

    /*
     * If a transfer is committed then wait for the frame address to appear.
     * Otherwise invalidate the grant entry against future use.
     */
    if ( likely(flags != GTF_accept_transfer) ||
         (synch_cmpxchg(&shared[ref].flags, flags, 0) != GTF_accept_transfer) )
        while ( unlikely((frame = shared[ref].frame) == 0) )
            cpu_relax();

    return frame;
}

unsigned long
gnttab_end_foreign_transfer(grant_ref_t ref)
{
    unsigned long frame = gnttab_end_foreign_transfer_ref(ref);
    put_free_entry(ref);
    return frame;
}

void
gnttab_free_grant_reference(grant_ref_t ref)
{

    put_free_entry(ref);
}

void
gnttab_free_grant_references(grant_ref_t head)
{
    grant_ref_t ref;
    unsigned long flags;
    int count = 1;
    if (head == GNTTAB_LIST_END)
	return;
    spin_lock_irqsave(&gnttab_list_lock, flags);
    ref = head;
    while (gnttab_list[ref] != GNTTAB_LIST_END) {
	ref = gnttab_list[ref];
	count++;
    }
    gnttab_list[ref] = gnttab_free_head;
    gnttab_free_head = head;
    gnttab_free_count += count;
    check_free_callbacks();
    spin_unlock_irqrestore(&gnttab_list_lock, flags);
}

int
gnttab_alloc_grant_references(u16 count, grant_ref_t *head)
{
    int h = get_free_entries(count);

    if (h == -1)
	return -ENOSPC;

    *head = h;

    return 0;
}

int
gnttab_claim_grant_reference(grant_ref_t *private_head)
{
    grant_ref_t g = *private_head;
    if (unlikely(g == GNTTAB_LIST_END))
        return -ENOSPC;
    *private_head = gnttab_list[g];
    return g;
}

void
gnttab_release_grant_reference(grant_ref_t *private_head, grant_ref_t  release)
{
    gnttab_list[release] = *private_head;
    *private_head = release;
}

void
gnttab_request_free_callback(struct gnttab_free_callback *callback,
			     void (*fn)(void *), void *arg, u16 count)
{
    unsigned long flags;
    spin_lock_irqsave(&gnttab_list_lock, flags);
    if (callback->next)
	goto out;
    callback->fn = fn;
    callback->arg = arg;
    callback->count = count;
    callback->next = gnttab_free_callback_list;
    gnttab_free_callback_list = callback;
    check_free_callbacks();
 out:
    spin_unlock_irqrestore(&gnttab_list_lock, flags);
}

/*
 * ProcFS operations
 */

#ifdef CONFIG_PROC_FS

static struct proc_dir_entry *grant_pde;

static int
grant_ioctl(struct inode *inode, struct file *file, unsigned int cmd,
	    unsigned long data)
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

static int
grant_read(char *page, char **start, off_t off, int count, int *eof,
	   void *data)
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

static int
grant_write(struct file *file, const char __user *buffer, unsigned long count,
	    void *data)
{
    /* TODO: implement this */
    return -ENOSYS;
}

#endif /* CONFIG_PROC_FS */

int
gnttab_resume(void)
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
        set_fixmap(FIX_GNTTAB_END - i, frames[i] << PAGE_SHIFT);

    return 0;
}

int
gnttab_suspend(void)
{
    int i;

    for ( i = 0; i < NR_GRANT_FRAMES; i++ )
	clear_fixmap(FIX_GNTTAB_END - i);

    return 0;
}

static int __init
gnttab_init(void)
{
    int i;

    BUG_ON(gnttab_resume());

    shared = (grant_entry_t *)fix_to_virt(FIX_GNTTAB_END);

    for ( i = 0; i < NR_GRANT_ENTRIES; i++ )
        gnttab_list[i] = i + 1;
    
#ifdef CONFIG_PROC_FS
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
#endif

    printk("Grant table initialized\n");
    return 0;
}

__initcall(gnttab_init);
