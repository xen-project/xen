/******************************************************************************
 * balloon.c
 *
 * Xen balloon driver - enables returning/claiming memory to/from Xen.
 *
 * Copyright (c) 2003, B Dragovic
 * Copyright (c) 2003-2004, M Williamson, K Fraser
 * 
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/smp_lock.h>
#include <linux/pagemap.h>
#include <linux/bootmem.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <asm-xen/xen_proc.h>
#include <asm-xen/hypervisor.h>
#include <asm-xen/ctrl_if.h>
#include <asm-xen/balloon.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <linux/list.h>

static struct proc_dir_entry *balloon_pde;

static DECLARE_MUTEX(balloon_mutex);
spinlock_t balloon_lock = SPIN_LOCK_UNLOCKED;

/* We aim for 'current allocation' == 'target allocation'. */
static unsigned long current_pages;
static unsigned long target_pages;

/* We may hit the hard limit in Xen. If we do then we remember it. */
static unsigned long hard_limit;

/*
 * Drivers may alter the memory reservation independently, but they must
 * inform the balloon driver so that we can avoid hitting the hard limit.
 */
static unsigned long driver_pages;

/* List of ballooned pages, threaded through the mem_map array. */
static LIST_HEAD(ballooned_pages);
static unsigned long balloon_low, balloon_high;

/* Main work function, always executed in process context. */
static void balloon_process(void *unused);
static DECLARE_WORK(balloon_worker, balloon_process, NULL);
static struct timer_list balloon_timer;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
/* Use the private and mapping fields of struct page as a list. */
#define PAGE_TO_LIST(p) ( (struct list_head *)&p->private )
#define LIST_TO_PAGE(l) ( list_entry( ((unsigned long *)l),   \
				      struct page, private ) )
#define UNLIST_PAGE(p)  do { list_del(PAGE_TO_LIST(p));       \
                             p->mapping = NULL;               \
                             p->private = 0; } while(0)
#else
/* There's a dedicated list field in struct page we can use.    */
#define PAGE_TO_LIST(p) ( &p->list )
#define LIST_TO_PAGE(l) ( list_entry(l, struct page, list) )
#define UNLIST_PAGE(p)  ( list_del(&p->list) )
#define pte_offset_kernel pte_offset
#define pud_t pgd_t
#define pud_offset(d, va) d
#define pud_none(d) 0
#define pud_bad(d) 0
#define subsys_initcall(_fn) __initcall(_fn)
#define pfn_to_page(_pfn) (mem_map + (_pfn))
#endif

#define IPRINTK(fmt, args...) \
    printk(KERN_INFO "xen_mem: " fmt, ##args)
#define WPRINTK(fmt, args...) \
    printk(KERN_WARNING "xen_mem: " fmt, ##args)

/* balloon_append: add the given page to the balloon. */
static void balloon_append(struct page *page)
{
    /* Low memory is re-populated first, so highmem pages go at list tail. */
    if ( PageHighMem(page) )
    {
        list_add_tail(PAGE_TO_LIST(page), &ballooned_pages);
        balloon_high++;
    }
    else
    {
        list_add(PAGE_TO_LIST(page), &ballooned_pages);
        balloon_low++;
    }
}

/* balloon_retrieve: rescue a page from the balloon, if it is not empty. */
static struct page *balloon_retrieve(void)
{
    struct page *page;

    if ( list_empty(&ballooned_pages) )
        return NULL;

    page = LIST_TO_PAGE(ballooned_pages.next);
    UNLIST_PAGE(page);

    if ( PageHighMem(page) )
        balloon_high--;
    else
        balloon_low--;

    return page;
}

static inline pte_t *get_ptep(unsigned long addr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

    pgd = pgd_offset_k(addr);
    if ( pgd_none(*pgd) || pgd_bad(*pgd) ) BUG();

    pud = pud_offset(pgd, addr);
    if ( pud_none(*pud) || pud_bad(*pud) ) BUG();

    pmd = pmd_offset(pud, addr);
    if ( pmd_none(*pmd) || pmd_bad(*pmd) ) BUG();

    return pte_offset_kernel(pmd, addr);
}

static void balloon_alarm(unsigned long unused)
{
    schedule_work(&balloon_worker);
}

static unsigned long current_target(void)
{
    unsigned long target = min(target_pages, hard_limit);
    if ( target > (current_pages + balloon_low + balloon_high) )
        target = current_pages + balloon_low + balloon_high;
    return target;
}

/*
 * We avoid multiple worker processes conflicting via the balloon mutex.
 * We may of course race updates of the target counts (which are protected
 * by the balloon lock), or with changes to the Xen hard limit, but we will
 * recover from these in time.
 */
static void balloon_process(void *unused)
{
    unsigned long *mfn_list, pfn, i, flags;
    struct page   *page;
    long           credit, debt, rc;
    void          *v;

    down(&balloon_mutex);

 retry:
    mfn_list = NULL;

    if ( (credit = current_target() - current_pages) > 0 )
    {
        mfn_list = (unsigned long *)vmalloc(credit * sizeof(*mfn_list));
        if ( mfn_list == NULL )
            goto out;

        balloon_lock(flags);
        rc = HYPERVISOR_dom_mem_op(
            MEMOP_increase_reservation, mfn_list, credit, 0);
        balloon_unlock(flags);
        if ( rc < credit )
        {
            /* We hit the Xen hard limit: reprobe. */
            if ( HYPERVISOR_dom_mem_op(
                MEMOP_decrease_reservation, mfn_list, rc, 0) != rc )
                BUG();
            hard_limit = current_pages + rc - driver_pages;
            vfree(mfn_list);
            goto retry;
        }

        for ( i = 0; i < credit; i++ )
        {
            if ( (page = balloon_retrieve()) == NULL )
                BUG();

            pfn = page - mem_map;
            if ( phys_to_machine_mapping[pfn] != INVALID_P2M_ENTRY )
                BUG();

            /* Update P->M and M->P tables. */
            phys_to_machine_mapping[pfn] = mfn_list[i];
            queue_machphys_update(mfn_list[i], pfn);
            
            /* Link back into the page tables if it's not a highmem page. */
            if ( pfn < max_low_pfn )
                queue_l1_entry_update(
                    get_ptep((unsigned long)__va(pfn << PAGE_SHIFT)),
                    (mfn_list[i] << PAGE_SHIFT) | pgprot_val(PAGE_KERNEL));
            
            /* Finally, relinquish the memory back to the system allocator. */
            ClearPageReserved(page);
            set_page_count(page, 1);
            __free_page(page);
        }

        current_pages += credit;
    }
    else if ( credit < 0 )
    {
        debt = -credit;

        mfn_list = (unsigned long *)vmalloc(debt * sizeof(*mfn_list));
        if ( mfn_list == NULL )
            goto out;

        for ( i = 0; i < debt; i++ )
        {
            if ( (page = alloc_page(GFP_HIGHUSER)) == NULL )
            {
                debt = i;
                break;
            }

            pfn = page - mem_map;
            mfn_list[i] = phys_to_machine_mapping[pfn];

            if ( !PageHighMem(page) )
            {
                v = phys_to_virt(pfn << PAGE_SHIFT);
                scrub_pages(v, 1);
                queue_l1_entry_update(get_ptep((unsigned long)v), 0);
            }
#ifdef CONFIG_XEN_SCRUB_PAGES
            else
            {
                v = kmap(page);
                scrub_pages(v, 1);
                kunmap(page);
            }
#endif
        }

        /* Ensure that ballooned highmem pages don't have cached mappings. */
        kmap_flush_unused();

        /* Flush updates through and flush the TLB. */
        xen_tlb_flush();

        /* No more mappings: invalidate pages in P2M and add to balloon. */
        for ( i = 0; i < debt; i++ )
        {
            pfn = mfn_to_pfn(mfn_list[i]);
            phys_to_machine_mapping[pfn] = INVALID_P2M_ENTRY;
            balloon_append(pfn_to_page(pfn));
        }

        if ( HYPERVISOR_dom_mem_op(
            MEMOP_decrease_reservation, mfn_list, debt, 0) != debt )
            BUG();

        current_pages -= debt;
    }

 out:
    if ( mfn_list != NULL )
        vfree(mfn_list);

    /* Schedule more work if there is some still to be done. */
    if ( current_target() != current_pages )
        mod_timer(&balloon_timer, jiffies + HZ);

    up(&balloon_mutex);
}

/* Resets the Xen limit, sets new target, and kicks off processing. */
static void set_new_target(unsigned long target)
{
    /* No need for lock. Not read-modify-write updates. */
    hard_limit   = ~0UL;
    target_pages = target;
    schedule_work(&balloon_worker);
}

static void balloon_ctrlif_rx(ctrl_msg_t *msg, unsigned long id)
{
    switch ( msg->subtype )
    {
    case CMSG_MEM_REQUEST_SET:
    {
        mem_request_t *req = (mem_request_t *)&msg->msg[0];
        if ( msg->length != sizeof(mem_request_t) )
            goto parse_error;
        set_new_target(req->target);
        req->status = 0;
    }
    break;        
    default:
        goto parse_error;
    }

    ctrl_if_send_response(msg);
    return;

 parse_error:
    msg->length = 0;
    ctrl_if_send_response(msg);
}

static int balloon_write(struct file *file, const char __user *buffer,
                         unsigned long count, void *data)
{
    char memstring[64], *endchar;
    unsigned long long target_bytes;

    if ( !capable(CAP_SYS_ADMIN) )
        return -EPERM;

    if ( count <= 1 )
        return -EBADMSG; /* runt */
    if ( count > sizeof(memstring) )
        return -EFBIG;   /* too long */

    if ( copy_from_user(memstring, buffer, count) )
        return -EFAULT;
    memstring[sizeof(memstring)-1] = '\0';

    target_bytes = memparse(memstring, &endchar);
    set_new_target(target_bytes >> PAGE_SHIFT);

    return count;
}

static int balloon_read(char *page, char **start, off_t off,
                        int count, int *eof, void *data)
{
    int len;

#define K(_p) ((_p)<<(PAGE_SHIFT-10))
    len = sprintf(
        page,
        "Current allocation: %8lu kB\n"
        "Requested target:   %8lu kB\n"
        "Low-mem balloon:    %8lu kB\n"
        "High-mem balloon:   %8lu kB\n"
        "Xen hard limit:     ",
        K(current_pages), K(target_pages), K(balloon_low), K(balloon_high));

    if ( hard_limit != ~0UL )
        len += sprintf(
            page + len, 
            "%8lu kB (inc. %8lu kB driver headroom)\n",
            K(hard_limit), K(driver_pages));
    else
        len += sprintf(
            page + len,
            "     ??? kB\n");

    *eof = 1;
    return len;
}

static int __init balloon_init(void)
{
    unsigned long pfn;
    struct page *page;

    IPRINTK("Initialising balloon driver.\n");

    current_pages = min(xen_start_info.nr_pages, max_pfn);
    target_pages  = current_pages;
    balloon_low   = 0;
    balloon_high  = 0;
    driver_pages  = 0UL;
    hard_limit    = ~0UL;

    init_timer(&balloon_timer);
    balloon_timer.data = 0;
    balloon_timer.function = balloon_alarm;
    
    if ( (balloon_pde = create_xen_proc_entry("balloon", 0644)) == NULL )
    {
        WPRINTK("Unable to create /proc/xen/balloon.\n");
        return -1;
    }

    balloon_pde->read_proc  = balloon_read;
    balloon_pde->write_proc = balloon_write;

    (void)ctrl_if_register_receiver(CMSG_MEM_REQUEST, balloon_ctrlif_rx, 0);

    /* Initialise the balloon with excess memory space. */
    for ( pfn = xen_start_info.nr_pages; pfn < max_pfn; pfn++ )
    {
        page = &mem_map[pfn];
        if ( !PageReserved(page) )
            balloon_append(page);
    }

    return 0;
}

subsys_initcall(balloon_init);

void balloon_update_driver_allowance(long delta)
{
    unsigned long flags;
    balloon_lock(flags);
    driver_pages += delta; /* non-atomic update */
    balloon_unlock(flags);
}

void balloon_put_pages(unsigned long *mfn_list, unsigned long nr_mfns)
{
    unsigned long flags;

    balloon_lock(flags);
    if ( HYPERVISOR_dom_mem_op(MEMOP_decrease_reservation, 
                               mfn_list, nr_mfns, 0) != nr_mfns )
        BUG();
    current_pages -= nr_mfns; /* non-atomic update */
    balloon_unlock(flags);

    schedule_work(&balloon_worker);
}

EXPORT_SYMBOL(balloon_update_driver_allowance);
EXPORT_SYMBOL(balloon_put_pages);
