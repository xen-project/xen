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
#include <linux/module.h>
#include <linux/kernel.h>
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
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <linux/list.h>

static struct proc_dir_entry *balloon_pde;

unsigned long credit;
static unsigned long current_pages;

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
#endif

#define IPRINTK(fmt, args...) \
    printk(KERN_INFO "xen_mem: " fmt, ##args)
#define WPRINTK(fmt, args...) \
    printk(KERN_WARNING "xen_mem: " fmt, ##args)

/* List of ballooned pages, threaded through the mem_map array. */
LIST_HEAD(ballooned_pages);

/* balloon_append: add the given page to the balloon. */
void balloon_append(struct page *page)
{
    list_add(PAGE_TO_LIST(page), &ballooned_pages);
}

/* balloon_retrieve: rescue a page from the balloon, if it is not empty. */
struct page *balloon_retrieve(void)
{
    struct page *page;

    if ( list_empty(&ballooned_pages) )
        return NULL;

    page = LIST_TO_PAGE(ballooned_pages.next);
    UNLIST_PAGE(page);
    return page;
}

static inline pte_t *get_ptep(unsigned long addr)
{
    pgd_t *pgd;
    pmd_t *pmd;

    pgd = pgd_offset_k(addr);
    if ( pgd_none(*pgd) || pgd_bad(*pgd) ) BUG();

    pmd = pmd_offset(pgd, addr);
    if ( pmd_none(*pmd) || pmd_bad(*pmd) ) BUG();

    return pte_offset_kernel(pmd, addr);
}

/* Main function for relinquishing memory. */
static unsigned long inflate_balloon(unsigned long num_pages)
{
    unsigned long *parray, *currp, curraddr, ret = 0, i, j, mfn, pfn;
    struct page *page;

    parray = (unsigned long *)vmalloc(num_pages * sizeof(unsigned long));
    if ( parray == NULL )
    {
        WPRINTK("inflate_balloon: Unable to vmalloc parray\n");
        return -ENOMEM;
    }

    currp = parray;

    for ( i = 0; i < num_pages; i++, currp++ )
    {
        page = alloc_page(GFP_HIGHUSER);
        pfn  = page - mem_map;

        /* If allocation fails then free all reserved pages. */
        if ( page == NULL )
        {
            printk(KERN_ERR "Unable to inflate balloon by %ld, only"
                   " %ld pages free.", num_pages, i);
            currp = parray;
            for ( j = 0; j < i; j++, currp++ )
                __free_page((struct page *) (mem_map + *currp));

            ret = -EFAULT;
            goto cleanup;
        }

        *currp = pfn;
    }

    for ( i = 0, currp = parray; i < num_pages; i++, currp++ )
    {
        mfn      = phys_to_machine_mapping[*currp];
        curraddr = (unsigned long)page_address(mem_map + *currp);
        /* Blow away page contents for security, and also p.t. ref if any. */
        if ( curraddr != 0 )
        {
            scrub_pages(curraddr, 1);
            queue_l1_entry_update(get_ptep(curraddr), 0);
        }
#ifdef CONFIG_XEN_SCRUB_PAGES
        else
        {
            void *p = kmap(&mem_map[*currp]);
            scrub_pages(p, 1);
            kunmap(&mem_map[*currp]);
        }
#endif

        balloon_append(&mem_map[*currp]);

        phys_to_machine_mapping[*currp] = INVALID_P2M_ENTRY;
        *currp = mfn;
    }

    /* Flush updates through and flush the TLB. */
    xen_tlb_flush();

    ret = HYPERVISOR_dom_mem_op(MEMOP_decrease_reservation, 
                                parray, num_pages, 0);
    if ( unlikely(ret != num_pages) )
    {
        printk(KERN_ERR "Unable to inflate balloon, error %lx\n", ret);
        goto cleanup;
    }

    credit += num_pages;
    ret = num_pages;

 cleanup:
    vfree(parray);

    return ret;
}

/* Install a set of new pages (@mfn_list, @nr_mfns) into the memory map. */
static unsigned long process_returned_pages(
    unsigned long *mfn_list, unsigned long nr_mfns)
{
    unsigned long pfn, i;
    struct page *page;

    for ( i = 0; i < nr_mfns; i++ )
    {
        if ( (page = balloon_retrieve()) != NULL )
            break;

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

    return i;
}

unsigned long deflate_balloon(unsigned long num_pages)
{
    unsigned long ret;
    unsigned long *parray;

    if ( num_pages > credit )
    {
        printk(KERN_ERR "deflate_balloon: %lu pages > %lu credit.\n",
               num_pages, credit);
        return -EAGAIN;
    }

    parray = (unsigned long *)vmalloc(num_pages * sizeof(unsigned long));
    if ( parray == NULL )
    {
        printk(KERN_ERR "deflate_balloon: Unable to vmalloc parray\n");
        return 0;
    }

    ret = HYPERVISOR_dom_mem_op(MEMOP_increase_reservation, 
                                parray, num_pages, 0);
    if ( unlikely(ret != num_pages) )
    {
        printk(KERN_ERR "deflate_balloon: xen increase_reservation err %lx\n",
               ret);
        goto cleanup;
    }

    if ( (ret = process_returned_pages(parray, num_pages)) < num_pages )
    {
        printk(KERN_WARNING
               "deflate_balloon: restored only %lx of %lx pages.\n",
           ret, num_pages);
        goto cleanup;
    }

    ret = num_pages;
    credit -= num_pages;

 cleanup:
    vfree(parray);

    return ret;
}

#define PAGE_TO_MB_SHIFT 8

static int balloon_try_target(int target)
{
    int change, reclaim;

    if ( target < current_pages )
    {
        if ( (change = inflate_balloon(current_pages-target)) <= 0 )
            return change;
        current_pages -= change;
        printk(KERN_INFO "Relinquish %dMB to xen. Domain now has %luMB\n",
            change>>PAGE_TO_MB_SHIFT, current_pages>>PAGE_TO_MB_SHIFT);
    }
    else if ( (reclaim = target - current_pages) > 0 )
    {
        if ( (change = deflate_balloon(reclaim)) <= 0 )
            return change;
        current_pages += change;
        printk(KERN_INFO "Reclaim %dMB from xen. Domain now has %luMB\n",
               change>>PAGE_TO_MB_SHIFT, current_pages>>PAGE_TO_MB_SHIFT);
    }

    return 1;
}


static void balloon_ctrlif_rx(ctrl_msg_t *msg, unsigned long id)
{
    switch ( msg->subtype )
    {
    case CMSG_MEM_REQUEST_SET:
        if ( msg->length != sizeof(mem_request_t) )
            goto parse_error;
        {
            mem_request_t *req = (mem_request_t *)&msg->msg[0];
            req->status = balloon_try_target(req->target);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
typedef size_t count_t;
#else
typedef u_long count_t;
#endif

static int do_balloon_write(const char *buffer, count_t count)
{
    char memstring[64], *endchar;
    int len, i;
    unsigned long target;
    unsigned long long targetbytes;

    /* Only admin can play with the balloon :) */
    if ( !capable(CAP_SYS_ADMIN) )
        return -EPERM;

    if ( count > sizeof(memstring) )
        return -EFBIG;

    len = strnlen_user(buffer, count);
    if ( len == 0 ) return -EBADMSG;
    if ( len == 1 ) return 1; /* input starts with a NUL char */
    if ( strncpy_from_user(memstring, buffer, len) < 0 )
        return -EFAULT;

    endchar = memstring;
    for ( i = 0; i < len; ++i, ++endchar )
        if ( (memstring[i] < '0') || (memstring[i] > '9') )
            break;
    if ( i == 0 )
        return -EBADMSG;

    targetbytes = memparse(memstring,&endchar);
    target = targetbytes >> PAGE_SHIFT;

    i = balloon_try_target(target);

    if ( i <= 0 ) return i;

    return len;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static int balloon_write(struct file *file, const char *buffer,
                         size_t count, loff_t *offp)
{
    int len = do_balloon_write(buffer, count);
    
    if ( len <= 0 ) return len;

    *offp += len;
    return len;
}

static int balloon_read(struct file *filp, char *buffer,
                        size_t count, loff_t *offp)
{
    static char priv_buf[32];
    char *priv_bufp = priv_buf;
    int len;
    len = sprintf(priv_buf,"%lu\n",current_pages<<PAGE_SHIFT);

    len -= *offp;
    priv_bufp += *offp;
    if (len>count) len = count;
    if (len<0) len = 0;

    if ( copy_to_user(buffer, priv_bufp, len) != 0 )
        return -EFAULT;

    *offp += len;
    return len;
}

static struct file_operations balloon_fops = {
    .read  = balloon_read,
    .write = balloon_write
};

#else

static int balloon_write(struct file *file, const char *buffer,
                         u_long count, void *data)
{
    return do_balloon_write(buffer, count);
}

static int balloon_read(char *page, char **start, off_t off,
			int count, int *eof, void *data)
{
  int len;
  len = sprintf(page,"%lu\n",current_pages<<PAGE_SHIFT);
  
  if (len <= off+count) *eof = 1;
  *start = page + off;
  len -= off;
  if (len>count) len = count;
  if (len<0) len = 0;
  return len;
}

#endif

static int __init balloon_init(void)
{
    unsigned long pfn;
    struct page *page;

    IPRINTK("Initialising balloon driver.\n");

    current_pages = min(xen_start_info.nr_pages, max_pfn);
    if ( (balloon_pde = create_xen_proc_entry("memory_target", 0644)) == NULL )
    {
        WPRINTK("Unable to create balloon driver proc entry!");
        return -1;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    balloon_pde->owner     = THIS_MODULE;
    balloon_pde->nlink     = 1;
    balloon_pde->proc_fops = &balloon_fops;
#else
    balloon_pde->write_proc = balloon_write;
    balloon_pde->read_proc  = balloon_read;
#endif

    (void)ctrl_if_register_receiver(CMSG_MEM_REQUEST, balloon_ctrlif_rx,
                                    CALLBACK_IN_BLOCKING_CONTEXT);

    /* Initialise the balloon with excess memory space. */
    for ( pfn = xen_start_info.nr_pages; pfn < max_pfn; pfn++ )
    {
        page = &mem_map[pfn];
        if ( !PageReserved(page) )
            balloon_append(page);
    }

    return 0;
}

static void __exit balloon_cleanup(void)
{
    if ( balloon_pde != NULL )
    {
        remove_xen_proc_entry("memory_target");
        balloon_pde = NULL;
    }
}

module_init(balloon_init);
module_exit(balloon_cleanup);
