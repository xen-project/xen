/******************************************************************************
 * balloon.c
 *
 * Xen balloon driver - enables returning/claiming memory to/from Xen.
 *
 * Copyright (c) 2003, B Dragovic
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <asm-xen/xen_proc.h>

#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/smp_lock.h>
#include <linux/pagemap.h>
#include <linux/bootmem.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>

#include <asm-xen/hypervisor.h>
#include <asm-xen/ctrl_if.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>

/* USER DEFINES -- THESE SHOULD BE COPIED TO USER-SPACE TOOLS */
#define USER_INFLATE_BALLOON  1   /* return mem to hypervisor */
#define USER_DEFLATE_BALLOON  2   /* claim mem from hypervisor */
typedef struct user_balloon_op {
    unsigned int  op;
    unsigned long size;
} user_balloon_op_t;
/* END OF USER DEFINE */

static struct proc_dir_entry *balloon_pde;

unsigned long credit;
static unsigned long current_pages, most_seen_pages;

/*
 * Dead entry written into balloon-owned entries in the PMT.
 * It is deliberately different to INVALID_P2M_ENTRY.
 */
#define DEAD 0xdead1234

static inline pte_t *get_ptep(unsigned long addr)
{
    pgd_t *pgd; pmd_t *pmd; pte_t *ptep;
    pgd = pgd_offset_k(addr);

    if ( pgd_none(*pgd) || pgd_bad(*pgd) ) BUG();

    pmd = pmd_offset(pgd, addr);
    if ( pmd_none(*pmd) || pmd_bad(*pmd) ) BUG();

    ptep = pte_offset_kernel(pmd, addr);

    return ptep;
}

/* Main function for relinquishing memory. */
static unsigned long inflate_balloon(unsigned long num_pages)
{
    unsigned long *parray;
    unsigned long *currp;
    unsigned long curraddr;
    unsigned long ret = 0;
    unsigned long i, j;

    parray = (unsigned long *)vmalloc(num_pages * sizeof(unsigned long));
    if ( parray == NULL )
    {
        printk(KERN_ERR "inflate_balloon: Unable to vmalloc parray\n");
        return -EFAULT;
    }

    currp = parray;

    for ( i = 0; i < num_pages; i++, currp++ )
    {
        struct page *page = alloc_page(GFP_HIGHUSER);
        unsigned long pfn = page - mem_map;

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
        unsigned long mfn = phys_to_machine_mapping[*currp];
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
        phys_to_machine_mapping[*currp] = DEAD;
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

/*
 * Install new mem pages obtained by deflate_balloon. function walks 
 * phys->machine mapping table looking for DEAD entries and populates
 * them.
 */
static unsigned long process_returned_pages(unsigned long * parray, 
                                       unsigned long num)
{
    /* currently, this function is rather simplistic as 
     * it is assumed that domain reclaims only number of 
     * pages previously released. this is to change soon
     * and the code to extend page tables etc. will be 
     * incorporated here.
     */
     
    unsigned long tot_pages = most_seen_pages;   
    unsigned long * curr = parray;
    unsigned long num_installed;
    unsigned long i;

    num_installed = 0;
    for ( i = 0; (i < tot_pages) && (num_installed < num); i++ )
    {
        if ( phys_to_machine_mapping[i] == DEAD )
        {
            phys_to_machine_mapping[i] = *curr;
            queue_machphys_update(*curr, i);
            if (i<max_low_pfn)
              queue_l1_entry_update(
                get_ptep((unsigned long)__va(i << PAGE_SHIFT)),
                ((*curr) << PAGE_SHIFT) | pgprot_val(PAGE_KERNEL));

            __free_page(mem_map + i);

            curr++;
            num_installed++;
        }
    }

    return num_installed;
}

unsigned long deflate_balloon(unsigned long num_pages)
{
    unsigned long ret;
    unsigned long * parray;

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

/*
 * pagetable_extend() mimics pagetable_init() from arch/xen/mm/init.c 
 * The loops do go through all of low memory (ZONE_NORMAL).  The
 * old pages have _PAGE_PRESENT set and so get skipped.
 * If low memory is not full, the new pages are used to fill it, going
 * from cur_low_pfn to low_pfn.   high memory is not direct mapped so
 * no extension is needed for new high memory.
 */

static void pagetable_extend (int cur_low_pfn, int newpages)
{
    unsigned long vaddr, end;
    pgd_t *kpgd, *pgd, *pgd_base;
    int i, j, k;
    pmd_t *kpmd, *pmd;
    pte_t *kpte, *pte, *pte_base;
    int low_pfn = min(cur_low_pfn+newpages,(int)max_low_pfn);

    /*
     * This can be zero as well - no problem, in that case we exit
     * the loops anyway due to the PTRS_PER_* conditions.
     */
    end = (unsigned long)__va(low_pfn*PAGE_SIZE);

    pgd_base = init_mm.pgd;
    i = pgd_index(PAGE_OFFSET);
    pgd = pgd_base + i;

    for (; i < PTRS_PER_PGD; pgd++, i++) {
        vaddr = i*PGDIR_SIZE;
        if (end && (vaddr >= end))
            break;
        pmd = (pmd_t *)pgd;
        for (j = 0; j < PTRS_PER_PMD; pmd++, j++) {
            vaddr = i*PGDIR_SIZE + j*PMD_SIZE;
            if (end && (vaddr >= end))
                break;

            /* Filled in for us already? */
            if ( pmd_val(*pmd) & _PAGE_PRESENT )
                continue;

            pte_base = pte = (pte_t *) __get_free_page(GFP_KERNEL);

            for (k = 0; k < PTRS_PER_PTE; pte++, k++) {
                vaddr = i*PGDIR_SIZE + j*PMD_SIZE + k*PAGE_SIZE;
                if (end && (vaddr >= end))
                    break;
                *pte = mk_pte(virt_to_page(vaddr), PAGE_KERNEL);
            }
            kpgd = pgd_offset_k((unsigned long)pte_base);
            kpmd = pmd_offset(kpgd, (unsigned long)pte_base);
            kpte = pte_offset_kernel(kpmd, (unsigned long)pte_base);
            queue_l1_entry_update(kpte,
                                  (*(unsigned long *)kpte)&~_PAGE_RW);
            set_pmd(pmd, __pmd(_KERNPG_TABLE + __pa(pte_base)));
            XEN_flush_page_update_queue();
        }
    }
}

/*
 * claim_new_pages() asks xen to increase this domain's memory  reservation
 * and return a list of the new pages of memory.  This new pages are
 * added to the free list of the memory manager.
 *
 * Available RAM does not normally change while Linux runs.  To make this work,
 * the linux mem= boottime command line param must say how big memory could
 * possibly grow.  Then setup_arch() in arch/xen/kernel/setup.c
 * sets max_pfn, max_low_pfn and the zones according to
 * this max memory size.   The page tables themselves can only be
 * extended after xen has assigned new pages to this domain.
 */

static unsigned long
claim_new_pages(unsigned long num_pages)
{
    unsigned long new_page_cnt, pfn;
    unsigned long * parray, *curr;

    if (most_seen_pages+num_pages> max_pfn)
        num_pages = max_pfn-most_seen_pages;
    if (num_pages==0) return -EINVAL;

    parray = (unsigned long *)vmalloc(num_pages * sizeof(unsigned long));
    if ( parray == NULL )
    {
        printk(KERN_ERR "claim_new_pages: Unable to vmalloc parray\n");
        return 0;
    }

    new_page_cnt = HYPERVISOR_dom_mem_op(MEMOP_increase_reservation, 
                                parray, num_pages, 0);
    if ( new_page_cnt != num_pages )
    {
        printk(KERN_WARNING
            "claim_new_pages: xen granted only %lu of %lu requested pages\n",
            new_page_cnt, num_pages);

        /* 
         * Avoid xen lockup when user forgot to setdomainmaxmem. Xen
         * usually can dribble out a few pages and then hangs.
         */
        if ( new_page_cnt < 1000 )
        {
            printk(KERN_WARNING "Remember to use setdomainmaxmem\n");
            HYPERVISOR_dom_mem_op(MEMOP_decrease_reservation, 
                                parray, new_page_cnt, 0);
            return -EFAULT;
        }
    }
    memcpy(phys_to_machine_mapping+most_seen_pages, parray,
           new_page_cnt * sizeof(unsigned long));

    pagetable_extend(most_seen_pages,new_page_cnt);

    for ( pfn = most_seen_pages, curr = parray;
          pfn < most_seen_pages+new_page_cnt;
          pfn++, curr++ )
    {
        struct page *page = mem_map + pfn;

#ifndef CONFIG_HIGHMEM
        if ( pfn>=max_low_pfn )
        {
            printk(KERN_WARNING "Warning only %ldMB will be used.\n",
               pfn>>PAGE_TO_MB_SHIFT);
            printk(KERN_WARNING "Use a HIGHMEM enabled kernel.\n");
            break;
        }
#endif
        queue_machphys_update(*curr, pfn);
        if ( pfn < max_low_pfn )
            queue_l1_entry_update(
                get_ptep((unsigned long)__va(pfn << PAGE_SHIFT)),
                ((*curr) << PAGE_SHIFT) | pgprot_val(PAGE_KERNEL));
        
        XEN_flush_page_update_queue();
        
        /* this next bit mimics arch/xen/mm/init.c:one_highpage_init() */
        ClearPageReserved(page);
        if ( pfn >= max_low_pfn )
            set_bit(PG_highmem, &page->flags);
        set_page_count(page, 1);
        __free_page(page);
    }

    vfree(parray);

    return new_page_cnt;
}


static int balloon_try_target(int target)
{
    if ( target < current_pages )
    {
        int change = inflate_balloon(current_pages-target);
        if ( change <= 0 )
            return change;

        current_pages -= change;
        printk(KERN_INFO "Relinquish %dMB to xen. Domain now has %luMB\n",
            change>>PAGE_TO_MB_SHIFT, current_pages>>PAGE_TO_MB_SHIFT);
    }
    else if ( target > current_pages )
    {
        int change, reclaim = min(target,most_seen_pages) - current_pages;

        if ( reclaim )
        {
            change = deflate_balloon( reclaim );
            if ( change <= 0 )
                return change;
            current_pages += change;
            printk(KERN_INFO "Reclaim %dMB from xen. Domain now has %luMB\n",
                change>>PAGE_TO_MB_SHIFT, current_pages>>PAGE_TO_MB_SHIFT);
        }

        if ( most_seen_pages < target )
        {
            int growth = claim_new_pages(target-most_seen_pages);
            if ( growth <= 0 )
                return growth;
            most_seen_pages += growth;
            current_pages += growth;
            printk(KERN_INFO "Granted %dMB new mem. Dom now has %luMB\n",
                growth>>PAGE_TO_MB_SHIFT, current_pages>>PAGE_TO_MB_SHIFT);
        }
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


static int balloon_write(struct file *file, const char *buffer,
                         size_t count, loff_t *offp)
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

    copy_to_user(buffer, priv_bufp, len);

    *offp += len;
    return len;
}

static struct file_operations balloon_fops = {
    .read  = balloon_read,
    .write = balloon_write
};

static int __init balloon_init(void)
{
    printk(KERN_ALERT "Starting Xen Balloon driver\n");

    most_seen_pages = current_pages = min(xen_start_info.nr_pages,max_pfn);
    if ( (balloon_pde = create_xen_proc_entry("memory_target", 0644)) == NULL )
    {
        printk(KERN_ALERT "Unable to create balloon driver proc entry!");
        return -1;
    }

    balloon_pde->owner     = THIS_MODULE;
    balloon_pde->nlink     = 1;
    balloon_pde->proc_fops = &balloon_fops;

    (void)ctrl_if_register_receiver(CMSG_MEM_REQUEST, balloon_ctrlif_rx,
                                    CALLBACK_IN_BLOCKING_CONTEXT);

    /* 
     * make_module a new phys map if mem= says xen can give us memory  to grow
     */
    if ( max_pfn > xen_start_info.nr_pages )
    {
        extern unsigned long *phys_to_machine_mapping;
        unsigned long *newmap;
        newmap = (unsigned long *)vmalloc(max_pfn * sizeof(unsigned long));
        memset(newmap, ~0, max_pfn * sizeof(unsigned long));
        memcpy(newmap, phys_to_machine_mapping,
               xen_start_info.nr_pages * sizeof(unsigned long));
        phys_to_machine_mapping = newmap;
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
