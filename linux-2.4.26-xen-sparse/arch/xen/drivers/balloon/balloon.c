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
#include <asm/xen_proc.h>

#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/smp_lock.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>

#include <asm/hypervisor.h>
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

/* Dead entry written into balloon-owned entries in the PMT. */
#define DEAD 0xdeadbeef

static struct proc_dir_entry *balloon_pde;
unsigned long credit;
static unsigned long current_pages, max_pages;

static inline pte_t *get_ptep(unsigned long addr)
{
    pgd_t *pgd; pmd_t *pmd; pte_t *ptep;
    pgd = pgd_offset_k(addr);

    if ( pgd_none(*pgd) || pgd_bad(*pgd) ) BUG();

    pmd = pmd_offset(pgd, addr);
    if ( pmd_none(*pmd) || pmd_bad(*pmd) ) BUG();

    ptep = pte_offset(pmd, addr);

    return ptep;
}

/* Main function for relinquishing memory. */
static unsigned long inflate_balloon(unsigned long num_pages)
{
    unsigned long *parray;
    unsigned long *currp;
    unsigned long curraddr;
    unsigned long ret = 0;
    unsigned long vaddr;
    unsigned long i, j;

    parray = (unsigned long *)vmalloc(num_pages * sizeof(unsigned long));
    if ( parray == NULL )
    {
        printk("inflate_balloon: Unable to vmalloc parray\n");
        return 0;
    }

    currp = parray;

    for ( i = 0; i < num_pages; i++ )
    {
        /* NB. Should be GFP_ATOMIC for a less aggressive inflation. */
        vaddr = __get_free_page(GFP_KERNEL);

        /* If allocation fails then free all reserved pages. */
        if ( vaddr == 0 )
        {
            printk("Unable to inflate balloon by %ld, only %ld pages free.",
                   num_pages, i);
            currp = parray;
            for(j = 0; j < i; j++){
                free_page(*currp++);
            }
            goto cleanup;
        }

        *currp++ = vaddr;
    }


    currp = parray;
    for ( i = 0; i < num_pages; i++ )
    {
        curraddr = *currp;
        *currp = virt_to_machine(*currp) >> PAGE_SHIFT;
        queue_l1_entry_update(get_ptep(curraddr), 0);
        phys_to_machine_mapping[__pa(curraddr) >> PAGE_SHIFT] = DEAD;
        currp++;
    }

    XEN_flush_page_update_queue();

    ret = HYPERVISOR_dom_mem_op(MEMOP_decrease_reservation, 
                                parray, num_pages);
    if ( unlikely(ret != num_pages) )
    {
        printk("Unable to inflate balloon, error %lx\n", ret);
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
static unsigned long process_new_pages(unsigned long * parray, 
                                       unsigned long num)
{
    /* currently, this function is rather simplistic as 
     * it is assumed that domain reclaims only number of 
     * pages previously released. this is to change soon
     * and the code to extend page tables etc. will be 
     * incorporated here.
     */
     
    unsigned long tot_pages = start_info.nr_pages;   
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
            queue_l1_entry_update(
                get_ptep((unsigned long)__va(i << PAGE_SHIFT)),
                ((*curr) << PAGE_SHIFT) | pgprot_val(PAGE_KERNEL));

            *curr = (unsigned long)__va(i << PAGE_SHIFT);
            curr++;
            num_installed++;
        }
    }

    /*
     * This is tricky (and will also change for machine addrs that 
     * are mapped to not previously released addresses). We free pages
     * that were allocated by get_free_page (the mappings are different 
     * now, of course).
     */
    curr = parray;
    for ( i = 0; i < num_installed; i++ )
    {
        free_page(*curr);
        curr++;
    }

    return num_installed;
}

unsigned long deflate_balloon(unsigned long num_pages)
{
    unsigned long ret;
    unsigned long * parray;

    if ( num_pages > credit )
    {
        printk("Can not allocate more pages than previously released.\n");
        return -EAGAIN;
    }

    parray = (unsigned long *)vmalloc(num_pages * sizeof(unsigned long));
    if ( parray == NULL )
    {
        printk("inflate_balloon: Unable to vmalloc parray\n");
        return 0;
    }

    XEN_flush_page_update_queue();

    ret = HYPERVISOR_dom_mem_op(MEMOP_increase_reservation, 
                                parray, num_pages);
    if ( unlikely(ret != num_pages) )
    {
        printk("Unable to deflate balloon, error %lx\n", ret);
        goto cleanup;
    }

    if ( (ret = process_new_pages(parray, num_pages)) < num_pages )
    {
        printk("Unable to deflate balloon by specified %lx pages, only %lx.\n",
               num_pages, ret);
        goto cleanup;
    }

    ret = num_pages;
    credit -= num_pages;

 cleanup:
    vfree(parray);

    return ret;
}

#define PAGE_TO_MB_SHIFT 8

static int balloon_write(struct file *file, const char *buffer,
                         u_long count, void *data)
{
    char memstring[64], *endchar;
    int len, i;
    unsigned long pages;
    unsigned long long target;

    /* Only admin can play with the balloon :) */
    if ( !capable(CAP_SYS_ADMIN) )
        return -EPERM;

    if (count>sizeof memstring) {
	    return -EFBIG;
    }

    len = strnlen_user(buffer, count);
    if (len==0) return -EBADMSG;
    if (len==1) return 1; /* input starts with a NUL char */
    if ( strncpy_from_user(memstring, buffer, len) < 0)
        return -EFAULT;

    endchar = memstring;
    for(i=0; i<len; ++i,++endchar) {
	    if ('0'>memstring[i] || memstring[i]>'9') break;
    }
    if (i==0) return -EBADMSG;

    target = memparse(memstring,&endchar);
    pages = target >> PAGE_SHIFT;

    if (pages < current_pages) {
	    int change = inflate_balloon(current_pages-pages);
	    if (change<0) return change;

	    current_pages -= change;
    	    printk("Relinquish %dMB to xen. Domain now has %ldMB\n",
		    change>>PAGE_TO_MB_SHIFT, current_pages>>PAGE_TO_MB_SHIFT);
    }
    else if (pages > current_pages) {
	    int change = deflate_balloon(min(pages,max_pages) - current_pages);
	    if (change<0) return change;

	    current_pages += change;
    	    printk("Reclaim %dMB from xen. Domain now has %ldMB\n",
		    change>>PAGE_TO_MB_SHIFT, current_pages>>PAGE_TO_MB_SHIFT);
    }

    return len;
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

static int __init init_module(void)
{
    printk(KERN_ALERT "Starting Xen Balloon driver\n");

    max_pages = current_pages = start_info.nr_pages;
    if ( (balloon_pde = create_xen_proc_entry("memory_target", 0644)) == NULL )
    {
        printk(KERN_ALERT "Unable to create balloon driver proc entry!");
        return -1;
    }

    balloon_pde->write_proc = balloon_write;
    balloon_pde->read_proc = balloon_read;

    return 0;
}

static void __exit cleanup_module(void)
{
    if ( balloon_pde != NULL )
    {
        remove_xen_proc_entry("balloon");
        balloon_pde = NULL;
    }
}

module_init(init_module);
module_exit(cleanup_module);
