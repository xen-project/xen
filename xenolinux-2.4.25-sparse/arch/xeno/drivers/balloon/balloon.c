/******************************************************************************
 * balloon.c
 *
 * Xeno balloon driver - enables returning/claiming memory to/from xen
 *
 * Copyright (c) 2003, B Dragovic
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <asm/xeno_proc.h>

#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/smp_lock.h>
#include <linux/pagemap.h>

#include <asm/hypervisor.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>

#include <asm/hypervisor-ifs/dom_mem_ops.h>

/* USER DEFINES -- THESE SHOULD BE COPIED TO USER-SPACE TOOLS */
#define USER_INFLATE_BALLOON  1   /* return mem to hypervisor */
#define USER_DEFLATE_BALLOON  2   /* claim mem from hypervisor */
typedef struct user_balloon_op {
    unsigned int  op;
    unsigned long size;
} user_balloon_op_t;
/* END OF USER DEFINE */

/* Dead entry written into ballon-owned entries in the PMT. */
#define DEAD 0xdeadbeef

static struct proc_dir_entry *balloon_pde;
unsigned long credit;

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

/* main function for relinquishing bit of memory */
static unsigned long inflate_balloon(unsigned long num_pages)
{
    dom_mem_op_t dom_mem_op;
    unsigned long *parray;
    unsigned long *currp;
    unsigned long curraddr;
    unsigned long ret = 0;
    unsigned long vaddr;
    unsigned long i, j;

    parray = (unsigned long *)kmalloc(num_pages *
                                      sizeof(unsigned long), GFP_KERNEL);
    currp = parray;

    for ( i = 0; i < num_pages; i++ )
    {
        /* try to obtain a free page, has to be done with GFP_ATOMIC
         * as we do not want to sleep indefinately.
         */
        vaddr = __get_free_page(GFP_ATOMIC);

        /* if allocation fails, free all reserved pages */
        if(!vaddr){
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

    XENO_flush_page_update_queue();

    dom_mem_op.op = MEMOP_RESERVATION_DECREASE;
    dom_mem_op.u.decrease.size  = num_pages;
    dom_mem_op.u.decrease.pages = parray;
    if ( (ret = HYPERVISOR_dom_mem_op(&dom_mem_op)) != num_pages )
    {
        printk("Unable to inflate balloon, error %lx\n", ret);
        goto cleanup;
    }

    credit += num_pages;
    ret = num_pages;

 cleanup:
    kfree(parray);

    return ret;
}

/* install new mem pages obtained by deflate_balloon. function walks 
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
            queue_l1_entry_update(
                (pte_t *)((i << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE), i);
            queue_l1_entry_update(
                get_ptep((unsigned long)__va(i << PAGE_SHIFT)),
                ((*curr) << PAGE_SHIFT) | pgprot_val(PAGE_KERNEL));

            *curr = (unsigned long)__va(i << PAGE_SHIFT);
            curr++;
            num_installed++;
        }
    }

    /* now, this is tricky (and will also change for machine addrs that 
      * are mapped to not previously released addresses). we free pages
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
    dom_mem_op_t dom_mem_op;
    unsigned long ret;
    unsigned long * parray;

    printk(KERN_ALERT "bd240 debug: deflate balloon called for %lx pages\n", num_pages);

    if ( num_pages > credit )
    {
        printk("Can not allocate more pages than previously released.\n");
        return -EAGAIN;
    }

    parray = (unsigned long *)kmalloc(num_pages * sizeof(unsigned long), 
                                      GFP_KERNEL);

    dom_mem_op.op = MEMOP_RESERVATION_INCREASE;
    dom_mem_op.u.increase.size = num_pages;
    dom_mem_op.u.increase.pages = parray;
    if((ret = HYPERVISOR_dom_mem_op(&dom_mem_op)) != num_pages){
        printk("Unable to deflate balloon, error %lx\n", ret);
        goto cleanup;
    }

    if((ret = process_new_pages(parray, num_pages)) < num_pages){
        printk("Unable to deflate balloon by specified %lx pages, only %lx.\n",
               num_pages, ret);
        goto cleanup;
    }

    ret = num_pages;
    credit -= num_pages;

 cleanup:
    kfree(parray);

    return ret;
}

static int balloon_write(struct file *file, const char *buffer,
                         u_long count, void *data)
{
    user_balloon_op_t bop;

    /* Only admin can play with the balloon :) */
    if ( !capable(CAP_SYS_ADMIN) )
        return -EPERM;

    if ( copy_from_user(&bop, buffer, sizeof(bop)) )
        return -EFAULT;

    switch ( bop.op )
    {
    case USER_INFLATE_BALLOON:
        if ( inflate_balloon(bop.size) < bop.size )
            return -EAGAIN;
        break;
        
    case USER_DEFLATE_BALLOON:
        deflate_balloon(bop.size);
        break;

    default:
        printk("Unknown command to balloon driver.");
        return -EFAULT;
    }

    return sizeof(bop);
}

/*
 * main balloon driver initialization function.
 */
static int __init init_module(void)
{
    printk(KERN_ALERT "Starting Xeno Balloon driver\n");

    credit = 0;

    balloon_pde = create_xeno_proc_entry("balloon", 0600);
    if ( balloon_pde == NULL )
    {
        printk(KERN_ALERT "Unable to create balloon driver proc entry!");
        return -1;
    }

    balloon_pde->write_proc = balloon_write;

    return 0;
}

static void __exit cleanup_module(void)
{
    if ( balloon_pde != NULL )
    {
        remove_xeno_proc_entry("balloon");
        balloon_pde = NULL;
    }
}

module_init(init_module);
module_exit(cleanup_module);


