/******************************************************************************
 * kernel.c
 * 
 * Assorted crap goes here, including the initial C entry point, jumped at
 * from head.S.
 * 
 * Copyright (c) 2002-2003, K A Fraser & R Neugebauer
 * Copyright (c) 2005, Grzegorz Milos, Intel Research Cambridge
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 */

#include <os.h>
#include <hypervisor.h>
#include <mm.h>
#include <events.h>
#include <time.h>
#include <types.h>
#include <lib.h>
#include <sched.h>
#include <xenbus.h>
#include "xenbus/xenbus_comms.h"

/*
 * Shared page for communicating with the hypervisor.
 * Events flags go here, for example.
 */
shared_info_t *HYPERVISOR_shared_info;

/*
 * This structure contains start-of-day info, such as pagetable base pointer,
 * address of the shared_info structure, and things like that.
 */
union start_info_union start_info_union;

/*
 * Just allocate the kernel stack here. SS:ESP is set up to point here
 * in head.S.
 */
char stack[8192];


/* Assembler interface fns in entry.S. */
void hypervisor_callback(void);
void failsafe_callback(void);

extern char shared_info[PAGE_SIZE];

#define __pte(x) ((pte_t) { (x) } )

static shared_info_t *map_shared_info(unsigned long pa)
{
    if ( HYPERVISOR_update_va_mapping(
        (unsigned long)shared_info, __pte(pa | 7), UVMF_INVLPG) )
    {
        printk("Failed to map shared_info!!\n");
        *(int*)0=0;
    }
    return (shared_info_t *)shared_info;
}


/*
 * INITIAL C ENTRY POINT.
 */
void start_kernel(start_info_t *si)
{
    static char hello[] = "Bootstrapping...\n";
    (void)HYPERVISOR_console_io(CONSOLEIO_write, strlen(hello), hello);

    /* Copy the start_info struct to a globally-accessible area. */
    memcpy(&start_info, si, sizeof(*si));

    /* Grab the shared_info pointer and put it in a safe place. */
    HYPERVISOR_shared_info = map_shared_info(start_info.shared_info);

    /* Set up event and failsafe callback addresses. */
#ifdef __i386__
    HYPERVISOR_set_callbacks(
        __KERNEL_CS, (unsigned long)hypervisor_callback,
        __KERNEL_CS, (unsigned long)failsafe_callback);
#else
    HYPERVISOR_set_callbacks(
        (unsigned long)hypervisor_callback,
        (unsigned long)failsafe_callback, 0);
#endif
    trap_init();

    /* ENABLE EVENT DELIVERY. This is disabled at start of day. */
    __sti();
    
    /* print out some useful information  */
    printk("Xen Minimal OS!\n");
    printk("start_info:   %p\n",    si);
    printk("  nr_pages:   %lu",     si->nr_pages);
    printk("  shared_inf: %08lx\n", si->shared_info);
    printk("  pt_base:    %p",      (void *)si->pt_base); 
    printk("  mod_start:  0x%lx\n", si->mod_start);
    printk("  mod_len:    %lu\n",   si->mod_len); 
    printk("  flags:      0x%x\n",  (unsigned int)si->flags);
    printk("  cmd_line:   %s\n",  
           si->cmd_line ? (const char *)si->cmd_line : "NULL");


    /*
     * If used for porting another OS, start here to figure out your
     * guest os entry point. Otherwise continue below...
     */
    /* init memory management */
    init_mm();

    /* set up events */
    init_events();
    /* init time and timers */
    init_time();
    
    /* init scheduler */
    init_sched();

    /* init xenbus */
    xs_init();
    
    /* Everything initialised, start idle thread */
    run_idle_thread();
}


/*
 * do_exit: This is called whenever an IRET fails in entry.S.
 * This will generally be because an application has got itself into
 * a really bad state (probably a bad CS or SS). It must be killed.
 * Of course, minimal OS doesn't have applications :-)
 */

void do_exit(void)
{
    printk("do_exit called!\n");
    for ( ;; ) HYPERVISOR_sched_op(SCHEDOP_shutdown, SHUTDOWN_crash);
}
