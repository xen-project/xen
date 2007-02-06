/******************************************************************************
 * kernel.c
 * 
 * Assorted crap goes here, including the initial C entry point, jumped at
 * from head.S.
 * 
 * Copyright (c) 2002-2003, K A Fraser & R Neugebauer
 * Copyright (c) 2005, Grzegorz Milos, Intel Research Cambridge
 * Copyright (c) 2006, Robert Kaiser, FH Wiesbaden
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
#include <gnttab.h>
#include <netfront.h>
#include <xen/features.h>
#include <xen/version.h>


u8 xen_features[XENFEAT_NR_SUBMAPS * 32];

void setup_xen_features(void)
{
    xen_feature_info_t fi;
    int i, j;

    for (i = 0; i < XENFEAT_NR_SUBMAPS; i++) 
    {
        fi.submap_idx = i;
        if (HYPERVISOR_xen_version(XENVER_get_features, &fi) < 0)
            break;
        
        for (j=0; j<32; j++)
            xen_features[i*32+j] = !!(fi.submap & 1<<j);
    }
}

void test_xenbus(void);

static void xenbus_tester(void *p)
{
    printk("Xenbus tests disabled, because of a Xend bug.\n");
    /* test_xenbus(); */
}

static void periodic_thread(void *p)
{
    struct timeval tv;
    printk("Periodic thread started.\n");
    for(;;)
    {
        gettimeofday(&tv);
        printk("T(s=%ld us=%ld)\n", tv.tv_sec, tv.tv_usec);
        sleep(1000);
    }
}

static void netfront_thread(void *p)
{
    init_netfront(&start_info);
}

/* This should be overridden by the application we are linked against. */
__attribute__((weak)) int app_main(start_info_t *si)
{
    printk("Dummy main: start_info=%p\n", si);
    create_thread("xenbus_tester", xenbus_tester, si);
    create_thread("periodic_thread", periodic_thread, si);
    create_thread("netfront", netfront_thread, si);
    return 0;
}

/*
 * INITIAL C ENTRY POINT.
 */
void start_kernel(start_info_t *si)
{
    static char hello[] = "Bootstrapping...\n";

    (void)HYPERVISOR_console_io(CONSOLEIO_write, strlen(hello), hello);

    arch_init(si);

    trap_init();

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

    /* Set up events. */
    init_events();
    
    /* ENABLE EVENT DELIVERY. This is disabled at start of day. */
    __sti();

    arch_print_info();

    setup_xen_features();

    /* Init memory management. */
    init_mm();

    /* Init time and timers. */
    init_time();

    /* Init the console driver. */
    init_console();

    /* Init grant tables */
    init_gnttab();
    
    /* Init scheduler. */
    init_sched();
 
    /* Init XenBus */
    init_xenbus();

    /* Call (possibly overridden) app_main() */
    app_main(&start_info);

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
    printk("Do_exit called!\n");
    for( ;; )
    {
        struct sched_shutdown sched_shutdown = { .reason = SHUTDOWN_crash };
        HYPERVISOR_sched_op(SCHEDOP_shutdown, &sched_shutdown);
    }
}
