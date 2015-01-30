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

#include <mini-os/os.h>
#include <mini-os/kernel.h>
#include <mini-os/hypervisor.h>
#include <mini-os/mm.h>
#include <mini-os/events.h>
#include <mini-os/time.h>
#include <mini-os/types.h>
#include <mini-os/lib.h>
#include <mini-os/sched.h>
#include <mini-os/xenbus.h>
#include <mini-os/gnttab.h>
#include <mini-os/netfront.h>
#include <mini-os/blkfront.h>
#include <mini-os/fbfront.h>
#include <mini-os/pcifront.h>
#include <mini-os/xmalloc.h>
#include <fcntl.h>
#include <xen/features.h>
#include <xen/version.h>

uint8_t xen_features[XENFEAT_NR_SUBMAPS * 32];

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

#ifdef CONFIG_XENBUS
/* This should be overridden by the application we are linked against. */
__attribute__((weak)) void app_shutdown(unsigned reason)
{
    struct sched_shutdown sched_shutdown = { .reason = reason };
    printk("Shutdown requested: %d\n", reason);
    HYPERVISOR_sched_op(SCHEDOP_shutdown, &sched_shutdown);
}

static void shutdown_thread(void *p)
{
    const char *path = "control/shutdown";
    const char *token = path;
    xenbus_event_queue events = NULL;
    char *shutdown = NULL, *err;
    unsigned int shutdown_reason;
    xenbus_watch_path_token(XBT_NIL, path, token, &events);
    while ((err = xenbus_read(XBT_NIL, path, &shutdown)) != NULL || !strcmp(shutdown, ""))
    {
        free(err);
        free(shutdown);
        shutdown = NULL;
        xenbus_wait_for_watch(&events);
    }
    err = xenbus_unwatch_path_token(XBT_NIL, path, token);
    free(err);
    err = xenbus_write(XBT_NIL, path, "");
    free(err);
    printk("Shutting down (%s)\n", shutdown);

    if (!strcmp(shutdown, "poweroff"))
        shutdown_reason = SHUTDOWN_poweroff;
    else if (!strcmp(shutdown, "reboot"))
        shutdown_reason = SHUTDOWN_reboot;
    else
        /* Unknown */
        shutdown_reason = SHUTDOWN_crash;
    app_shutdown(shutdown_reason);
    free(shutdown);
}
#endif


/* This should be overridden by the application we are linked against. */
__attribute__((weak)) int app_main(start_info_t *si)
{
    printk("kernel.c: dummy main: start_info=%p\n", si);
    return 0;
}

void start_kernel(void)
{
    /* Set up events. */
    init_events();

    /* ENABLE EVENT DELIVERY. This is disabled at start of day. */
    local_irq_enable();

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

#ifdef CONFIG_XENBUS
    create_thread("shutdown", shutdown_thread, NULL);
#endif

    /* Call (possibly overridden) app_main() */
    app_main(&start_info);

    /* Everything initialised, start idle thread */
    run_idle_thread();
}

void stop_kernel(void)
{
    /* TODO: fs import */

    local_irq_disable();

    /* Reset grant tables */
    fini_gnttab();

    /* Reset XenBus */
    fini_xenbus();

    /* Reset timers */
    fini_time();

    /* Reset memory management. */
    fini_mm();

    /* Reset events. */
    fini_events();

    /* Reset arch details */
    arch_fini();
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
    arch_do_exit();
    for( ;; )
    {
        struct sched_shutdown sched_shutdown = { .reason = SHUTDOWN_crash };
        HYPERVISOR_sched_op(SCHEDOP_shutdown, &sched_shutdown);
    }
}
