/******************************************************************************
 * kernel.c
 * 
 * Assorted crap goes here, including the initial C entry point, jumped at
 * from head.S.
 */

#include <os.h>
#include <hypervisor.h>
#include <mm.h>
#include <events.h>
#include <time.h>
#include <types.h>
#include <lib.h>

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

/* default event handlers */
static void exit_handler(int ev, struct pt_regs *regs);
static void debug_handler(int ev, struct pt_regs *regs);


/*
 * INITIAL C ENTRY POINT.
 */
void start_kernel(start_info_t *si)
{
    int i;

    /* Copy the start_info struct to a globally-accessible area. */
    memcpy(&start_info, si, sizeof(*si));

    /* Grab the shared_info pointer and put it in a safe place. */
    HYPERVISOR_shared_info = start_info.shared_info;

    /* Set up event and failsafe callback addresses. */
    HYPERVISOR_set_callbacks(
        __KERNEL_CS, (unsigned long)hypervisor_callback,
        __KERNEL_CS, (unsigned long)failsafe_callback);


    trap_init();


    /* ENABLE EVENT DELIVERY. This is disabled at start of day. */
    __sti();
    
    /* print out some useful information  */
    printk("Xeno Minimal OS!\n");
    printk("start_info:   %p\n",  si);
    printk("  nr_pages:   %lu",   si->nr_pages);
    printk("  shared_inf: %p\n",  si->shared_info);
    printk("  pt_base:    %p",    (void *)si->pt_base); 
    printk("  mod_start:  0x%lx\n", si->mod_start);
    printk("  mod_len:    %lu\n", si->mod_len); 
    printk("  net_rings: ");
    for (i = 0; i < MAX_DOMAIN_VIFS; i++) {
        printk(" %lx", si->net_rings[i]);
    }; printk("\n");
    printk("  blk_ring:   0x%lx\n", si->blk_ring);
    printk("  dom_id:     %d\n",  si->dom_id);
    printk("  flags:      0x%lx\n", si->flags);
    printk("  cmd_line:   %s\n",  si->cmd_line ? (const char *)si->cmd_line : "NULL");


    /*
     * If used for porting another OS, start here to figure out your
     * guest os entry point. Otherwise continue below...
     */

    /* init memory management */
    init_mm();

    /* set up events */
    init_events();

    /* install some handlers */
    add_ev_action(EV_DIE, &exit_handler);
    enable_ev_action(EV_DIE);
    enable_hypervisor_event(EV_DIE);

    add_ev_action(EV_DEBUG, &debug_handler);
    enable_ev_action(EV_DEBUG);
    enable_hypervisor_event(EV_DEBUG);

    /* init time and timers */
    init_time();

    /* do nothing */
    for ( ; ; ) HYPERVISOR_yield();
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
    for ( ;; ) ;
}
static void exit_handler(int ev, struct pt_regs *regs) {
    do_exit();
}

/*
 * a debug handler to print out some state from the guest
 */
static void debug_handler(int ev, struct pt_regs *regs) {
    dump_regs(regs);
}
