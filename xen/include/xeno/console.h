/******************************************************************************
 * xeno/console.h
 * 
 * Xen header file concerning console access.
 * 
 * Copyright (c) 2003 James Scott, Intel Research Cambridge
 */

/*
 * Ownership of console --- currently hardwired to dom0. This is used to see 
 * who gets the PS/2 keyboard/mouse events
 */

#define CONSOLE_ISOWNER(p) (p->domain == 0) 
#define CONSOLE_OWNER      (find_domain_by_id(0))


/*
 * Xen output redirection (in common/kernel.c)
 *
 * This is coarsely done right now - 
 *  - a boot-time option for console output
 *  - a compile-time option for serial output and console output
 *
 * Really, when starting up a guest os with console privilege, we should:
 *  - reset the video to a known state
 *  - stop sending characters (clear 'opt_console')
 *  - allow the guest os access to the video RAM area and keyboard
 * Similarly, when stopping that guest os, we should:
 *  - stop allowing the guest os access to video RAM
 *  - reset the video to a known state
 *  - start sending it console output again (if we so desire)
 *
 * Resetting the video to a known state has not been explored yet, although
 * Xen resets to a VGA text mode at start of day. Also, the notion of
 * privileges for guest os's (e.g. console privilege) has not been explored
 * yet, so this will do for now.
 */

#define CONFIG_OUTPUT_SERIAL  1
#define CONFIG_OUTPUT_CONSOLE 1
#define CONFIG_OUTPUT_CONSOLE_RING 1

extern int opt_console;

#define CONSOLE_RING_SIZE     16392

typedef struct console_ring_st
{
    char buf[CONSOLE_RING_SIZE];
    unsigned int len;
} console_ring_t;

console_ring_t console_ring;

void init_console_ring();
long read_console_ring(char *str, unsigned int count);
