// <xeno/console.h> - Xen header file concerning console access
// Copyright (c) 2003 James Scott, Intel Research Cambridge

// ownership of console - current defaulting to dom0
// this is currently used to see who gets the PS/2 keyboard/mouse events
#define CONSOLE_ISOWNER(p) (p->domain == 0) 
#define CONSOLE_OWNER find_domain_by_id(0) 


// Xen output redirection (in common/kernel.c!)
//
// This is coarsely done right now - 
//   a boot-time option for console output
//   a compile-time option for serial output
//
// Really, when starting up a guest os with console privilege, we should:
//  - reset the video to a known state
//  - stop sending characters (use global var opt_console)
//  - allow the guest os access to the video RAM area (instead of the coarse IOPL hack nowadays) and keyboard (see above)
// Similarly, when stopping that guest os, we should:
//  - stop allowing the guest os access to video RAM
//  - reset the video to a known state
//  - start sending it console output again (if we so desire)
//
// resetting the video to a known state has not been explored yet
// the notion of privileges for guest os's (e.g. console privilege) has not been explored yet
// so this will do for now

#define CONFIG_OUTPUT_CONSOLE 1 // but see also opt_console
#define CONFIG_OUTPUT_SERIAL  1

extern int opt_console;
