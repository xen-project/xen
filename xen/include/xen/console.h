/******************************************************************************
 * xen/console.h
 * 
 * Xen header file concerning console access.
 * 
 * Copyright (c) 2003 James Scott, Intel Research Cambridge
 */

#ifndef __CONSOLE_H__
#define __CONSOLE_H__

#include <xen/spinlock.h>

extern spinlock_t console_lock;

/*
 * Ownership of console --- currently hardwired to dom0. This is used to see 
 * who gets the PS/2 keyboard/mouse events
 */
#define CONSOLE_ISOWNER(p) (p->domain == 0) 
#define CONSOLE_OWNER      (find_domain_by_id(0))

void set_printk_prefix(const char *prefix);

#define CONSOLE_RING_CLEAR 1
long read_console_ring(unsigned long, unsigned int, unsigned int);

void init_console(void);
void console_endboot(int disable_vga);

#endif
