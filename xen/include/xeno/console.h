/******************************************************************************
 * xeno/console.h
 * 
 * Xen header file concerning console access.
 * 
 * Copyright (c) 2003 James Scott, Intel Research Cambridge
 */

#ifndef __CONSOLE_H__
#define __CONSOLE_H__

/*
 * Ownership of console --- currently hardwired to dom0. This is used to see 
 * who gets the PS/2 keyboard/mouse events
 */

extern int sercon_handle;
extern int vgacon_enabled;

#define CONSOLE_ISOWNER(p) (p->domain == 0) 
#define CONSOLE_OWNER      (find_domain_by_id(0))

#define CONSOLE_RING_SIZE	16392
#define CONSOLE_RING_CLEAR	1

typedef struct console_ring_st
{
    char buf[CONSOLE_RING_SIZE];
    unsigned int len;
} console_ring_t;

extern console_ring_t console_ring;

long read_console_ring(unsigned long, unsigned int, unsigned int);

#endif
