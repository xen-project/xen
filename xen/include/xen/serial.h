/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/******************************************************************************
 * serial.h
 * 
 * Driver for 16550-series UARTs. This driver is to be kept within Xen as
 * it permits debugging of seriously-toasted machines (e.g., in situations
 * where a device driver within a guest OS would be inaccessible).
 * 
 * This file contains public definitions. The arch-specific header
 * contains only private hooks, and is not included from this file.
 * 
 * Copyright (c) 2003-2005, K A Fraser
 */

#ifndef __XEN_SERIAL_H__
#define __XEN_SERIAL_H__

#include <asm/regs.h>

/* 'Serial handles' are comprise the following fields. */
#define SERHND_IDX      (1<<0) /* COM1 or COM2?                           */
#define SERHND_HI       (1<<1) /* Mux/demux each transferred char by MSB. */
#define SERHND_LO       (1<<2) /* Ditto, except that the MSB is cleared.  */
#define SERHND_COOKED   (1<<3) /* Newline/carriage-return translation?    */

/* Two-stage initialisation (before/after IRQ-subsystem initialisation). */
void serial_init_stage1(void);
void serial_init_stage2(void);

/* Takes a config string and creates a numeric handle on the COM port. */
int parse_serial_handle(char *conf);

/* Register a character-receive hook on the specified COM port. */
typedef void (*serial_rx_fn)(unsigned char, struct xen_regs *);
void serial_set_rx_handler(int handle, serial_rx_fn fn);

/* Transmit a single character via the specified COM port. */
void serial_putc(int handle, unsigned char c);

/* Transmit a NULL-terminated string via the specified COM port. */
void serial_puts(int handle, const unsigned char *s);

/*
 * An alternative to registering a character-receive hook. This function
 * will not return until a character is available. It can safely be
 * called with interrupts disabled.
 */
unsigned char serial_getc(int handle);
/* 
 * Same as serial_getc but can also be called from interrupt handlers.
 */
unsigned char irq_serial_getc(int handle);

void serial_force_unlock(int handle);

#endif /* __XEN_SERIAL_H__ */
