/******************************************************************************
 * xen/console.h
 * 
 * Xen header file concerning console access.
 */

#ifndef __CONSOLE_H__
#define __CONSOLE_H__

#include <xen/spinlock.h>

extern spinlock_t console_lock;

void set_printk_prefix(const char *prefix);

#define CONSOLE_RING_CLEAR 1
long read_console_ring(unsigned long, unsigned int, unsigned int);

void init_console(void);
void console_endboot(int disable_vga);

void console_force_unlock(void);
void console_force_lock(void);

void console_putc(char c);
int console_getc(void);
int irq_console_getc(void);

#endif /* __CONSOLE_H__ */
