/******************************************************************************
 * xen/console.h
 * 
 * Xen header file concerning console access.
 */

#ifndef __CONSOLE_H__
#define __CONSOLE_H__

#include <xen/spinlock.h>
#include <xen/guest_access.h>
#include <public/xen.h>

void set_printk_prefix(const char *prefix);

long read_console_ring(XEN_GUEST_HANDLE(char), u32 *, int);

void init_console(void);
void console_endboot(void);

int fill_console_start_info(struct dom0_vga_console_info *);

void console_force_unlock(void);
void console_force_lock(void);

void console_start_sync(void);
void console_end_sync(void);

/*
 * Steal output from the console. Returns +ve identifier, else -ve error.
 * Takes the handle of the serial line to steal, and steal callback function.
 */
int console_steal(int handle, void (*fn)(const char *));

/* Give back stolen console. Takes the identifier returned by console_steal. */
void console_giveback(int id);

#endif /* __CONSOLE_H__ */
