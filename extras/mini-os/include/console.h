/* 
 ****************************************************************************
 * (C) 2006 - Grzegorz Milos - Cambridge University
 ****************************************************************************
 *
 *        File: console.h
 *      Author: Grzegorz Milos
 *     Changes: 
 *              
 *        Date: Mar 2006
 * 
 * Environment: Xen Minimal OS
 * Description: Console interface.
 *
 * Handles console I/O. Defines printk.
 *
 ****************************************************************************
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
#ifndef _LIB_CONSOLE_H_
#define _LIB_CONSOLE_H_

#include<os.h>
#include<traps.h>
#include<stdarg.h>

void print(int direct, const char *fmt, va_list args);
void printk(const char *fmt, ...);
void xprintk(const char *fmt, ...);

#define tprintk(_fmt, _args...) printk("[%s] " _fmt, current->name, ##_args) 

void xencons_rx(char *buf, unsigned len, struct pt_regs *regs);
void xencons_tx(void);

void init_console(void);
void console_print(char *data, int length);
void fini_console(void);

/* Low level functions defined in xencons_ring.c */
extern struct wait_queue_head console_queue;
int xencons_ring_init(void);
int xencons_ring_send(const char *data, unsigned len);
int xencons_ring_send_no_notify(const char *data, unsigned len);
int xencons_ring_avail(void);
int xencons_ring_recv(char *data, unsigned len);


#endif /* _LIB_CONSOLE_H_ */
