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
 
#include <types.h>
#include <wait.h>
#include <mm.h>
#include <hypervisor.h>
#include <events.h>
#include <os.h>
#include <lib.h>
#include <xenbus.h>
#include <xen/io/console.h>


/* Low level functions defined in xencons_ring.c */
extern int xencons_ring_init(void);
extern int xencons_ring_send(const char *data, unsigned len);
extern int xencons_ring_send_no_notify(const char *data, unsigned len);


/* If console not initialised the printk will be sent to xen serial line 
   NOTE: you need to enable verbose in xen/Rules.mk for it to work. */
static int console_initialised = 0;


void xencons_rx(char *buf, unsigned len, struct pt_regs *regs)
{
    if(len > 0)
    {
        /* Just repeat what's written */
        buf[len] = '\0';
        printk("%s", buf);
        
        if(buf[len-1] == '\r')
            printk("\nNo console input handler.\n");
    }
}

void xencons_tx(void)
{
    /* Do nothing, handled by _rx */
}


void console_print(char *data, int length)
{
    char *curr_char, saved_char;
    int part_len;
    int (*ring_send_fn)(const char *data, unsigned length);

    if(!console_initialised)
        ring_send_fn = xencons_ring_send_no_notify;
    else
        ring_send_fn = xencons_ring_send;
        
    for(curr_char = data; curr_char < data+length-1; curr_char++)
    {
        if(*curr_char == '\n')
        {
            saved_char = *(curr_char+1);
            *(curr_char+1) = '\r';
            part_len = curr_char - data + 2;
            ring_send_fn(data, part_len);
            *(curr_char+1) = saved_char;
            data = curr_char+1;
            length -= part_len - 1;
        }
    }
    
    ring_send_fn(data, length);
    
    if(data[length-1] == '\n')
        ring_send_fn("\r", 1);
}

void print(int direct, const char *fmt, va_list args)
{
    static char   buf[1024];
    
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
 
    if(direct)
    {
        (void)HYPERVISOR_console_io(CONSOLEIO_write, strlen(buf), buf);
        return;
    }
    
    if(!console_initialised)
        (void)HYPERVISOR_console_io(CONSOLEIO_write, strlen(buf), buf);
        
    console_print(buf, strlen(buf));
}

void printk(const char *fmt, ...)
{
    va_list       args;
    va_start(args, fmt);
    print(0, fmt, args);
    va_end(args);        
}

void xprintk(const char *fmt, ...)
{
    va_list       args;
    va_start(args, fmt);
    print(1, fmt, args);
    va_end(args);        
}
void init_console(void)
{   
    printk("Initialising console ... ");
    xencons_ring_init();    
    console_initialised = 1;
    /* This is also required to notify the daemon */
    printk("done.\n");
}
