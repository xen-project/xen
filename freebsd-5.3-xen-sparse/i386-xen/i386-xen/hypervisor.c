/******************************************************************************
 * hypervisor.c
 * 
 * Communication to/from hypervisor.
 * 
 * Copyright (c) 2002-2003, K A Fraser
 * 
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
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIEAS OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 */

#include <machine/xen-os.h>
#include <machine/hypervisor.h>
#include <machine/xenvar.h>
#include <machine/multicall.h>

/* XXX need to verify what the caller save registers are on x86 KMM */
#define CALLER_SAVE __asm__("pushal; ")
#define CALLER_RESTORE __asm__("popal;")


/* ni == non-inline - these are only intended for use from assembler
 * no reason to have them in a header - 
 *
 */
void ni_queue_multicall0(unsigned long op); 
void ni_queue_multicall1(unsigned long op, unsigned long arg1); 
void ni_queue_multicall2(unsigned long op, unsigned long arg1,
			 unsigned long arg2); 
void ni_queue_multicall3(unsigned long op, unsigned long arg1,
			 unsigned long arg2, unsigned long arg3); 
void ni_queue_multicall4(unsigned long op, unsigned long arg1,
			 unsigned long arg2, unsigned long arg4,
			 unsigned long arg5); 

void ni_execute_multicall_list(void);

multicall_entry_t multicall_list[MAX_MULTICALL_ENTS];
int nr_multicall_ents = 0;


void 
ni_queue_multicall0(unsigned long op) 
{
    CALLER_SAVE;
    queue_multicall0(op);
    CALLER_RESTORE;
}

void 
ni_queue_multicall1(unsigned long op, unsigned long arg1) 
{
    CALLER_SAVE;
    queue_multicall1(op, arg1);
    CALLER_RESTORE;
}

void 
ni_queue_multicall2(unsigned long op, unsigned long arg1, 
		    unsigned long arg2) 
{
    CALLER_SAVE;
    queue_multicall2(op, arg1, arg2);
    CALLER_RESTORE;
}

void 
ni_queue_multicall3(unsigned long op, unsigned long arg1, 
		    unsigned long arg2, unsigned long arg3) 
{
    CALLER_SAVE;
    queue_multicall3(op, arg1, arg2, arg3);
    CALLER_RESTORE;
}

void 
ni_queue_multicall4(unsigned long op, unsigned long arg1,
		    unsigned long arg2, unsigned long arg3,
		    unsigned long arg4) 
{
    CALLER_SAVE;    
    queue_multicall4(op, arg1, arg2, arg3, arg4);
    CALLER_RESTORE;
}

void
ni_execute_multicall_list(void)
{
    CALLER_SAVE;
    execute_multicall_list();
    CALLER_RESTORE;
}
