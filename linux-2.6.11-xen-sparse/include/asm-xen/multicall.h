/******************************************************************************
 * multicall.h
 * 
 * Copyright (c) 2003-2004, K A Fraser
 * 
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef __MULTICALL_H__
#define __MULTICALL_H__

#include <asm-xen/hypervisor.h>

extern multicall_entry_t multicall_list[];
extern int nr_multicall_ents;

static inline void queue_multicall0(unsigned long op)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    nr_multicall_ents = i+1;
}

static inline void queue_multicall1(unsigned long op, unsigned long arg1)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    multicall_list[i].args[0] = arg1;
    nr_multicall_ents = i+1;
}

static inline void queue_multicall2(
    unsigned long op, unsigned long arg1, unsigned long arg2)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    multicall_list[i].args[0] = arg1;
    multicall_list[i].args[1] = arg2;
    nr_multicall_ents = i+1;
}

static inline void queue_multicall3(
    unsigned long op, unsigned long arg1, unsigned long arg2,
    unsigned long arg3)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    multicall_list[i].args[0] = arg1;
    multicall_list[i].args[1] = arg2;
    multicall_list[i].args[2] = arg3;
    nr_multicall_ents = i+1;
}

static inline void queue_multicall4(
    unsigned long op, unsigned long arg1, unsigned long arg2,
    unsigned long arg3, unsigned long arg4)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    multicall_list[i].args[0] = arg1;
    multicall_list[i].args[1] = arg2;
    multicall_list[i].args[2] = arg3;
    multicall_list[i].args[3] = arg4;
    nr_multicall_ents = i+1;
}

static inline void queue_multicall5(
    unsigned long op, unsigned long arg1, unsigned long arg2,
    unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    int i = nr_multicall_ents;
    multicall_list[i].op      = op;
    multicall_list[i].args[0] = arg1;
    multicall_list[i].args[1] = arg2;
    multicall_list[i].args[2] = arg3;
    multicall_list[i].args[3] = arg4;
    multicall_list[i].args[4] = arg5;
    nr_multicall_ents = i+1;
}

static inline void execute_multicall_list(void)
{
    if ( unlikely(nr_multicall_ents == 0) ) return;
    (void)HYPERVISOR_multicall(multicall_list, nr_multicall_ents);
    nr_multicall_ents = 0;
}

#endif /* __MULTICALL_H__ */
