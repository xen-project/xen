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

DECLARE_PER_CPU(multicall_entry_t, multicall_list[]);
DECLARE_PER_CPU(int, nr_multicall_ents);

static inline void queue_multicall0(unsigned long op)
{
    int cpu = smp_processor_id();
    int i = per_cpu(nr_multicall_ents, cpu);
    per_cpu(multicall_list[i], cpu).op      = op;
    per_cpu(nr_multicall_ents, cpu) = i+1;
}

static inline void queue_multicall1(unsigned long op, unsigned long arg1)
{
    int cpu = smp_processor_id();
    int i = per_cpu(nr_multicall_ents, cpu);
    per_cpu(multicall_list[i], cpu).op      = op;
    per_cpu(multicall_list[i], cpu).args[0] = arg1;
    per_cpu(nr_multicall_ents, cpu) = i+1;
}

static inline void queue_multicall2(
    unsigned long op, unsigned long arg1, unsigned long arg2)
{
    int cpu = smp_processor_id();
    int i = per_cpu(nr_multicall_ents, cpu);
    per_cpu(multicall_list[i], cpu).op      = op;
    per_cpu(multicall_list[i], cpu).args[0] = arg1;
    per_cpu(multicall_list[i], cpu).args[1] = arg2;
    per_cpu(nr_multicall_ents, cpu) = i+1;
}

static inline void queue_multicall3(
    unsigned long op, unsigned long arg1, unsigned long arg2,
    unsigned long arg3)
{
    int cpu = smp_processor_id();
    int i = per_cpu(nr_multicall_ents, cpu);
    per_cpu(multicall_list[i], cpu).op      = op;
    per_cpu(multicall_list[i], cpu).args[0] = arg1;
    per_cpu(multicall_list[i], cpu).args[1] = arg2;
    per_cpu(multicall_list[i], cpu).args[2] = arg3;
    per_cpu(nr_multicall_ents, cpu) = i+1;
}

static inline void queue_multicall4(
    unsigned long op, unsigned long arg1, unsigned long arg2,
    unsigned long arg3, unsigned long arg4)
{
    int cpu = smp_processor_id();
    int i = per_cpu(nr_multicall_ents, cpu);
    per_cpu(multicall_list[i], cpu).op      = op;
    per_cpu(multicall_list[i], cpu).args[0] = arg1;
    per_cpu(multicall_list[i], cpu).args[1] = arg2;
    per_cpu(multicall_list[i], cpu).args[2] = arg3;
    per_cpu(multicall_list[i], cpu).args[3] = arg4;
    per_cpu(nr_multicall_ents, cpu) = i+1;
}

static inline void queue_multicall5(
    unsigned long op, unsigned long arg1, unsigned long arg2,
    unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    int cpu = smp_processor_id();
    int i = per_cpu(nr_multicall_ents, cpu);
    per_cpu(multicall_list[i], cpu).op      = op;
    per_cpu(multicall_list[i], cpu).args[0] = arg1;
    per_cpu(multicall_list[i], cpu).args[1] = arg2;
    per_cpu(multicall_list[i], cpu).args[2] = arg3;
    per_cpu(multicall_list[i], cpu).args[3] = arg4;
    per_cpu(multicall_list[i], cpu).args[4] = arg5;
    per_cpu(nr_multicall_ents, cpu) = i+1;
}

static inline void execute_multicall_list(void)
{
    int cpu = smp_processor_id();
    if ( unlikely(per_cpu(nr_multicall_ents, cpu) == 0) ) return;
    (void)HYPERVISOR_multicall(&per_cpu(multicall_list[0], cpu),
			       per_cpu(nr_multicall_ents, cpu));
    per_cpu(nr_multicall_ents, cpu) = 0;
}

#endif /* __MULTICALL_H__ */
