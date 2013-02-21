/******************************************************************************
 * hypercall.h
 * 
 * Copyright (c) 2002-2006, K A Fraser
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
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

#ifndef __HVMLOADER_HYPERCALL_H__
#define __HVMLOADER_HYPERCALL_H__

#include <stdint.h>
#include <xen/xen.h>
#include "config.h"

#define hcall_addr(name)                                                \
    ((unsigned long)HYPERCALL_PHYSICAL_ADDRESS + __HYPERVISOR_##name * 32)

#define _hypercall0(type, name)                 \
({                                              \
    long __res;                                 \
    asm volatile (                              \
        "call *%%eax"                           \
        : "=a" (__res)                          \
        : "0" (hcall_addr(name))                \
        : "memory" );                           \
    (type)__res;                                \
})

#define _hypercall1(type, name, a1)             \
({                                              \
    long __res, __ign1;                         \
    asm volatile (                              \
        "call *%%eax"                           \
        : "=a" (__res), "=b" (__ign1)           \
        : "0" (hcall_addr(name)),               \
          "1" ((long)(a1))                      \
        : "memory" );                           \
    (type)__res;                                \
})

#define _hypercall2(type, name, a1, a2)                 \
({                                                      \
    long __res, __ign1, __ign2;                         \
    asm volatile (                                      \
        "call *%%eax"                                   \
        : "=a" (__res), "=b" (__ign1), "=c" (__ign2)    \
        : "0" (hcall_addr(name)),                       \
          "1" ((long)(a1)), "2" ((long)(a2))            \
        : "memory" );                                   \
    (type)__res;                                        \
})

#define _hypercall3(type, name, a1, a2, a3)             \
({                                                      \
    long __res, __ign1, __ign2, __ign3;                 \
    asm volatile (                                      \
        "call *%%eax"                                   \
        : "=a" (__res), "=b" (__ign1), "=c" (__ign2),   \
          "=d" (__ign3)                                 \
        : "0" (hcall_addr(name)),                       \
          "1" ((long)(a1)), "2" ((long)(a2)),           \
          "3" ((long)(a3))                              \
        : "memory" );                                   \
    (type)__res;                                        \
})

#define _hypercall4(type, name, a1, a2, a3, a4)         \
({                                                      \
    long __res, __ign1, __ign2, __ign3, __ign4;         \
    asm volatile (                                      \
        "call *%%eax"                                   \
        : "=a" (__res), "=b" (__ign1), "=c" (__ign2),   \
          "=d" (__ign3), "=S" (__ign4)                  \
        : "0" (hcall_addr(name)),                       \
          "1" ((long)(a1)), "2" ((long)(a2)),           \
          "3" ((long)(a3)), "4" ((long)(a4))            \
        : "memory" );                                   \
    (type)__res;                                        \
})

#define _hypercall5(type, name, a1, a2, a3, a4, a5)     \
({                                                      \
    long __res, __ign1, __ign2, __ign3, __ign4, __ign5; \
    asm volatile (                                      \
        "call *%%eax"                                   \
        : "=a" (__res), "=b" (__ign1), "=c" (__ign2),   \
          "=d" (__ign3), "=S" (__ign4), "=D" (__ign5)   \
        : "0" (hcall_addr(name)),                       \
          "1" ((long)(a1)), "2" ((long)(a2)),           \
          "3" ((long)(a3)), "4" ((long)(a4)),           \
          "5" ((long)(a5))                              \
        : "memory" );                                   \
    (type)__res;                                        \
})

static inline int
hypercall_sched_op(
    int cmd, void *arg)
{
    return _hypercall2(int, sched_op, cmd, arg);
}

static inline int
hypercall_memory_op(
    unsigned int cmd, void *arg)
{
    return _hypercall2(int, memory_op, cmd, arg);
}

static inline int
hypercall_multicall(
    void *call_list, int nr_calls)
{
    return _hypercall2(int, multicall, call_list, nr_calls);
}

static inline int
hypercall_event_channel_op(
    int cmd, void *arg)
{
    return _hypercall2(int, event_channel_op, cmd, arg);
}

static inline int
hypercall_xen_version(
    int cmd, void *arg)
{
    return _hypercall2(int, xen_version, cmd, arg);
}

static inline int
hypercall_console_io(
    int cmd, int count, char *str)
{
    return _hypercall3(int, console_io, cmd, count, str);
}

static inline int
hypercall_vm_assist(
    unsigned int cmd, unsigned int type)
{
    return _hypercall2(int, vm_assist, cmd, type);
}

static inline int
hypercall_vcpu_op(
    int cmd, int vcpuid, void *extra_args)
{
    return _hypercall3(int, vcpu_op, cmd, vcpuid, extra_args);
}

static inline int
hypercall_hvm_op(
    int cmd, void *arg)
{
    return _hypercall2(int, hvm_op, cmd, arg);
}

#endif /* __HVMLOADER_HYPERCALL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
