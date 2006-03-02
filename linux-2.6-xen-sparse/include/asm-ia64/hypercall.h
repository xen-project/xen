/******************************************************************************
 * hypercall.h
 * 
 * Linux-specific hypervisor handling.
 * 
 * Copyright (c) 2002-2004, K A Fraser
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

#ifndef __HYPERCALL_H__
#define __HYPERCALL_H__

#include <xen/interface/xen.h>
#include <xen/interface/sched.h>

/* FIXME: temp place to hold these page related macros */
#include <asm/page.h>
#define virt_to_machine(v) __pa(v)
#define machine_to_virt(m) __va(m)
#define virt_to_mfn(v)	((__pa(v)) >> PAGE_SHIFT)
#define mfn_to_virt(m)	(__va((m) << PAGE_SHIFT))

/*
 * Assembler stubs for hyper-calls.
 */

#define _hypercall0(type, name)					\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"				\
			      "mov r2=%1\n"			\
			      "break 0x1000 ;;\n"		\
			      "mov %0=r8 ;;\n"			\
			      : "=r" (__res)			\
			      : "i" (__HYPERVISOR_##name)	\
			      : "r2","r8",			\
			        "memory" );			\
	(type)__res;						\
})

#define _hypercall1(type, name, a1)				\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"				\
			      "mov r14=%2\n"			\
			      "mov r2=%1\n"			\
			      "break 0x1000 ;;\n"		\
			      "mov %0=r8 ;;\n"			\
			      : "=r" (__res)			\
			      : "i" (__HYPERVISOR_##name),	\
				"r" ((unsigned long)(a1))	\
			      : "r14","r2","r8",		\
				"memory" );			\
	(type)__res;						\
})

#define _hypercall2(type, name, a1, a2)				\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"				\
			      "mov r14=%2\n"			\
			      "mov r15=%3\n"			\
			      "mov r2=%1\n"			\
			      "break 0x1000 ;;\n"		\
			      "mov %0=r8 ;;\n"			\
			      : "=r" (__res)			\
			      : "i" (__HYPERVISOR_##name),	\
				"r" ((unsigned long)(a1)),	\
				"r" ((unsigned long)(a2))	\
			      : "r14","r15","r2","r8",		\
				"memory" );			\
	(type)__res;						\
})

#define _hypercall3(type, name, a1, a2, a3)			\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"                            \
			      "mov r14=%2\n"                    \
			      "mov r15=%3\n"                    \
			      "mov r16=%4\n"                    \
			      "mov r2=%1\n"                     \
			      "break 0x1000 ;;\n"               \
			      "mov %0=r8 ;;\n"                  \
			      : "=r" (__res)                    \
			      : "i" (__HYPERVISOR_##name),      \
				"r" ((unsigned long)(a1)),	\
				"r" ((unsigned long)(a2)),	\
				"r" ((unsigned long)(a3))	\
			      : "r14","r15","r16","r2","r8",	\
			        "memory" );                     \
	(type)__res;                                            \
})

#define _hypercall4(type, name, a1, a2, a3, a4)			\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"                            \
			      "mov r14=%2\n"                    \
			      "mov r15=%3\n"                    \
			      "mov r16=%4\n"                    \
			      "mov r17=%5\n"                    \
			      "mov r2=%1\n"                     \
			      "break 0x1000 ;;\n"               \
			      "mov %0=r8 ;;\n"                  \
			      : "=r" (__res)                    \
			      : "i" (__HYPERVISOR_##name),      \
				"r" ((unsigned long)(a1)),	\
				"r" ((unsigned long)(a2)),	\
				"r" ((unsigned long)(a3)),	\
				"r" ((unsigned long)(a4))       \
			      : "r14","r15","r16","r2","r8",	\
			        "r17","memory" );               \
	(type)__res;                                            \
})

#define _hypercall5(type, name, a1, a2, a3, a4, a5)		\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"                            \
			      "mov r14=%2\n"                    \
			      "mov r15=%3\n"                    \
			      "mov r16=%4\n"                    \
			      "mov r17=%5\n"                    \
			      "mov r18=%6\n"                    \
			      "mov r2=%1\n"                     \
			      "break 0x1000 ;;\n"               \
			      "mov %0=r8 ;;\n"                  \
			      : "=r" (__res)                    \
			      : "i" (__HYPERVISOR_##name),      \
				"r" ((unsigned long)(a1)),	\
				"r" ((unsigned long)(a2)),	\
				"r" ((unsigned long)(a3)),	\
				"r" ((unsigned long)(a4)),	\
				"r" ((unsigned long)(a5))       \
			      : "r14","r15","r16","r2","r8",	\
			        "r17","r18","memory" );         \
	(type)__res;                                            \
})

static inline int
HYPERVISOR_sched_op(
    int cmd, unsigned long arg)
{
	return _hypercall2(int, sched_op, cmd, arg);
}

static inline long
HYPERVISOR_set_timer_op(
    u64 timeout)
{
    unsigned long timeout_hi = (unsigned long)(timeout>>32);
    unsigned long timeout_lo = (unsigned long)timeout;
    return _hypercall2(long, set_timer_op, timeout_lo, timeout_hi);
}

static inline int
HYPERVISOR_dom0_op(
    dom0_op_t *dom0_op)
{
    dom0_op->interface_version = DOM0_INTERFACE_VERSION;
    return _hypercall1(int, dom0_op, dom0_op);
}

static inline int
HYPERVISOR_multicall(
    void *call_list, int nr_calls)
{
    return _hypercall2(int, multicall, call_list, nr_calls);
}

static inline int
HYPERVISOR_memory_op(
    unsigned int cmd, void *arg)
{
    return _hypercall2(int, memory_op, cmd, arg);
}

static inline int
HYPERVISOR_event_channel_op(
    void *op)
{
    return _hypercall1(int, event_channel_op, op);
}

static inline int
HYPERVISOR_xen_version(
    int cmd, void *arg)
{
    return _hypercall2(int, xen_version, cmd, arg);
}

static inline int
HYPERVISOR_console_io(
    int cmd, int count, char *str)
{
    return _hypercall3(int, console_io, cmd, count, str);
}

static inline int
HYPERVISOR_physdev_op(
    void *physdev_op)
{
    return _hypercall1(int, physdev_op, physdev_op);
}

static inline int
HYPERVISOR_grant_table_op(
    unsigned int cmd, void *uop, unsigned int count)
{
    return _hypercall3(int, grant_table_op, cmd, uop, count);
}

static inline int
HYPERVISOR_vcpu_op(
	int cmd, int vcpuid, void *extra_args)
{
    return _hypercall3(int, vcpu_op, cmd, vcpuid, extra_args);
}

static inline int
HYPERVISOR_suspend(
	unsigned long srec)
{
    return _hypercall3(int, sched_op, SCHEDOP_shutdown,
			SHUTDOWN_suspend, srec);
}

extern fastcall unsigned int __do_IRQ(unsigned int irq, struct pt_regs *regs);
static inline void exit_idle(void) {}
#define do_IRQ(irq, regs) __do_IRQ((irq), (regs))

#endif /* __HYPERCALL_H__ */
