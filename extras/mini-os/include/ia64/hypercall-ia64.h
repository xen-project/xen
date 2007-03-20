/******************************************************************************
 * hypercall.h
 * 
 * Mini-OS-specific hypervisor handling for ia64.
 * 
 * Copyright (c) 2002-2004, K A Fraser
 * Changes: Dietmar Hahn <dietmar.hahn@fujiti-siemens.com>
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

#ifndef __HYPERCALL_H__
#define __HYPERCALL_H__

#include "lib.h"	/* memcpy() */
#include "errno.h"	/* ENOSYS() */
#include <xen/event_channel.h>
#include <xen/sched.h>
#include <xen/version.h>

#ifndef _HYPERVISOR_H_
# error "please don't include this file directly"
#endif

// See linux/compiler.h
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

extern unsigned long __hypercall(unsigned long a1, unsigned long a2,
                                 unsigned long a3, unsigned long a4,
                                 unsigned long a5, unsigned long cmd);
/*
 * Assembler stubs for hyper-calls.
 */

#define _hypercall0(type, name)					\
({								\
	long __res;						\
	__res = __hypercall(0, 0, 0, 0, 0,			\
			    __HYPERVISOR_##name);		\
	(type)__res;						\
})

#define _hypercall1(type, name, a1)				\
({								\
	long __res;						\
	__res = __hypercall((unsigned long)a1,			\
			    0, 0, 0, 0, __HYPERVISOR_##name);	\
	(type)__res;						\
})

#define _hypercall2(type, name, a1, a2)				\
({								\
	long __res;						\
	__res = __hypercall((unsigned long)a1,			\
			    (unsigned long)a2,			\
			    0, 0, 0, __HYPERVISOR_##name);	\
	(type)__res;						\
})

#define _hypercall3(type, name, a1, a2, a3)			\
({								\
	long __res;						\
	__res = __hypercall((unsigned long)a1,			\
			    (unsigned long)a2,			\
			    (unsigned long)a3,			\
			    0, 0, __HYPERVISOR_##name);		\
	(type)__res;						\
})

#define _hypercall4(type, name, a1, a2, a3, a4)			\
({								\
	long __res;						\
	__res = __hypercall((unsigned long)a1,			\
			    (unsigned long)a2,			\
			    (unsigned long)a3,			\
			    (unsigned long)a4,			\
			    0, __HYPERVISOR_##name);		\
	(type)__res;						\
})

#define _hypercall5(type, name, a1, a2, a3, a4, a5)		\
({								\
	long __res;						\
	__res = __hypercall((unsigned long)a1,			\
			    (unsigned long)a2,			\
			    (unsigned long)a3,			\
			    (unsigned long)a4,			\
			    (unsigned long)a5,			\
			    __HYPERVISOR_##name);		\
	(type)__res;						\
})


extern unsigned long xencomm_vaddr_to_paddr(unsigned long vaddr);
struct xencomm_handle;

/* Inline version.  To be used only on linear space (kernel space).  */
static inline struct xencomm_handle *
xencomm_create_inline(void *buffer)
{
	unsigned long paddr;

	paddr = xencomm_vaddr_to_paddr((unsigned long)buffer);
	return (struct xencomm_handle *)(paddr | XENCOMM_INLINE_FLAG);
}

static inline int
xencomm_arch_event_channel_op(int cmd, void *arg)
{
	int rc;
	struct xencomm_handle *newArg;

	newArg = xencomm_create_inline(arg);
	rc = _hypercall2(int, event_channel_op, cmd, newArg);
	if (unlikely(rc == -ENOSYS)) {
		struct evtchn_op op;

		op.cmd = SWAP(cmd);
		memcpy(&op.u, arg, sizeof(op.u));
		rc = _hypercall1(int, event_channel_op_compat, &op);
	}
	return rc;
}
#define HYPERVISOR_event_channel_op xencomm_arch_event_channel_op

static inline int
xencomm_arch_xen_version(int cmd, struct xencomm_handle *arg)
{
	return _hypercall2(int, xen_version, cmd, arg);
}

static inline int
xencomm_arch_xen_feature(int cmd, struct xencomm_handle *arg)
{
	struct xencomm_handle *newArg;

	newArg = xencomm_create_inline(arg);
	return _hypercall2(int, xen_version, cmd, newArg);
}

static inline int
HYPERVISOR_xen_version(int cmd, void *arg)
{
	switch(cmd) {
		case XENVER_version:
			return xencomm_arch_xen_version(cmd, 0);
		case XENVER_get_features:
			return xencomm_arch_xen_feature(cmd, arg);
		default:
			return -1;
	}
}

static inline int
xencomm_arch_console_io(int cmd, int count, char *str)
{
	struct xencomm_handle *newStr;

	newStr = xencomm_create_inline(str);
	return _hypercall3(int, console_io, cmd, count, newStr);
}


#define HYPERVISOR_console_io xencomm_arch_console_io

static inline int
HYPERVISOR_sched_op_compat(int cmd, unsigned long arg)
{
	return _hypercall2(int, sched_op_compat, cmd, arg);
}

static inline int
xencomm_arch_sched_op(int cmd, void *arg)
{
	struct xencomm_handle *newArg;

	newArg = xencomm_create_inline(arg);
	return _hypercall2(int, sched_op, cmd, newArg);
}

#define HYPERVISOR_sched_op xencomm_arch_sched_op

static inline int
xencomm_arch_callback_op(int cmd, void *arg)
{
	struct xencomm_handle *newArg;

	newArg = xencomm_create_inline(arg);
	return _hypercall2(int, callback_op, cmd, newArg);
}
#define HYPERVISOR_callback_op xencomm_arch_callback_op

static inline int
xencomm_arch_hypercall_grant_table_op(unsigned int cmd,
                                      struct xencomm_handle *uop,
                                      unsigned int count)
{
	return _hypercall3(int, grant_table_op, cmd, uop, count);
}

int HYPERVISOR_grant_table_op(unsigned int cmd, void *uop, unsigned int count);

#endif /* __HYPERCALL_H__ */
