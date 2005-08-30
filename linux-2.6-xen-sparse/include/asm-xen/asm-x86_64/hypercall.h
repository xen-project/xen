/******************************************************************************
 * hypercall.h
 * 
 * Linux-specific hypervisor handling.
 * 
 * Copyright (c) 2002-2004, K A Fraser
 * 
 * 64-bit updates:
 *   Benjamin Liu <benjamin.liu@intel.com>
 *   Jun Nakajima <jun.nakajima@intel.com>
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

#include <asm-xen/xen-public/xen.h>

#define __syscall_clobber "r11","rcx","memory"

#define _hypercall0(type, name)			\
({						\
	long __res;				\
	asm volatile (				\
		TRAP_INSTR			\
		: "=a" (__res)			\
		: "0" (__HYPERVISOR_##name)	\
		: __syscall_clobber );		\
	(type)__res;				\
})

#define _hypercall1(type, name, a1)				\
({								\
	long __res, __ign1;					\
	asm volatile (						\
		TRAP_INSTR					\
		: "=a" (__res), "=D" (__ign1)			\
		: "0" (__HYPERVISOR_##name), "1" ((long)(a1))	\
		: __syscall_clobber );				\
	(type)__res;						\
})

#define _hypercall2(type, name, a1, a2)				\
({								\
	long __res, __ign1, __ign2;				\
	asm volatile (						\
		TRAP_INSTR					\
		: "=a" (__res), "=D" (__ign1), "=S" (__ign2)	\
		: "0" (__HYPERVISOR_##name), "1" ((long)(a1)),	\
		"2" ((long)(a2))				\
		: __syscall_clobber );				\
	(type)__res;						\
})

#define _hypercall3(type, name, a1, a2, a3)			\
({								\
	long __res, __ign1, __ign2, __ign3;			\
	asm volatile (						\
		TRAP_INSTR					\
		: "=a" (__res), "=D" (__ign1), "=S" (__ign2), 	\
		"=d" (__ign3)					\
		: "0" (__HYPERVISOR_##name), "1" ((long)(a1)),	\
		"2" ((long)(a2)), "3" ((long)(a3))		\
		: __syscall_clobber );				\
	(type)__res;						\
})

#define _hypercall4(type, name, a1, a2, a3, a4)			\
({								\
	long __res, __ign1, __ign2, __ign3;			\
	asm volatile (						\
		"movq %8,%%r10; " TRAP_INSTR			\
		: "=a" (__res), "=D" (__ign1), "=S" (__ign2),	\
		"=d" (__ign3)					\
		: "0" (__HYPERVISOR_##name), "1" ((long)(a1)),	\
		"2" ((long)(a2)), "3" ((long)(a3)),		\
		"g" ((long)(a4))				\
		: __syscall_clobber, "r10" );			\
	(type)__res;						\
})

#define _hypercall5(type, name, a1, a2, a3, a4, a5)		\
({								\
	long __res, __ign1, __ign2, __ign3;			\
	asm volatile (						\
		"movq %8,%%r10; movq %9,%%r8; " TRAP_INSTR	\
		: "=a" (__res), "=D" (__ign1), "=S" (__ign2),	\
		"=d" (__ign3)					\
		: "0" (__HYPERVISOR_##name), "1" ((long)(a1)),	\
		"2" ((long)(a2)), "3" ((long)(a3)),		\
		"g" ((long)(a4)), "g" ((long)(a5))		\
		: __syscall_clobber, "r10", "r8" );		\
	(type)__res;						\
})

static inline int
HYPERVISOR_set_trap_table(
	trap_info_t *table)
{
	return _hypercall1(int, set_trap_table, table);
}

static inline int
HYPERVISOR_mmu_update(
	mmu_update_t *req, int count, int *success_count, domid_t domid)
{
	return _hypercall4(int, mmu_update, req, count, success_count, domid);
}

static inline int
HYPERVISOR_mmuext_op(
	struct mmuext_op *op, int count, int *success_count, domid_t domid)
{
	return _hypercall4(int, mmuext_op, op, count, success_count, domid);
}

static inline int
HYPERVISOR_set_gdt(
	unsigned long *frame_list, int entries)
{
	return _hypercall2(int, set_gdt, frame_list, entries);
}

static inline int
HYPERVISOR_stack_switch(
	unsigned long ss, unsigned long esp)
{
	return _hypercall2(int, stack_switch, ss, esp);
}

static inline int
HYPERVISOR_set_callbacks(
	unsigned long event_address, unsigned long failsafe_address, 
	unsigned long syscall_address)
{
	return _hypercall3(int, set_callbacks,
			   event_address, failsafe_address, syscall_address);
}

static inline int
HYPERVISOR_fpu_taskswitch(
	int set)
{
	return _hypercall1(int, fpu_taskswitch, set);
}

static inline int
HYPERVISOR_yield(
	void)
{
	return _hypercall2(int, sched_op, SCHEDOP_yield, 0);
}

static inline int
HYPERVISOR_block(
	void)
{
	return _hypercall2(int, sched_op, SCHEDOP_block, 0);
}

static inline int
HYPERVISOR_shutdown(
	void)
{
	return _hypercall2(int, sched_op, SCHEDOP_shutdown |
			   (SHUTDOWN_poweroff << SCHEDOP_reasonshift), 0);
}

static inline int
HYPERVISOR_reboot(
	void)
{
	return _hypercall2(int, sched_op, SCHEDOP_shutdown |
			   (SHUTDOWN_reboot << SCHEDOP_reasonshift), 0);
}

static inline long
HYPERVISOR_set_timer_op(
	u64 timeout)
{
	return _hypercall1(long, set_timer_op, timeout);
}

static inline int
HYPERVISOR_dom0_op(
	dom0_op_t *dom0_op)
{
	dom0_op->interface_version = DOM0_INTERFACE_VERSION;
	return _hypercall1(int, dom0_op, dom0_op);
}

static inline int
HYPERVISOR_set_debugreg(
	int reg, unsigned long value)
{
	return _hypercall2(int, set_debugreg, reg, value);
}

static inline unsigned long
HYPERVISOR_get_debugreg(
	int reg)
{
	return _hypercall1(unsigned long, get_debugreg, reg);
}

static inline int
HYPERVISOR_update_descriptor(
	unsigned long ma, unsigned long word)
{
	return _hypercall2(int, update_descriptor, ma, word);
}

static inline int
HYPERVISOR_memory_op(
	unsigned int cmd, void *arg)
{
	return _hypercall2(int, memory_op, cmd, arg);
}

static inline int
HYPERVISOR_multicall(
	void *call_list, int nr_calls)
{
	return _hypercall2(int, multicall, call_list, nr_calls);
}

static inline int
HYPERVISOR_update_va_mapping(
	unsigned long va, pte_t new_val, unsigned long flags)
{
	return _hypercall3(int, update_va_mapping, va, new_val.pte, flags);
}

static inline int
HYPERVISOR_event_channel_op(
	void *op)
{
	return _hypercall1(int, event_channel_op, op);
}

static inline int
HYPERVISOR_xen_version(
	int cmd)
{
	return _hypercall1(int, xen_version, cmd);
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
HYPERVISOR_update_va_mapping_otherdomain(
	unsigned long va, pte_t new_val, unsigned long flags, domid_t domid)
{
	return _hypercall4(int, update_va_mapping_otherdomain, va,
			   new_val.pte, flags, domid);
}

static inline int
HYPERVISOR_vm_assist(
	unsigned int cmd, unsigned int type)
{
	return _hypercall2(int, vm_assist, cmd, type);
}

static inline int
HYPERVISOR_boot_vcpu(
	unsigned long vcpu, vcpu_guest_context_t *ctxt)
{
	return _hypercall2(int, boot_vcpu, vcpu, ctxt);
}

static inline int
HYPERVISOR_vcpu_up(
	int vcpu)
{
	return _hypercall2(int, sched_op, SCHEDOP_vcpu_up |
			   (vcpu << SCHEDOP_vcpushift), 0);
}

static inline int
HYPERVISOR_vcpu_pickle(
	int vcpu, vcpu_guest_context_t *ctxt)
{
	return _hypercall2(int, sched_op, SCHEDOP_vcpu_pickle |
			   (vcpu << SCHEDOP_vcpushift), ctxt);
}

static inline int
HYPERVISOR_switch_to_user(void)
{
	return _hypercall0(int, switch_to_user);
}

static inline int
HYPERVISOR_set_segment_base(
	int reg, unsigned long value)
{
	return _hypercall2(int, set_segment_base, reg, value);
}

static inline int
HYPERVISOR_suspend(
	unsigned long srec)
{
	return _hypercall2(int, sched_op, SCHEDOP_shutdown |
			   (SHUTDOWN_suspend << SCHEDOP_reasonshift), srec);
}

#endif /* __HYPERCALL_H__ */

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
