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
/*
 * Benjamin Liu <benjamin.liu@intel.com>
 * Jun Nakajima <jun.nakajima@intel.com>
 *   Ported to x86-64.
 * 
 */

#ifndef __HYPERCALL_H__
#define __HYPERCALL_H__
#include <asm-xen/xen-public/xen.h>

#define __syscall_clobber "r11","rcx","memory"

/*
 * Assembler stubs for hyper-calls.
 */
static inline int
HYPERVISOR_set_trap_table(
    trap_info_t *table)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_set_trap_table), "D" (table)
	: __syscall_clobber );

    return ret;
}

static inline int
HYPERVISOR_mmu_update(
    mmu_update_t *req, int count, int *success_count, domid_t domid)
{
    int ret;

    __asm__ __volatile__ (
        "movq %5, %%r10;" TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_mmu_update), "D" (req), "S" ((long)count),
	  "d" (success_count), "g" ((unsigned long)domid)
	: __syscall_clobber, "r10" );

    return ret;
}

static inline int
HYPERVISOR_mmuext_op(
    struct mmuext_op *op, int count, int *success_count, domid_t domid)
{
    int ret;

    __asm__ __volatile__ (
        "movq %5, %%r10;" TRAP_INSTR
        : "=a" (ret)
        : "0" (__HYPERVISOR_mmuext_op), "D" (op), "S" ((long)count), 
          "d" (success_count), "g" ((unsigned long)domid)
        : __syscall_clobber, "r10" );

    return ret;
}

static inline int
HYPERVISOR_set_gdt(
    unsigned long *frame_list, int entries)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_set_gdt), "D" (frame_list), "S" ((long)entries)
	: __syscall_clobber );


    return ret;
}
static inline int
HYPERVISOR_stack_switch(
    unsigned long ss, unsigned long esp)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_stack_switch), "D" (ss), "S" (esp)
	: __syscall_clobber );

    return ret;
}

static inline int
HYPERVISOR_set_callbacks(
    unsigned long event_address, unsigned long failsafe_address, 
    unsigned long syscall_address)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_set_callbacks), "D" (event_address),
	  "S" (failsafe_address), "d" (syscall_address)
	: __syscall_clobber );

    return ret;
}

static inline int
HYPERVISOR_fpu_taskswitch(
    int set)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" ((unsigned long)__HYPERVISOR_fpu_taskswitch),
          "D" ((unsigned long) set) : __syscall_clobber );

    return ret;
}

static inline int
HYPERVISOR_yield(
    void)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_sched_op), "D" ((unsigned long)SCHEDOP_yield)
	: __syscall_clobber );

    return ret;
}

static inline int
HYPERVISOR_block(
    void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_sched_op), "D" ((unsigned long)SCHEDOP_block)
	: __syscall_clobber );

    return ret;
}

static inline int
HYPERVISOR_shutdown(
    void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_sched_op),
	  "D" ((unsigned long)(SCHEDOP_shutdown | (SHUTDOWN_poweroff << SCHEDOP_reasonshift)))
	: __syscall_clobber );

    return ret;
}

static inline int
HYPERVISOR_reboot(
    void)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_sched_op),
	  "D" ((unsigned long)(SCHEDOP_shutdown | (SHUTDOWN_reboot << SCHEDOP_reasonshift)))
	: __syscall_clobber );

    return ret;
}

static inline int
HYPERVISOR_suspend(
    unsigned long srec)
{
    int ret;

    /* NB. On suspend, control software expects a suspend record in %esi. */
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_sched_op),
        "D" ((unsigned long)(SCHEDOP_shutdown | (SHUTDOWN_suspend << SCHEDOP_reasonshift))), 
        "S" (srec)
	: __syscall_clobber );

    return ret;
}

/*
 * We can have the timeout value in a single argument for the hypercall, but
 * that will break the common code. 
 */
static inline long
HYPERVISOR_set_timer_op(
    u64 timeout)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_set_timer_op),
	  "D" (timeout)
	: __syscall_clobber );

    return ret;
}

static inline int
HYPERVISOR_dom0_op(
    dom0_op_t *dom0_op)
{
    int ret;

    dom0_op->interface_version = DOM0_INTERFACE_VERSION;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_dom0_op), "D" (dom0_op)
	: __syscall_clobber );

    return ret;
}

static inline int
HYPERVISOR_set_debugreg(
    int reg, unsigned long value)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_set_debugreg), "D" ((unsigned long)reg), "S" (value)
	: __syscall_clobber );

    return ret;
}

static inline unsigned long
HYPERVISOR_get_debugreg(
    int reg)
{
    unsigned long ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_get_debugreg), "D" ((unsigned long)reg)
	: __syscall_clobber );

    return ret;
}

static inline int
HYPERVISOR_update_descriptor(
    unsigned long ma, unsigned long word)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_update_descriptor), "D" (ma),
	  "S" (word)
	: __syscall_clobber );

    return ret;
}

static inline int
HYPERVISOR_dom_mem_op(
    unsigned int op, unsigned long *extent_list,
    unsigned long nr_extents, unsigned int extent_order)
{
    int ret;

    __asm__ __volatile__ (
        "movq %5,%%r10; movq %6,%%r8;" TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_dom_mem_op), "D" ((unsigned long)op), "S" (extent_list),
	  "d" (nr_extents), "g" ((unsigned long) extent_order), "g" ((unsigned long) DOMID_SELF)
	: __syscall_clobber,"r8","r10");

    return ret;
}

static inline int
HYPERVISOR_multicall(
    void *call_list, int nr_calls)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_multicall), "D" (call_list), "S" ((unsigned long)nr_calls)
	: __syscall_clobber);

    return ret;
}

static inline int
HYPERVISOR_update_va_mapping(
    unsigned long page_nr, pte_t new_val, unsigned long flags)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_update_va_mapping), 
          "D" (page_nr), "S" (new_val.pte), "d" (flags)
	: __syscall_clobber);

    return ret;
}

static inline int
HYPERVISOR_event_channel_op(
    void *op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_event_channel_op), "D" (op)
	: __syscall_clobber);

    return ret;
}

static inline int
HYPERVISOR_xen_version(
    int cmd)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_xen_version), "D" ((unsigned long)cmd)
	: __syscall_clobber);

    return ret;
}

static inline int
HYPERVISOR_console_io(
    int cmd, int count, char *str)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_console_io), "D" ((unsigned long)cmd), "S" ((unsigned long)count), "d" (str)
	: __syscall_clobber);

    return ret;
}

static inline int
HYPERVISOR_physdev_op(
    void *physdev_op)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_physdev_op), "D" (physdev_op)
	: __syscall_clobber);

    return ret;
}

static inline int
HYPERVISOR_grant_table_op(
    unsigned int cmd, void *uop, unsigned int count)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_grant_table_op), "D" ((unsigned long)cmd), "S" ((unsigned long)uop), "d" (count)
	: __syscall_clobber);

    return ret;
}

static inline int
HYPERVISOR_update_va_mapping_otherdomain(
    unsigned long page_nr, pte_t new_val, unsigned long flags, domid_t domid)
{
    int ret;

    __asm__ __volatile__ (
        "movq %5, %%r10;" TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_update_va_mapping_otherdomain),
          "D" (page_nr), "S" (new_val.pte), "d" (flags), "g" ((unsigned long)domid)
	: __syscall_clobber,"r10");
    
    return ret;
}

static inline int
HYPERVISOR_vm_assist(
    unsigned int cmd, unsigned int type)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_vm_assist), "D" ((unsigned long)cmd), "S" ((unsigned long)type)
	: __syscall_clobber);

    return ret;
}

static inline int
HYPERVISOR_switch_to_user(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" ((unsigned long)__HYPERVISOR_switch_to_user) : __syscall_clobber );

    return ret;
}

static inline int
HYPERVISOR_boot_vcpu(
    unsigned long vcpu, vcpu_guest_context_t *ctxt)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" (__HYPERVISOR_boot_vcpu), "D" (vcpu), "S" (ctxt)
	: __syscall_clobber);

    return ret;
}

static inline int
HYPERVISOR_set_segment_base(
    int reg, unsigned long value)
{
    int ret;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret)
	: "0" ((unsigned long)__HYPERVISOR_set_segment_base), "D" ((unsigned long)reg), "S" (value)
	: __syscall_clobber );

    return ret;
}

#endif /* __HYPERCALL_H__ */
