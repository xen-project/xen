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

#include <asm-xen/xen-public/xen.h>
#include <asm-xen/xen-public/sched.h>

/* FIXME: temp place to hold these page related macros */
#include <asm/page.h>
#define virt_to_machine(v) __pa(v)
#define machine_to_virt(m) __va(m)
//#define virt_to_mfn(v)	(__pa(v) >> 14)
//#define mfn_to_virt(m)	(__va(m << 14))
#define virt_to_mfn(v)	((__pa(v)) >> PAGE_SHIFT)
#define mfn_to_virt(m)	(__va((m) << PAGE_SHIFT))

/*
 * Assembler stubs for hyper-calls.
 */

#if 0
static inline int
HYPERVISOR_set_trap_table(
    trap_info_t *table)
{
#if 0
    int ret;
    unsigned long ignore;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ignore)
	: "0" (__HYPERVISOR_set_trap_table), "1" (table)
	: "memory" );

    return ret;
#endif
    return 1;
}

static inline int
HYPERVISOR_mmu_update(
    mmu_update_t *req, int count, int *success_count, domid_t domid)
{
#if 0
    int ret;
    unsigned long ign1, ign2, ign3, ign4;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2), "=d" (ign3), "=S" (ign4)
	: "0" (__HYPERVISOR_mmu_update), "1" (req), "2" (count),
        "3" (success_count), "4" (domid)
	: "memory" );

    return ret;
#endif
    return 1;
}

static inline int
HYPERVISOR_mmuext_op(
    struct mmuext_op *op, int count, int *success_count, domid_t domid)
{
#if 0
    int ret;
    unsigned long ign1, ign2, ign3, ign4;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2), "=d" (ign3), "=S" (ign4)
	: "0" (__HYPERVISOR_mmuext_op), "1" (op), "2" (count),
        "3" (success_count), "4" (domid)
	: "memory" );

    return ret;
#endif
    return 1;
}

static inline int
HYPERVISOR_set_gdt(
    unsigned long *frame_list, int entries)
{
#if 0
    int ret;
    unsigned long ign1, ign2;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2)
	: "0" (__HYPERVISOR_set_gdt), "1" (frame_list), "2" (entries)
	: "memory" );


    return ret;
#endif
    return 1;
}

static inline int
HYPERVISOR_stack_switch(
    unsigned long ss, unsigned long esp)
{
#if 0
    int ret;
    unsigned long ign1, ign2;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2)
	: "0" (__HYPERVISOR_stack_switch), "1" (ss), "2" (esp)
	: "memory" );

    return ret;
#endif
    return 1;
}

static inline int
HYPERVISOR_set_callbacks(
    unsigned long event_selector, unsigned long event_address,
    unsigned long failsafe_selector, unsigned long failsafe_address)
{
#if 0
    int ret;
    unsigned long ign1, ign2, ign3, ign4;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2), "=d" (ign3), "=S" (ign4)
	: "0" (__HYPERVISOR_set_callbacks), "1" (event_selector),
	  "2" (event_address), "3" (failsafe_selector), "4" (failsafe_address)
	: "memory" );

    return ret;
#endif
    return 1;
}

static inline int
HYPERVISOR_fpu_taskswitch(
    int set)
{
#if 0
    int ret;
    unsigned long ign;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign)
        : "0" (__HYPERVISOR_fpu_taskswitch), "1" (set)
        : "memory" );

    return ret;
#endif
    return 1;
}

static inline int
HYPERVISOR_sched_op(
    int cmd, unsigned long arg)
{
    return 1;
}

static inline int
HYPERVISOR_suspend(
    unsigned long srec)
{
    return 1;
}

static inline long
HYPERVISOR_set_timer_op(
    u64 timeout)
{
#if 0
    int ret;
    unsigned long timeout_hi = (unsigned long)(timeout>>32);
    unsigned long timeout_lo = (unsigned long)timeout;
    unsigned long ign1, ign2;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2)
	: "0" (__HYPERVISOR_set_timer_op), "b" (timeout_lo), "c" (timeout_hi)
	: "memory");

    return ret;
#endif
    return 1;
}

static inline int
HYPERVISOR_dom0_op(
    dom0_op_t *dom0_op)
{
#if 0
    int ret;
    unsigned long ign1;

    dom0_op->interface_version = DOM0_INTERFACE_VERSION;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1)
	: "0" (__HYPERVISOR_dom0_op), "1" (dom0_op)
	: "memory");

    return ret;
#endif
    return 1;
}

static inline int
HYPERVISOR_set_debugreg(
    int reg, unsigned long value)
{
#if 0
    int ret;
    unsigned long ign1, ign2;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2)
	: "0" (__HYPERVISOR_set_debugreg), "1" (reg), "2" (value)
	: "memory" );

    return ret;
#endif
    return 1;
}

static inline unsigned long
HYPERVISOR_get_debugreg(
    int reg)
{
#if 0
    unsigned long ret;
    unsigned long ign;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign)
	: "0" (__HYPERVISOR_get_debugreg), "1" (reg)
	: "memory" );

    return ret;
#endif
    return 1;
}

static inline int
HYPERVISOR_update_descriptor(
    unsigned long ma, unsigned long word1, unsigned long word2)
{
#if 0
    int ret;
    unsigned long ign1, ign2, ign3;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2), "=d" (ign3)
	: "0" (__HYPERVISOR_update_descriptor), "1" (ma), "2" (word1),
	  "3" (word2)
	: "memory" );

    return ret;
#endif
    return 1;
}

static inline int
HYPERVISOR_set_fast_trap(
    int idx)
{
#if 0
    int ret;
    unsigned long ign;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign)
	: "0" (__HYPERVISOR_set_fast_trap), "1" (idx)
	: "memory" );

    return ret;
#endif
    return 1;
}

static inline int
HYPERVISOR_dom_mem_op(
    unsigned int op, unsigned long *extent_list,
    unsigned long nr_extents, unsigned int extent_order)
{
#if 0
    int ret;
    unsigned long ign1, ign2, ign3, ign4, ign5;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2), "=d" (ign3), "=S" (ign4),
	  "=D" (ign5)
	: "0" (__HYPERVISOR_dom_mem_op), "1" (op), "2" (extent_list),
	  "3" (nr_extents), "4" (extent_order), "5" (DOMID_SELF)
        : "memory" );

    return ret;
#endif
    return 1;
}

static inline int
HYPERVISOR_multicall(
    void *call_list, int nr_calls)
{
#if 0
    int ret;
    unsigned long ign1, ign2;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2)
	: "0" (__HYPERVISOR_multicall), "1" (call_list), "2" (nr_calls)
	: "memory" );

    return ret;
#endif
    return 1;
}
#endif

static inline int
HYPERVISOR_update_va_mapping(
    unsigned long va, pte_t new_val, unsigned long flags)
{
    /* no-op */
    return 1;
}

static inline int
HYPERVISOR_memory_op(
    unsigned int cmd, void *arg)
{
    int ret;
    __asm__ __volatile__ ( ";; mov r14=%2 ; mov r15=%3 ; mov r2=%1 ; break 0x1000 ;; mov %0=r8 ;;"
        : "=r" (ret)
        : "i" (__HYPERVISOR_console_io), "r"(cmd), "r"(arg)
        : "r14","r15","r2","r8","memory" );
    return ret;
}

static inline int
HYPERVISOR_event_channel_op(
    void *op)
{
    int ret;
    __asm__ __volatile__ ( ";; mov r14=%2 ; mov r2=%1 ; break 0x1000 ;; mov %0=r8 ;;"
        : "=r" (ret)
        : "i" (__HYPERVISOR_event_channel_op), "r"(op)
        : "r14","r2","r8","memory" );
    return ret;
}

#if 0
static inline int
HYPERVISOR_xen_version(
    int cmd)
{
#if 0
    int ret;
    unsigned long ignore;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ignore)
	: "0" (__HYPERVISOR_xen_version), "1" (cmd)
	: "memory" );

    return ret;
#endif
    return 1;
}
#endif

static inline int
HYPERVISOR_console_io(
    int cmd, int count, char *str)
{
    int ret;
    __asm__ __volatile__ ( ";; mov r14=%2 ; mov r15=%3 ; mov r16=%4 ; mov r2=%1 ; break 0x1000 ;; mov %0=r8 ;;"
        : "=r" (ret)
        : "i" (__HYPERVISOR_console_io), "r"(cmd), "r"(count), "r"(str)
        : "r14","r15","r16","r2","r8","memory" );
    return ret;
}

#if 0
static inline int
HYPERVISOR_physdev_op(
    void *physdev_op)
{
#if 0
    int ret;
    unsigned long ign;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign)
	: "0" (__HYPERVISOR_physdev_op), "1" (physdev_op)
	: "memory" );

    return ret;
#endif
    return 1;
}
#endif

static inline int
HYPERVISOR_grant_table_op(
    unsigned int cmd, void *uop, unsigned int count)
{
    int ret;
    __asm__ __volatile__ ( ";; mov r14=%2 ; mov r15=%3 ; mov r16=%4 ; mov r2=%1 ; break 0x1000 ;; mov %0=r8 ;;"
        : "=r" (ret)
        : "i" (__HYPERVISOR_grant_table_op), "r"(cmd), "r"(uop), "r"(count)
        : "r14","r15","r16","r2","r8","memory" );
    return ret;
}

#if 0
static inline int
HYPERVISOR_update_va_mapping_otherdomain(
    unsigned long va, pte_t new_val, unsigned long flags, domid_t domid)
{
#if 0
    int ret;
    unsigned long ign1, ign2, ign3, ign4;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2), "=d" (ign3), "=S" (ign4)
	: "0" (__HYPERVISOR_update_va_mapping_otherdomain),
          "1" (va), "2" ((new_val).pte_low), "3" (flags), "4" (domid) :
        "memory" );
    
    return ret;
#endif
    return 1;
}

static inline int
HYPERVISOR_vm_assist(
    unsigned int cmd, unsigned int type)
{
#if 0
    int ret;
    unsigned long ign1, ign2;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2)
	: "0" (__HYPERVISOR_vm_assist), "1" (cmd), "2" (type)
	: "memory" );

    return ret;
#endif
    return 1;
}

#endif

#endif /* __HYPERCALL_H__ */
