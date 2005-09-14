/******************************************************************************
 * hypervisor.h
 * 
 * Hypervisor handling.
 * 
 * TODO - x86_64 broken!
 *
 * Copyright (c) 2002, K A Fraser
 * Copyright (c) 2005, Grzegorz Milos
 */

#ifndef _HYPERVISOR_H_
#define _HYPERVISOR_H_

#include <types.h>
#include <xen/xen.h>

/*
 * a placeholder for the start of day information passed up from the hypervisor
 */
union start_info_union
{
    start_info_t start_info;
    char padding[512];
};
extern union start_info_union start_info_union;
#define start_info (start_info_union.start_info)


/* hypervisor.c */
//void do_hypervisor_callback(struct pt_regs *regs);
void mask_evtchn(u32 port);
void unmask_evtchn(u32 port);
void clear_evtchn(u32 port);

/*
 * Assembler stubs for hyper-calls.
 */
#if defined(__i386__)
static inline int
HYPERVISOR_set_trap_table(
    trap_info_t *table)
{
    int ret;
    unsigned long ignore;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ignore)
	: "0" (__HYPERVISOR_set_trap_table), "1" (table)
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_mmu_update(
    mmu_update_t *req, int count, int *success_count, domid_t domid)
{
    int ret;
    unsigned long ign1, ign2, ign3, ign4;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2), "=d" (ign3), "=S" (ign4)
	: "0" (__HYPERVISOR_mmu_update), "1" (req), "2" (count),
        "3" (success_count), "4" (domid)
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_mmuext_op(
    struct mmuext_op *op, int count, int *success_count, domid_t domid)
{
    int ret;
    unsigned long ign1, ign2, ign3, ign4;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2), "=d" (ign3), "=S" (ign4)
	: "0" (__HYPERVISOR_mmuext_op), "1" (op), "2" (count),
        "3" (success_count), "4" (domid)
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_set_gdt(
    unsigned long *frame_list, int entries)
{
    int ret;
    unsigned long ign1, ign2;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2)
	: "0" (__HYPERVISOR_set_gdt), "1" (frame_list), "2" (entries)
	: "memory" );


    return ret;
}

static inline int
HYPERVISOR_stack_switch(
    unsigned long ss, unsigned long esp)
{
    int ret;
    unsigned long ign1, ign2;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2)
	: "0" (__HYPERVISOR_stack_switch), "1" (ss), "2" (esp)
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_set_callbacks(
    unsigned long event_selector, unsigned long event_address,
    unsigned long failsafe_selector, unsigned long failsafe_address)
{
    int ret;
    unsigned long ign1, ign2, ign3, ign4;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2), "=d" (ign3), "=S" (ign4)
	: "0" (__HYPERVISOR_set_callbacks), "1" (event_selector),
	  "2" (event_address), "3" (failsafe_selector), "4" (failsafe_address)
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_fpu_taskswitch(
    int set)
{
    int ret;
    unsigned long ign;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign)
        : "0" (__HYPERVISOR_fpu_taskswitch), "1" (set)
        : "memory" );

    return ret;
}

static inline int
HYPERVISOR_yield(
    void)
{
    int ret;
    unsigned long ign;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign)
	: "0" (__HYPERVISOR_sched_op), "1" (SCHEDOP_yield)
	: "memory", "ecx" );

    return ret;
}

static inline int
HYPERVISOR_block(
    void)
{
    int ret;
    unsigned long ign1;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1)
	: "0" (__HYPERVISOR_sched_op), "1" (SCHEDOP_block)
	: "memory", "ecx" );

    return ret;
}

static inline int
HYPERVISOR_shutdown(
    void)
{
    int ret;
    unsigned long ign1;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1)
	: "0" (__HYPERVISOR_sched_op),
	  "1" (SCHEDOP_shutdown | (SHUTDOWN_poweroff << SCHEDOP_reasonshift))
        : "memory", "ecx" );

    return ret;
}

static inline int
HYPERVISOR_reboot(
    void)
{
    int ret;
    unsigned long ign1;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1)
	: "0" (__HYPERVISOR_sched_op),
	  "1" (SCHEDOP_shutdown | (SHUTDOWN_reboot << SCHEDOP_reasonshift))
        : "memory", "ecx" );

    return ret;
}

static inline int
HYPERVISOR_suspend(
    unsigned long srec)
{
    int ret;
    unsigned long ign1, ign2;

    /* NB. On suspend, control software expects a suspend record in %esi. */
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=S" (ign2)
	: "0" (__HYPERVISOR_sched_op),
        "b" (SCHEDOP_shutdown | (SHUTDOWN_suspend << SCHEDOP_reasonshift)), 
        "S" (srec) : "memory", "ecx");

    return ret;
}

static inline int
HYPERVISOR_crash(
    void)
{
    int ret;
    unsigned long ign1;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1)
	: "0" (__HYPERVISOR_sched_op),
	  "1" (SCHEDOP_shutdown | (SHUTDOWN_crash << SCHEDOP_reasonshift))
        : "memory", "ecx" );

    return ret;
}

static inline long
HYPERVISOR_set_timer_op(
    u64 timeout)
{
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
}

#if 0
static inline int
HYPERVISOR_dom0_op(
    dom0_op_t *dom0_op)
{
    int ret;
    unsigned long ign1;

    dom0_op->interface_version = DOM0_INTERFACE_VERSION;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1)
	: "0" (__HYPERVISOR_dom0_op), "1" (dom0_op)
	: "memory");

    return ret;
}
#endif

static inline int
HYPERVISOR_set_debugreg(
    int reg, unsigned long value)
{
    int ret;
    unsigned long ign1, ign2;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2)
	: "0" (__HYPERVISOR_set_debugreg), "1" (reg), "2" (value)
	: "memory" );

    return ret;
}

static inline unsigned long
HYPERVISOR_get_debugreg(
    int reg)
{
    unsigned long ret;
    unsigned long ign;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign)
	: "0" (__HYPERVISOR_get_debugreg), "1" (reg)
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_update_descriptor(
    u64 ma, u64 desc)
{
    int ret;
    unsigned long ign1, ign2, ign3, ign4;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2), "=d" (ign3), "=S" (ign4)
	: "0" (__HYPERVISOR_update_descriptor),
	  "1" ((unsigned long)ma), "2" ((unsigned long)(ma>>32)),
	  "3" ((unsigned long)desc), "4" ((unsigned long)(desc>>32))
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_dom_mem_op(
    unsigned int op, unsigned long *extent_list,
    unsigned long nr_extents, unsigned int extent_order)
{
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
}

static inline int
HYPERVISOR_multicall(
    void *call_list, int nr_calls)
{
    int ret;
    unsigned long ign1, ign2;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2)
	: "0" (__HYPERVISOR_multicall), "1" (call_list), "2" (nr_calls)
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_update_va_mapping(
    unsigned long va, pte_t new_val, unsigned long flags)
{
    int ret;
    unsigned long ign1, ign2, ign3, ign4;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2), "=d" (ign3), "=S" (ign4)
	: "0" (__HYPERVISOR_update_va_mapping), 
          "1" (va), "2" ((new_val).pte_low),
#ifdef CONFIG_X86_PAE
	  "3" ((new_val).pte_high),
#else
	  "3" (0),
#endif
	  "4" (flags)
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_event_channel_op(
    void *op)
{
    int ret;
    unsigned long ignore;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ignore)
	: "0" (__HYPERVISOR_event_channel_op), "1" (op)
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_xen_version(
    int cmd, void *arg)
{
    int ret;
    unsigned long ignore, ign2;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ignore), "=c" (ign2)
	: "0" (__HYPERVISOR_xen_version), "1" (cmd), "2" (arg)
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_console_io(
    int cmd, int count, char *str)
{
    int ret;
    unsigned long ign1, ign2, ign3;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2), "=d" (ign3)
	: "0" (__HYPERVISOR_console_io), "1" (cmd), "2" (count), "3" (str)
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_physdev_op(
    void *physdev_op)
{
    int ret;
    unsigned long ign;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign)
	: "0" (__HYPERVISOR_physdev_op), "1" (physdev_op)
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_grant_table_op(
    unsigned int cmd, void *uop, unsigned int count)
{
    int ret;
    unsigned long ign1, ign2, ign3;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2), "=d" (ign3)
	: "0" (__HYPERVISOR_grant_table_op), "1" (cmd), "2" (uop), "3" (count)
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_update_va_mapping_otherdomain(
    unsigned long va, pte_t new_val, unsigned long flags, domid_t domid)
{
    int ret;
    unsigned long ign1, ign2, ign3, ign4, ign5;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2), "=d" (ign3),
	  "=S" (ign4), "=D" (ign5)
	: "0" (__HYPERVISOR_update_va_mapping_otherdomain),
          "1" (va), "2" ((new_val).pte_low),
#ifdef CONFIG_X86_PAE
	  "3" ((new_val).pte_high),
#else
	  "3" (0),
#endif
	  "4" (flags), "5" (domid) :
        "memory" );
    
    return ret;
}

static inline int
HYPERVISOR_vm_assist(
    unsigned int cmd, unsigned int type)
{
    int ret;
    unsigned long ign1, ign2;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2)
	: "0" (__HYPERVISOR_vm_assist), "1" (cmd), "2" (type)
	: "memory" );

    return ret;
}

static inline int
HYPERVISOR_boot_vcpu(
    unsigned long vcpu, vcpu_guest_context_t *ctxt)
{
    int ret;
    unsigned long ign1, ign2;

    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2)
	: "0" (__HYPERVISOR_boot_vcpu), "1" (vcpu), "2" (ctxt)
	: "memory");

    return ret;
}

static inline int
HYPERVISOR_vcpu_down(
    int vcpu)
{
    int ret;
    unsigned long ign1;
    /* Yes, I really do want to clobber edx here: when we resume a
       vcpu after unpickling a multi-processor domain, it returns
       here, but clobbers all of the call clobbered registers. */
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1)
	: "0" (__HYPERVISOR_sched_op),
	  "1" (SCHEDOP_vcpu_down | (vcpu << SCHEDOP_vcpushift))
        : "memory", "ecx", "edx" );

    return ret;
}

static inline int
HYPERVISOR_vcpu_up(
    int vcpu)
{
    int ret;
    unsigned long ign1;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1)
	: "0" (__HYPERVISOR_sched_op),
	  "1" (SCHEDOP_vcpu_up | (vcpu << SCHEDOP_vcpushift))
        : "memory", "ecx" );

    return ret;
}

static inline int
HYPERVISOR_vcpu_pickle(
    int vcpu, vcpu_guest_context_t *ctxt)
{
    int ret;
    unsigned long ign1, ign2;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret), "=b" (ign1), "=c" (ign2)
	: "0" (__HYPERVISOR_sched_op),
	  "1" (SCHEDOP_vcpu_pickle | (vcpu << SCHEDOP_vcpushift)),
	  "2" (ctxt)
        : "memory" );

    return ret;
}
#elif defined(__x86_64__)

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
#endif


static __inline__ int HYPERVISOR_dom0_op(void *dom0_op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_dom0_op),
        _a1 (dom0_op) : "memory" );

    return ret;
}

static __inline__ int HYPERVISOR_set_debugreg(int reg, unsigned long value)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_debugreg),
        _a1 (reg), _a2 (value) : "memory" );

    return ret;
}

static __inline__ unsigned long HYPERVISOR_get_debugreg(int reg)
{
    unsigned long ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_get_debugreg),
        _a1 (reg) : "memory" );

    return ret;
}

static __inline__ int HYPERVISOR_update_descriptor(
    unsigned long pa, unsigned long word1, unsigned long word2)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_update_descriptor), 
        _a1 (pa), _a2 (word1), _a3 (word2) : "memory" );

    return ret;
}

static __inline__ int HYPERVISOR_dom_mem_op(void *dom_mem_op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_memory_op),
        _a1 (dom_mem_op) : "memory" );

    return ret;
}

static __inline__ int HYPERVISOR_multicall(void *call_list, int nr_calls)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_multicall),
        _a1 (call_list), _a2 (nr_calls) : "memory" );

    return ret;
}

static __inline__ int HYPERVISOR_update_va_mapping(
    unsigned long page_nr, unsigned long new_val, unsigned long flags)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_update_va_mapping), 
        _a1 (page_nr), _a2 (new_val), _a3 (flags) : "memory" );

    return ret;
}

static __inline__ int HYPERVISOR_xen_version(int cmd)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_xen_version), 
        _a1 (cmd) : "memory" );

    return ret;
}

static __inline__ int HYPERVISOR_console_io(int cmd, int count, char *str)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_console_io),
        _a1 (cmd), _a2 (count), _a3 (str) : "memory" );

    return ret;
}

#endif /* __HYPERVISOR_H__ */
