/******************************************************************************
 * hypervisor.h
 * 
 * Linux-specific hypervisor handling.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#ifndef _HYPERVISOR_H_
#define _HYPERVISOR_H_

#include <types.h>

#include <xen-public/xen.h>
#include <xen-public/io/domain_controller.h>

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
void do_hypervisor_callback(struct pt_regs *regs);
void enable_hypervisor_event(unsigned int ev);
void disable_hypervisor_event(unsigned int ev);
void ack_hypervisor_event(unsigned int ev);

/*
 * Assembler stubs for hyper-calls.
 */

#ifdef __i386__
#define _a1 "b"
#define _a2 "c"
#define _a3 "d"
#define _a4 "S"
#else
#define _a1 "D"
#define _a2 "S"
#define _a3 "d"
#define _a4 "b"
#endif

static __inline__ int HYPERVISOR_set_trap_table(trap_info_t *table)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_trap_table),
        _a1 (table) : "memory" );

    return ret;
}

static __inline__ int HYPERVISOR_mmu_update(mmu_update_t *req, 
                                            int count, 
                                            int *success_count)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_mmu_update), 
        _a1 (req), _a2 (count), _a3 (success_count)  : "memory" );

    return ret;
}

static __inline__ int HYPERVISOR_set_gdt(unsigned long *frame_list, int entries)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_gdt), 
        _a1 (frame_list), _a2 (entries) : "memory" );


    return ret;
}

static __inline__ int HYPERVISOR_stack_switch(unsigned long ss, unsigned long esp)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_stack_switch),
        _a1 (ss), _a2 (esp) : "memory" );

    return ret;
}

#ifdef __i386__
static __inline__ int HYPERVISOR_set_callbacks(
    unsigned long event_selector, unsigned long event_address,
    unsigned long failsafe_selector, unsigned long failsafe_address)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_callbacks),
        _a1 (event_selector), _a2 (event_address), 
        _a3 (failsafe_selector), _a4 (failsafe_address) : "memory" );

    return ret;
}
#else
static __inline__ int HYPERVISOR_set_callbacks(
    unsigned long event_address,
    unsigned long failsafe_address,
    unsigned long syscall_address)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_callbacks),
        _a1 (event_address), _a2 (failsafe_address), 
        _a3 (syscall_address) : "memory" );

    return ret;
}
#endif

static __inline__ int
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

static __inline__ int HYPERVISOR_yield(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        _a1 (SCHEDOP_yield) : "memory" );

    return ret;
}

static __inline__ int HYPERVISOR_block(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        _a1 (SCHEDOP_block) : "memory" );

    return ret;
}

static __inline__ int HYPERVISOR_shutdown(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        _a1 (SCHEDOP_shutdown | (SHUTDOWN_poweroff << SCHEDOP_reasonshift))
        : "memory" );

    return ret;
}

static __inline__ int HYPERVISOR_reboot(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        _a1 (SCHEDOP_shutdown | (SHUTDOWN_reboot << SCHEDOP_reasonshift))
        : "memory" );

    return ret;
}

static __inline__ int HYPERVISOR_suspend(unsigned long srec)
{
    int ret;
    /* NB. On suspend, control software expects a suspend record in %esi. */
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        _a1 (SCHEDOP_shutdown | (SHUTDOWN_suspend << SCHEDOP_reasonshift)), 
        "S" (srec) : "memory" );

    return ret;
}

static __inline__ long HYPERVISOR_set_timer_op(void *timer_arg)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_timer_op),
        _a1 (timer_arg) : "memory" );

    return ret;
}

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

static __inline__ int HYPERVISOR_set_fast_trap(int idx)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_fast_trap), 
        _a1 (idx) : "memory" );

    return ret;
}

static __inline__ int HYPERVISOR_dom_mem_op(void *dom_mem_op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_dom_mem_op),
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
