
#ifndef _HYPERVISOR_H_
#define _HYPERVISOR_H_

#include <types.h>

/* include the hypervisor interface */
#include <hypervisor-ifs/network.h>
#include <hypervisor-ifs/block.h>
#include <hypervisor-ifs/hypervisor-if.h>


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

static inline int HYPERVISOR_set_trap_table(trap_info_t *table)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_trap_table),
        "b" (table) );

    return ret;
}

static inline int HYPERVISOR_mmu_update(mmu_update_t *req, int count)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_mmu_update), 
        "b" (req), "c" (count) );

    return ret;
}

static inline int HYPERVISOR_console_write(const char *str, int count)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_console_write), 
        "b" (str), "c" (count) );


    return ret;
}

static inline int HYPERVISOR_set_gdt(unsigned long *frame_list, int entries)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_gdt), 
        "b" (frame_list), "c" (entries) );


    return ret;
}

static inline int HYPERVISOR_stack_switch(unsigned long ss, unsigned long esp)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_stack_switch),
        "b" (ss), "c" (esp) : "memory" );

    return ret;
}

static inline int HYPERVISOR_set_callbacks(
    unsigned long event_selector, unsigned long event_address,
    unsigned long failsafe_selector, unsigned long failsafe_address)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_callbacks),
        "b" (event_selector), "c" (event_address), 
        "d" (failsafe_selector), "S" (failsafe_address) : "memory" );

    return ret;
}

static inline int HYPERVISOR_net_io_op(netop_t *op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_net_io_op),
        "b" (op) );

    return ret;
}

static inline int HYPERVISOR_fpu_taskswitch(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_fpu_taskswitch) );

    return ret;
}

static inline int HYPERVISOR_yield(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        "b" (SCHEDOP_yield) );

    return ret;
}

static inline int HYPERVISOR_exit(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        "b" (SCHEDOP_exit) );

    return ret;
}

static inline int HYPERVISOR_stop(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        "b" (SCHEDOP_stop) );

    return ret;
}

static inline int HYPERVISOR_dom0_op(void *dom0_op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_dom0_op),
        "b" (dom0_op) : "memory" );

    return ret;
}

static inline int HYPERVISOR_network_op(void *network_op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_network_op),
        "b" (network_op) );

    return ret;
}

static inline int HYPERVISOR_block_io_op(unsigned int op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_block_io_op),
        "b" (op) ); 

    return ret;
}

static inline int HYPERVISOR_set_debugreg(int reg, unsigned long value)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_debugreg),
        "b" (reg), "c" (value) );

    return ret;
}

static inline unsigned long HYPERVISOR_get_debugreg(int reg)
{
    unsigned long ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_get_debugreg),
        "b" (reg) );

    return ret;
}

static inline int HYPERVISOR_update_descriptor(
    unsigned long pa, unsigned long word1, unsigned long word2)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_update_descriptor), 
        "b" (pa), "c" (word1), "d" (word2) );

    return ret;
}

static inline int HYPERVISOR_set_fast_trap(int idx)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_fast_trap), 
        "b" (idx) );

    return ret;
}

static inline int HYPERVISOR_dom_mem_op(void *dom_mem_op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_dom_mem_op),
        "b" (dom_mem_op) : "memory" );

    return ret;
}

static inline int HYPERVISOR_multicall(void *call_list, int nr_calls)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_multicall),
        "b" (call_list), "c" (nr_calls) : "memory" );

    return ret;
}

static inline long HYPERVISOR_kbd_op(unsigned char op, unsigned char val)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_kbd_op),
        "b" (op), "c" (val) );

    return ret;
}

static inline int HYPERVISOR_update_va_mapping(
    unsigned long page_nr, unsigned long new_val, unsigned long flags)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_update_va_mapping), 
        "b" (page_nr), "c" (new_val), "d" (flags) );

    return ret;
}

#endif /* __HYPERVISOR_H__ */
