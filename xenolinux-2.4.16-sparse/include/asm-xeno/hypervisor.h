/******************************************************************************
 * hypervisor.h
 * 
 * Linux-specific hypervisor handling.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#ifndef __HYPERVISOR_H__
#define __HYPERVISOR_H__

#include <asm/hypervisor-ifs/hypervisor-if.h>
#include <asm/ptrace.h>

/* arch/xeno/kernel/setup.c */
union start_info_union
{
    start_info_t start_info;
    char padding[512];
};
extern union start_info_union start_info_union;
#define start_info (start_info_union.start_info)

/* arch/xeno/kernel/hypervisor.c */
void do_hypervisor_callback(struct pt_regs *regs);

/* arch/xeno/mm/hypervisor.c */
/*
 * NB. ptr values should be fake-physical. 'vals' should be alread
 * fully adjusted (ie. for start_info.phys_base).
 */
void queue_l1_entry_update(unsigned long ptr, unsigned long val);
void queue_l2_entry_update(unsigned long ptr, unsigned long val);
void queue_baseptr_create(unsigned long ptr);
void queue_baseptr_remove(unsigned long ptr);
void queue_tlb_flush(void);
void queue_tlb_flush_one(unsigned long ptr);
void flush_page_update_queue(void);


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


static inline int HYPERVISOR_pt_update(page_update_request_t *req, int count)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_pt_update), 
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

static inline int HYPERVISOR_set_pagetable(unsigned long ptr)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_pagetable),
        "b" (ptr) );

    return ret;
}

static inline int HYPERVISOR_set_guest_stack(
    unsigned long ss, unsigned long esp)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_guest_stack),
        "b" (ss), "c" (esp) );

    return ret;
}

static inline int HYPERVISOR_net_update(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_net_update) );

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
        : "=a" (ret) : "0" (__HYPERVISOR_yield) );

    return ret;
}

static inline int HYPERVISOR_exit(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_exit) );

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

#endif /* __HYPERVISOR_H__ */
