/******************************************************************************
 * hypervisor.h
 * 
 * Linux-specific hypervisor handling.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#ifndef __HYPERVISOR_H__
#define __HYPERVISOR_H__


#include <machine/hypervisor-ifs.h>
#include <machine/frame.h>
#include "opt_xen.h"

extern start_info_t *xen_start_info;

/* arch/xen/mm/hypervisor.c */
/*
 * NB. ptr values should be PHYSICAL, not MACHINE. 'vals' should be already
 * be MACHINE addresses.
 */


void MULTICALL_flush_page_update_queue(void);

#ifdef CONFIG_XEN_PHYSDEV_ACCESS
/* Allocate a contiguous empty region of low memory. Return virtual start. */
unsigned long allocate_empty_lowmem_region(unsigned long pages);
/* Deallocate a contiguous region of low memory. Return it to the allocator. */
void deallocate_lowmem_region(unsigned long vstart, unsigned long pages);
#endif

typedef struct { unsigned long pte_low, pte_high; } pte_t;

/*
 * Assembler stubs for hyper-calls.
 */

static inline int HYPERVISOR_set_trap_table(trap_info_t *table)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_trap_table),
        "b" (table) : "memory" );

    return ret;
}

static inline int 
HYPERVISOR_mmu_update(mmu_update_t *req, int count, 
		      int *success_count, domid_t domid)
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



static inline int HYPERVISOR_set_gdt(unsigned long *frame_list, int entries)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_gdt), 
        "b" (frame_list), "c" (entries) : "memory" );


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

static inline int HYPERVISOR_fpu_taskswitch(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_fpu_taskswitch) : "memory" );

    return ret;
}

static inline int HYPERVISOR_yield(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        "b" (SCHEDOP_yield) : "memory" );

    return ret;
}

static inline int HYPERVISOR_block(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        "b" (SCHEDOP_block) : "memory" );

    return ret;
}

static inline int HYPERVISOR_shutdown(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
	"b" (SCHEDOP_shutdown | (SHUTDOWN_poweroff << SCHEDOP_reasonshift))
        : "memory" );

    return ret;
}

static inline int HYPERVISOR_reboot(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        "b" (SCHEDOP_shutdown | (SHUTDOWN_reboot << SCHEDOP_reasonshift))
        : "memory" );

    return ret;
}

static inline int HYPERVISOR_suspend(unsigned long srec)
{
    int ret;
    /* NB. On suspend, control software expects a suspend record in %esi. */
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
	"b" (SCHEDOP_shutdown | (SHUTDOWN_suspend << SCHEDOP_reasonshift)), 
        "S" (srec) : "memory" );

    return ret;
}

static inline long HYPERVISOR_set_timer_op(uint64_t timeout)
{
    int ret;
    unsigned long timeout_hi = (unsigned long)(timeout>>32);
    unsigned long timeout_lo = (unsigned long)timeout;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_timer_op),
        "b" (timeout_lo), "c" (timeout_hi) : "memory" );

    return ret;
}

static inline int HYPERVISOR_dom0_op(dom0_op_t *dom0_op)
{
    int ret;
    dom0_op->interface_version = DOM0_INTERFACE_VERSION;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_dom0_op),
        "b" (dom0_op) : "memory" );

    return ret;
}

static inline int HYPERVISOR_set_debugreg(int reg, unsigned long value)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_debugreg),
        "b" (reg), "c" (value) : "memory" );

    return ret;
}

static inline unsigned long HYPERVISOR_get_debugreg(int reg)
{
    unsigned long ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_get_debugreg),
        "b" (reg) : "memory" );

    return ret;
}

static inline int HYPERVISOR_update_descriptor(
    unsigned long pa, unsigned long word1, unsigned long word2)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_update_descriptor), 
        "b" (pa), "c" (word1), "d" (word2) : "memory" );

    return ret;
}

static inline int HYPERVISOR_set_fast_trap(int idx)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_fast_trap), 
        "b" (idx) : "memory" );

    return ret;
}

static inline int HYPERVISOR_dom_mem_op(unsigned int   op,
					unsigned long *pages,
					unsigned long  nr_pages)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_dom_mem_op),
	"b" (op), "c" (pages), "d" (nr_pages) : "memory" );
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

static inline int HYPERVISOR_update_va_mapping(
    unsigned long page_nr, unsigned long new_val, unsigned long flags)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_update_va_mapping), 
	"b" (page_nr), "c" (new_val), "d" (flags):
	"memory" );
    /* XXX */
#if 0
    if ( unlikely(ret < 0) )
        panic("Failed update VA mapping: %08lx, %08lx, %08lx",
              page_nr, (new_val).pte_low, flags);
#endif
    return ret;
}

static inline int HYPERVISOR_event_channel_op(void *op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_event_channel_op),
        "b" (op) : "memory" );

    return ret;
}

static inline int HYPERVISOR_xen_version(int cmd)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_xen_version), 
        "b" (cmd) : "memory" );

    return ret;
}

static inline int HYPERVISOR_console_io(int cmd, int count, char *str)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_console_io),
        "b" (cmd), "c" (count), "d" (str) : "memory" );

    return ret;
}

static __inline int HYPERVISOR_console_write(char *str, int count)
{
    return HYPERVISOR_console_io(CONSOLEIO_write, count, str); 
}

static inline int HYPERVISOR_physdev_op(void *physdev_op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_physdev_op),
        "b" (physdev_op) : "memory" );

    return ret;
}

static inline int HYPERVISOR_update_va_mapping_otherdomain(
    unsigned long page_nr, pte_t new_val, unsigned long flags, domid_t domid)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_update_va_mapping_otherdomain), 
        "b" (page_nr), "c" ((new_val).pte_low), "d" (flags), "S" (domid) :
        "memory" );
    
    return ret;
} 

static inline int HYPERVISOR_vm_assist(unsigned int cmd, unsigned int type)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_vm_assist),
        "b" (cmd), "c" (type) : "memory" );

    return ret;
}

#endif /* __HYPERVISOR_H__ */
