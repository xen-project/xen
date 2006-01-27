/******************************************************************************
 * asm-x86/hypercall.h
 */

#ifndef __ASM_X86_HYPERCALL_H__
#define __ASM_X86_HYPERCALL_H__

struct trap_info;
extern long
do_set_trap_table(
    struct trap_info *traps);

struct mmu_update;
extern int
do_mmu_update(
    struct mmu_update *ureqs,
    unsigned int count,
    unsigned int *pdone,
    unsigned int foreigndom);

extern long
do_set_gdt(
    unsigned long *frame_list,
    unsigned int entries);

extern long
do_stack_switch(
    unsigned long ss,
    unsigned long esp);

extern long
do_fpu_taskswitch(
    int set);

extern long
do_set_debugreg(
    int reg,
    unsigned long value);

extern unsigned long
do_get_debugreg(
    int reg);

extern long
do_update_descriptor(
    u64 pa,
    u64 desc);

extern int
do_update_va_mapping(
    unsigned long va,
    u64 val64,
    unsigned long flags);

struct physdev_op;
extern long
do_physdev_op(
    struct physdev_op *uop);

extern int
do_update_va_mapping_otherdomain(
    unsigned long va,
    u64 val64,
    unsigned long flags,
    domid_t domid);

extern int
do_mmuext_op(
    struct mmuext_op *uops,
    unsigned int count,
    unsigned int *pdone,
    unsigned int foreigndom);

extern unsigned long
do_iret(
    void);

#ifdef __x86_64__

extern long
do_set_callbacks(
    unsigned long event_address,
    unsigned long failsafe_address,
    unsigned long syscall_address);

extern long
do_set_segment_base(
    unsigned int which,
    unsigned long base);

#else

extern long
do_set_callbacks(
    unsigned long event_selector,
    unsigned long event_address,
    unsigned long failsafe_selector,
    unsigned long failsafe_address);

#endif

#endif /* __ASM_X86_HYPERCALL_H__ */
