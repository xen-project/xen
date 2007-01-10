/******************************************************************************
 * asm-x86/hypercall.h
 */

#ifndef __ASM_X86_HYPERCALL_H__
#define __ASM_X86_HYPERCALL_H__

#include <public/physdev.h>
#include <xen/types.h>

/*
 * Both do_mmuext_op() and do_mmu_update():
 * We steal the m.s.b. of the @count parameter to indicate whether this
 * invocation of do_mmu_update() is resuming a previously preempted call.
 */
#define MMU_UPDATE_PREEMPTED          (~(~0U>>1))

extern long
do_event_channel_op_compat(
    XEN_GUEST_HANDLE(evtchn_op_t) uop);

extern long
do_physdev_op_compat(
    XEN_GUEST_HANDLE(physdev_op_t) uop);

extern long
do_set_trap_table(
    XEN_GUEST_HANDLE(trap_info_t) traps);

extern int
do_mmu_update(
    XEN_GUEST_HANDLE(mmu_update_t) ureqs,
    unsigned int count,
    XEN_GUEST_HANDLE(uint) pdone,
    unsigned int foreigndom);

extern long
do_set_gdt(
    XEN_GUEST_HANDLE(ulong) frame_list,
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

extern long
do_physdev_op(
    int cmd, XEN_GUEST_HANDLE(void) arg);

extern int
do_update_va_mapping_otherdomain(
    unsigned long va,
    u64 val64,
    unsigned long flags,
    domid_t domid);

extern int
do_mmuext_op(
    XEN_GUEST_HANDLE(mmuext_op_t) uops,
    unsigned int count,
    XEN_GUEST_HANDLE(uint) pdone,
    unsigned int foreigndom);

extern unsigned long
do_iret(
    void);

struct vcpu;
extern long
arch_do_vcpu_op(
    int cmd, struct vcpu *v, XEN_GUEST_HANDLE(void) arg);

extern int
do_kexec(
    unsigned long op, unsigned arg1, XEN_GUEST_HANDLE(void) uarg);

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

#ifdef CONFIG_COMPAT

extern int
compat_physdev_op(
    int cmd,
    XEN_GUEST_HANDLE(void) arg);

extern int
arch_compat_vcpu_op(
    int cmd, struct vcpu *v, XEN_GUEST_HANDLE(void) arg);

#endif

#endif /* __ASM_X86_HYPERCALL_H__ */
