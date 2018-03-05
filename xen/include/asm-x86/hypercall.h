/******************************************************************************
 * asm-x86/hypercall.h
 */

#ifndef __ASM_X86_HYPERCALL_H__
#define __ASM_X86_HYPERCALL_H__

#include <xen/types.h>
#include <public/physdev.h>
#include <public/event_channel.h>
#include <public/arch-x86/xen-mca.h> /* for do_mca */
#include <asm/paging.h>

typedef unsigned long hypercall_fn_t(
    unsigned long, unsigned long, unsigned long,
    unsigned long, unsigned long, unsigned long);

typedef struct {
    hypercall_fn_t *native, *compat;
} hypercall_table_t;

typedef struct {
    uint8_t native, compat;
} hypercall_args_t;

extern const hypercall_args_t hypercall_args_table[NR_hypercalls];

void pv_hypercall(struct cpu_user_regs *regs);
void hypercall_page_initialise_ring3_kernel(void *hypercall_page);
void hypercall_page_initialise_ring1_kernel(void *hypercall_page);
void pv_hypercall_table_replace(unsigned int hypercall, hypercall_fn_t * native,
                                hypercall_fn_t *compat);
hypercall_fn_t *pv_get_hypercall_handler(unsigned int hypercall, bool compat);

/*
 * Both do_mmuext_op() and do_mmu_update():
 * We steal the m.s.b. of the @count parameter to indicate whether this
 * invocation of do_mmu_update() is resuming a previously preempted call.
 */
#define MMU_UPDATE_PREEMPTED          (~(~0U>>1))

extern long
do_event_channel_op_compat(
    XEN_GUEST_HANDLE_PARAM(evtchn_op_t) uop);

/* Legacy hypercall (as of 0x00030202). */
extern long do_physdev_op_compat(
    XEN_GUEST_HANDLE(physdev_op_t) uop);

/* Legacy hypercall (as of 0x00030101). */
extern long do_sched_op_compat(
    int cmd, unsigned long arg);

extern long
do_set_trap_table(
    XEN_GUEST_HANDLE_PARAM(const_trap_info_t) traps);

extern long
do_mmu_update(
    XEN_GUEST_HANDLE_PARAM(mmu_update_t) ureqs,
    unsigned int count,
    XEN_GUEST_HANDLE_PARAM(uint) pdone,
    unsigned int foreigndom);

extern long
do_set_gdt(
    XEN_GUEST_HANDLE_PARAM(xen_ulong_t) frame_list,
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

extern long
do_mca(XEN_GUEST_HANDLE_PARAM(xen_mc_t) u_xen_mc);

extern long
do_update_va_mapping(
    unsigned long va,
    u64 val64,
    unsigned long flags);

extern long
do_physdev_op(
    int cmd, XEN_GUEST_HANDLE_PARAM(void) arg);

extern long
do_update_va_mapping_otherdomain(
    unsigned long va,
    u64 val64,
    unsigned long flags,
    domid_t domid);

extern long
do_mmuext_op(
    XEN_GUEST_HANDLE_PARAM(mmuext_op_t) uops,
    unsigned int count,
    XEN_GUEST_HANDLE_PARAM(uint) pdone,
    unsigned int foreigndom);

extern long do_callback_op(
    int cmd, XEN_GUEST_HANDLE_PARAM(const_void) arg);

extern unsigned long
do_iret(
    void);

extern long
do_set_callbacks(
    unsigned long event_address,
    unsigned long failsafe_address,
    unsigned long syscall_address);

extern long
do_set_segment_base(
    unsigned int which,
    unsigned long base);

#ifdef CONFIG_COMPAT

#include <compat/arch-x86/xen.h>
#include <compat/physdev.h>

extern int
compat_physdev_op(
    int cmd,
    XEN_GUEST_HANDLE_PARAM(void) arg);

extern int
arch_compat_vcpu_op(
    int cmd, struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg);

extern int compat_mmuext_op(
    XEN_GUEST_HANDLE_PARAM(void) arg,
    unsigned int count,
    XEN_GUEST_HANDLE_PARAM(uint) pdone,
    unsigned int foreigndom);

extern int compat_platform_op(
    XEN_GUEST_HANDLE_PARAM(void) u_xenpf_op);

extern long compat_callback_op(
    int cmd, XEN_GUEST_HANDLE(void) arg);

extern int compat_update_va_mapping(
    unsigned int va, u32 lo, u32 hi, unsigned int flags);

extern int compat_update_va_mapping_otherdomain(
    unsigned long va, u32 lo, u32 hi, unsigned long flags, domid_t domid);

DEFINE_XEN_GUEST_HANDLE(trap_info_compat_t);
extern int compat_set_trap_table(XEN_GUEST_HANDLE(trap_info_compat_t) traps);

extern int compat_set_gdt(
    XEN_GUEST_HANDLE_PARAM(uint) frame_list, unsigned int entries);

extern int compat_update_descriptor(
    u32 pa_lo, u32 pa_hi, u32 desc_lo, u32 desc_hi);

extern unsigned int compat_iret(void);

extern int compat_nmi_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg);

extern long compat_set_callbacks(
    unsigned long event_selector, unsigned long event_address,
    unsigned long failsafe_selector, unsigned long failsafe_address);

DEFINE_XEN_GUEST_HANDLE(physdev_op_compat_t);
extern int compat_physdev_op_compat(XEN_GUEST_HANDLE(physdev_op_compat_t) uop);

#endif /* CONFIG_COMPAT */

#endif /* __ASM_X86_HYPERCALL_H__ */
