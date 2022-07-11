/******************************************************************************
 * asm-x86/hypercall.h
 */

#ifndef __XEN_HYPERCALL_H__
#error "asm/hypercall.h should not be included directly - include xen/hypercall.h instead"
#endif

#ifndef __ASM_X86_HYPERCALL_H__
#define __ASM_X86_HYPERCALL_H__

#include <xen/types.h>
#include <public/physdev.h>
#include <public/event_channel.h>
#include <public/arch-x86/xen-mca.h> /* for do_mca */
#include <asm/paging.h>

#define __HYPERVISOR_paging_domctl_cont __HYPERVISOR_arch_1

typedef unsigned long hypercall_fn_t(
    unsigned long, unsigned long, unsigned long,
    unsigned long, unsigned long);

typedef struct {
    uint8_t native;
#ifdef CONFIG_COMPAT
    uint8_t compat;
#endif
} hypercall_args_t;

extern const hypercall_args_t hypercall_args_table[NR_hypercalls];

#ifdef CONFIG_PV
void pv_hypercall(struct cpu_user_regs *regs);
#endif

void pv_ring1_init_hypercall_page(void *ptr);
void pv_ring3_init_hypercall_page(void *ptr);

/*
 * Both do_mmuext_op() and do_mmu_update():
 * We steal the m.s.b. of the @count parameter to indicate whether this
 * invocation of do_mmu_update() is resuming a previously preempted call.
 */
#define MMU_UPDATE_PREEMPTED          (~(~0U>>1))

extern long cf_check
do_event_channel_op_compat(
    XEN_GUEST_HANDLE_PARAM(evtchn_op_t) uop);

/* Legacy hypercall (as of 0x00030202). */
extern long cf_check do_physdev_op_compat(
    XEN_GUEST_HANDLE(physdev_op_t) uop);

/* Legacy hypercall (as of 0x00030101). */
extern long cf_check do_sched_op_compat(
    int cmd, unsigned long arg);

extern long cf_check
do_set_trap_table(
    XEN_GUEST_HANDLE_PARAM(const_trap_info_t) traps);

extern long cf_check
do_mmu_update(
    XEN_GUEST_HANDLE_PARAM(mmu_update_t) ureqs,
    unsigned int count,
    XEN_GUEST_HANDLE_PARAM(uint) pdone,
    unsigned int foreigndom);

extern long cf_check
do_set_gdt(
    XEN_GUEST_HANDLE_PARAM(xen_ulong_t) frame_list,
    unsigned int entries);

extern long cf_check
do_stack_switch(
    unsigned long ss,
    unsigned long esp);

extern long cf_check
do_fpu_taskswitch(
    int set);

extern long cf_check
do_set_debugreg(
    int reg,
    unsigned long value);

extern long cf_check
do_get_debugreg(
    int reg);

extern long cf_check
do_update_descriptor(
    uint64_t gaddr, seg_desc_t desc);

extern long cf_check
do_mca(XEN_GUEST_HANDLE_PARAM(xen_mc_t) u_xen_mc);

extern long cf_check
do_update_va_mapping(
    unsigned long va,
    uint64_t val64,
    unsigned long flags);

extern long cf_check
do_physdev_op(
    int cmd, XEN_GUEST_HANDLE_PARAM(void) arg);

extern long cf_check
do_update_va_mapping_otherdomain(
    unsigned long va,
    uint64_t val64,
    unsigned long flags,
    domid_t domid);

extern long cf_check
do_mmuext_op(
    XEN_GUEST_HANDLE_PARAM(mmuext_op_t) uops,
    unsigned int count,
    XEN_GUEST_HANDLE_PARAM(uint) pdone,
    unsigned int foreigndom);

extern long cf_check do_callback_op(
    int cmd, XEN_GUEST_HANDLE_PARAM(const_void) arg);

extern long cf_check
do_iret(
    void);

extern long cf_check
do_set_callbacks(
    unsigned long event_address,
    unsigned long failsafe_address,
    unsigned long syscall_address);

extern long cf_check
do_set_segment_base(
    unsigned int which,
    unsigned long base);

long cf_check do_nmi_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg);

long cf_check do_xenpmu_op(unsigned int op,
                           XEN_GUEST_HANDLE_PARAM(xen_pmu_params_t) arg);

long cf_check do_paging_domctl_cont(
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl);

#ifdef CONFIG_COMPAT

#include <compat/arch-x86/xen.h>
#include <compat/physdev.h>
#include <compat/platform.h>

extern int
compat_common_vcpu_op(
    int cmd, struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg);

extern int cf_check compat_mmuext_op(
    XEN_GUEST_HANDLE_PARAM(void) arg,
    unsigned int count,
    XEN_GUEST_HANDLE_PARAM(uint) pdone,
    unsigned int foreigndom);

extern int cf_check compat_callback_op(
    int cmd, XEN_GUEST_HANDLE(const_void) arg);

extern int cf_check compat_update_va_mapping(
    unsigned int va, uint32_t lo, uint32_t hi, unsigned int flags);

extern int cf_check compat_update_va_mapping_otherdomain(
    unsigned int va, uint32_t lo, uint32_t hi, unsigned int flags, domid_t domid);

DEFINE_XEN_GUEST_HANDLE(trap_info_compat_t);
extern int cf_check compat_set_trap_table(
    XEN_GUEST_HANDLE(trap_info_compat_t) traps);

extern int cf_check compat_set_gdt(
    XEN_GUEST_HANDLE_PARAM(uint) frame_list, unsigned int entries);

extern int cf_check compat_update_descriptor(
    uint32_t pa_lo, uint32_t pa_hi, uint32_t desc_lo, uint32_t desc_hi);

extern int cf_check compat_iret(void);

extern int cf_check compat_nmi_op(
    unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg);

extern int cf_check compat_set_callbacks(
    unsigned long event_selector, unsigned long event_address,
    unsigned long failsafe_selector, unsigned long failsafe_address);

DEFINE_XEN_GUEST_HANDLE(physdev_op_compat_t);
extern int cf_check compat_physdev_op_compat(
    XEN_GUEST_HANDLE(physdev_op_compat_t) uop);

#endif /* CONFIG_COMPAT */

#endif /* __ASM_X86_HYPERCALL_H__ */
