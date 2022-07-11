/******************************************************************************
 * hypercall.h
 */

#ifndef __XEN_HYPERCALL_H__
#define __XEN_HYPERCALL_H__

#include <xen/types.h>
#include <xen/time.h>
#include <public/xen.h>
#include <public/domctl.h>
#include <public/sysctl.h>
#include <public/platform.h>
#include <public/event_channel.h>
#include <public/version.h>
#include <public/pmu.h>
#include <public/hvm/dm_op.h>
#ifdef CONFIG_COMPAT
#include <compat/platform.h>
#endif
#include <asm/hypercall.h>
#include <xsm/xsm.h>

extern long cf_check
do_sched_op(
    int cmd,
    XEN_GUEST_HANDLE_PARAM(void) arg);

extern long cf_check
do_domctl(
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl);

extern long
arch_do_domctl(
    struct xen_domctl *domctl, struct domain *d,
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl);

extern long cf_check
do_sysctl(
    XEN_GUEST_HANDLE_PARAM(xen_sysctl_t) u_sysctl);

extern long
arch_do_sysctl(
    struct xen_sysctl *sysctl,
    XEN_GUEST_HANDLE_PARAM(xen_sysctl_t) u_sysctl);

extern long cf_check
do_platform_op(
    XEN_GUEST_HANDLE_PARAM(xen_platform_op_t) u_xenpf_op);

extern long
pci_physdev_op(
    int cmd, XEN_GUEST_HANDLE_PARAM(void) arg);

/*
 * To allow safe resume of do_memory_op() after preemption, we need to know
 * at what point in the page list to resume. For this purpose I steal the
 * high-order bits of the @cmd parameter, which are otherwise unused and zero.
 *
 * Note that both of these values are effectively part of the ABI, even if
 * we don't need to make them a formal part of it: A guest suspended for
 * migration in the middle of a continuation would fail to work if resumed on
 * a hypervisor using different values.
 */
#define MEMOP_EXTENT_SHIFT 6 /* cmd[:6] == start_extent */
#define MEMOP_CMD_MASK     ((1 << MEMOP_EXTENT_SHIFT) - 1)

extern long cf_check
do_memory_op(
    unsigned long cmd,
    XEN_GUEST_HANDLE_PARAM(void) arg);

extern long cf_check
do_multicall(
    XEN_GUEST_HANDLE_PARAM(multicall_entry_t) call_list,
    unsigned int nr_calls);

extern long cf_check
do_set_timer_op(
    s_time_t timeout);

extern long cf_check
do_event_channel_op(
    int cmd, XEN_GUEST_HANDLE_PARAM(void) arg);

extern long cf_check
do_xen_version(
    int cmd,
    XEN_GUEST_HANDLE_PARAM(void) arg);

extern long cf_check
do_console_io(
    unsigned int cmd,
    unsigned int count,
    XEN_GUEST_HANDLE_PARAM(char) buffer);

extern long cf_check
do_grant_table_op(
    unsigned int cmd,
    XEN_GUEST_HANDLE_PARAM(void) uop,
    unsigned int count);

extern long cf_check
do_vm_assist(
    unsigned int cmd,
    unsigned int type);

extern long cf_check
do_vcpu_op(
    int cmd,
    unsigned int vcpuid,
    XEN_GUEST_HANDLE_PARAM(void) arg);

struct vcpu;
extern long
common_vcpu_op(int cmd,
    struct vcpu *v,
    XEN_GUEST_HANDLE_PARAM(void) arg);

extern long cf_check
do_hvm_op(
    unsigned long op,
    XEN_GUEST_HANDLE_PARAM(void) arg);

extern long cf_check
do_kexec_op(
    unsigned int op,
    XEN_GUEST_HANDLE_PARAM(void) uarg);

extern long cf_check
do_xsm_op(
    XEN_GUEST_HANDLE_PARAM(void) u_xsm_op);

#ifdef CONFIG_ARGO
extern long cf_check do_argo_op(
    unsigned int cmd,
    XEN_GUEST_HANDLE_PARAM(void) arg1,
    XEN_GUEST_HANDLE_PARAM(void) arg2,
    unsigned long arg3,
    unsigned long arg4);
#endif

extern long cf_check
do_xenoprof_op(int op, XEN_GUEST_HANDLE_PARAM(void) arg);

extern long cf_check
do_dm_op(
    domid_t domid,
    unsigned int nr_bufs,
    XEN_GUEST_HANDLE_PARAM(xen_dm_op_buf_t) bufs);

#ifdef CONFIG_HYPFS
extern long cf_check
do_hypfs_op(
    unsigned int cmd,
    XEN_GUEST_HANDLE_PARAM(const_char) arg1,
    unsigned long arg2,
    XEN_GUEST_HANDLE_PARAM(void) arg3,
    unsigned long arg4);
#endif

#ifdef CONFIG_COMPAT

extern int cf_check
compat_memory_op(
    unsigned int cmd,
    XEN_GUEST_HANDLE_PARAM(void) arg);

extern int cf_check
compat_grant_table_op(
    unsigned int cmd,
    XEN_GUEST_HANDLE_PARAM(void) uop,
    unsigned int count);

extern int cf_check
compat_vcpu_op(
    int cmd,
    unsigned int vcpuid,
    XEN_GUEST_HANDLE_PARAM(void) arg);

extern int cf_check
compat_xenoprof_op(int op, XEN_GUEST_HANDLE_PARAM(void) arg);

extern int cf_check
compat_xen_version(
    int cmd,
    XEN_GUEST_HANDLE_PARAM(void) arg);

extern int cf_check
compat_sched_op(
    int cmd,
    XEN_GUEST_HANDLE_PARAM(void) arg);

extern int cf_check
compat_set_timer_op(
    uint32_t lo,
    int32_t hi);

extern int cf_check compat_xsm_op(
    XEN_GUEST_HANDLE_PARAM(void) op);

extern int cf_check compat_kexec_op(
    unsigned int op, XEN_GUEST_HANDLE_PARAM(void) uarg);

DEFINE_XEN_GUEST_HANDLE(multicall_entry_compat_t);
extern int cf_check compat_multicall(
    XEN_GUEST_HANDLE_PARAM(multicall_entry_compat_t) call_list,
    uint32_t nr_calls);

int compat_physdev_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg);

DEFINE_XEN_GUEST_HANDLE(compat_platform_op_t);
int compat_platform_op(XEN_GUEST_HANDLE_PARAM(compat_platform_op_t) u_xenpf_op);

#ifdef CONFIG_ARGO
extern int cf_check compat_argo_op(
    unsigned int cmd,
    XEN_GUEST_HANDLE_PARAM(void) arg1,
    XEN_GUEST_HANDLE_PARAM(void) arg2,
    unsigned long arg3,
    unsigned long arg4);
#endif

extern int cf_check
compat_dm_op(
    domid_t domid,
    unsigned int nr_bufs,
    XEN_GUEST_HANDLE_PARAM(void) bufs);

#endif

void arch_get_xen_caps(xen_capabilities_info_t *info);

#endif /* __XEN_HYPERCALL_H__ */
