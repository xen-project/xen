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

/* Needs to be after asm/hypercall.h. */
#include <xen/hypercall-defs.h>

extern long
arch_do_domctl(
    struct xen_domctl *domctl, struct domain *d,
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl);

extern long
arch_do_sysctl(
    struct xen_sysctl *sysctl,
    XEN_GUEST_HANDLE_PARAM(xen_sysctl_t) u_sysctl);

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

extern long
common_vcpu_op(int cmd,
    struct vcpu *v,
    XEN_GUEST_HANDLE_PARAM(void) arg);

#endif /* __XEN_HYPERCALL_H__ */
