/******************************************************************************
 * xen-compat.h
 * 
 * Guest OS interface to Xen.  Compatibility layer.
 * 
 * Copyright (c) 2006, Christian Limpach
 */

#ifndef __XEN_PUBLIC_XEN_COMPAT_H__
#define __XEN_PUBLIC_XEN_COMPAT_H__

#define __XEN_LATEST_INTERFACE_VERSION__ 0x00030202

#if defined(__XEN__) || defined(__XEN_TOOLS__)
/* Xen is built with matching headers and implements the latest interface. */
#define __XEN_INTERFACE_VERSION__ __XEN_LATEST_INTERFACE_VERSION__
#elif !defined(__XEN_INTERFACE_VERSION__)
/* Guests which do not specify a version get the legacy interface. */
#define __XEN_INTERFACE_VERSION__ 0x00000000
#endif

#if __XEN_INTERFACE_VERSION__ > __XEN_LATEST_INTERFACE_VERSION__
#error "These header files do not support the requested interface version."
#endif

/* New sched_op hypercall introduced in 0x00030101. */
#if __XEN_INTERFACE_VERSION__ < 0x00030101
#undef __HYPERVISOR_sched_op
#define __HYPERVISOR_sched_op __HYPERVISOR_sched_op_compat
#endif

/* Structural guest handles introduced in 0x00030201. */
#if __XEN_INTERFACE_VERSION__ < 0x00030201
#undef __DEFINE_XEN_GUEST_HANDLE
#define __DEFINE_XEN_GUEST_HANDLE(name, type) \
    typedef type * __guest_handle_ ## name
#endif

/* New event-channel and physdev hypercalls introduced in 0x00030202. */
#if __XEN_INTERFACE_VERSION__ < 0x00030202
#undef __HYPERVISOR_event_channel_op
#define __HYPERVISOR_event_channel_op __HYPERVISOR_event_channel_op_compat
#undef __HYPERVISOR_physdev_op
#define __HYPERVISOR_physdev_op __HYPERVISOR_physdev_op_compat
#endif

#endif /* __XEN_PUBLIC_XEN_COMPAT_H__ */
