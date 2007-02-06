/******************************************************************************
 * physdev.c
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/guest_access.h>
#include <compat/xen.h>
#include <compat/event_channel.h>
#include <compat/physdev.h>
#include <asm/hypercall.h>

#define do_physdev_op compat_physdev_op

#define physdev_apic               compat_physdev_apic
#define physdev_apic_t             physdev_apic_compat_t

#define physdev_eoi                compat_physdev_eoi
#define physdev_eoi_t              physdev_eoi_compat_t

#define physdev_set_iobitmap       compat_physdev_set_iobitmap
#define physdev_set_iobitmap_t     physdev_set_iobitmap_compat_t

#define physdev_set_iopl           compat_physdev_set_iopl
#define physdev_set_iopl_t         physdev_set_iopl_compat_t

#define physdev_irq                compat_physdev_irq
#define physdev_irq_t              physdev_irq_compat_t

#define physdev_irq_status_query   compat_physdev_irq_status_query
#define physdev_irq_status_query_t physdev_irq_status_query_compat_t

#define COMPAT
#undef guest_handle_okay
#define guest_handle_okay          compat_handle_okay
typedef int ret_t;

#include "../physdev.c"

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
