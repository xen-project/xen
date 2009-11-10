/******************************************************************************
 * platform_hypercall.c
 */

#include <xen/config.h>
#include <xen/types.h>
#include <compat/platform.h>

DEFINE_XEN_GUEST_HANDLE(compat_platform_op_t);
#define xen_platform_op     compat_platform_op
#define xen_platform_op_t   compat_platform_op_t
#define do_platform_op(x)   compat_platform_op(_##x)

#define xen_processor_px    compat_processor_px
#define xen_processor_px_t  compat_processor_px_t
#define xen_processor_performance    compat_processor_performance
#define xen_processor_performance_t  compat_processor_performance_t
#define xenpf_set_processor_pminfo   compat_pf_set_processor_pminfo

#define set_px_pminfo		compat_set_px_pminfo

#define xen_processor_power     compat_processor_power
#define xen_processor_power_t   compat_processor_power_t
#define set_cx_pminfo           compat_set_cx_pminfo

DEFINE_XEN_GUEST_HANDLE(compat_physical_cpuinfo_t);
#define xen_physical_cpuinfo compat_physical_cpuinfo
#define xen_physical_cpuinfo_t compat_physical_cpuinfo_t
#define xenpf_pcpu_info compat_pf_pcpu_info
#define xenpf_pcpu_info_t compat_pf_pcpu_info_t

#define xenpf_enter_acpi_sleep compat_pf_enter_acpi_sleep

#define COMPAT
#define _XEN_GUEST_HANDLE(t) XEN_GUEST_HANDLE(t)
typedef int ret_t;

#include "../platform_hypercall.c"

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
