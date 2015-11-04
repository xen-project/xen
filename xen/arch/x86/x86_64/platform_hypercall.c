/******************************************************************************
 * platform_hypercall.c
 */

asm(".file \"" __FILE__ "\"");

#include <xen/lib.h>
#include <compat/platform.h>

DEFINE_XEN_GUEST_HANDLE(compat_platform_op_t);
#define xen_platform_op     compat_platform_op
#define xen_platform_op_t   compat_platform_op_t
#define do_platform_op(x)   compat_platform_op(_##x)

#define efi_get_info        efi_compat_get_info
#define efi_runtime_call(x) efi_compat_runtime_call(x)

#define xen_processor_performance compat_processor_performance
#define set_px_pminfo       compat_set_px_pminfo

#define xen_processor_power compat_processor_power
#define set_cx_pminfo       compat_set_cx_pminfo

#define xen_pf_pcpuinfo xenpf_pcpuinfo
CHECK_pf_pcpuinfo;
#undef xen_pf_pcpuinfo

#define xen_pf_pcpu_version xenpf_pcpu_version
CHECK_pf_pcpu_version;
#undef xen_pf_pcpu_version

#define xen_pf_enter_acpi_sleep xenpf_enter_acpi_sleep
CHECK_pf_enter_acpi_sleep;
#undef xen_pf_enter_acpi_sleep

#define xen_pf_resource_entry xenpf_resource_entry
CHECK_pf_resource_entry;
#undef xen_pf_resource_entry

#define COMPAT
#define _XEN_GUEST_HANDLE(t) XEN_GUEST_HANDLE(t)
#define _XEN_GUEST_HANDLE_PARAM(t) XEN_GUEST_HANDLE_PARAM(t)
typedef int ret_t;

#include "../platform_hypercall.c"

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
