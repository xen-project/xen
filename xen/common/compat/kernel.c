/******************************************************************************
 * kernel.c
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/version.h>
#include <xen/sched.h>
#include <xen/nmi.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <compat/xen.h>
#include <compat/nmi.h>
#include <compat/version.h>

extern xen_commandline_t saved_cmdline;

#define xen_extraversion compat_extraversion
#define xen_extraversion_t compat_extraversion_t

#define xen_compile_info compat_compile_info
#define xen_compile_info_t compat_compile_info_t

CHECK_TYPE(capabilities_info);

#define xen_platform_parameters compat_platform_parameters
#define xen_platform_parameters_t compat_platform_parameters_t
#undef HYPERVISOR_VIRT_START
#define HYPERVISOR_VIRT_START HYPERVISOR_COMPAT_VIRT_START(current->domain)

#define xen_changeset_info compat_changeset_info
#define xen_changeset_info_t compat_changeset_info_t

#define xen_feature_info compat_feature_info
#define xen_feature_info_t compat_feature_info_t

CHECK_TYPE(domain_handle);

#define xennmi_callback compat_nmi_callback
#define xennmi_callback_t compat_nmi_callback_t

#define DO(fn) int compat_##fn
#define COMPAT

#include "../kernel.c"

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
