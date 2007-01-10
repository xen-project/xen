/******************************************************************************
 * platform_hypercall.c
 *
 */

#include <xen/config.h>
#include <xen/types.h>
#include <compat/platform.h>

DEFINE_XEN_GUEST_HANDLE(compat_platform_op_t);
#define xen_platform_op     compat_platform_op
#define xen_platform_op_t   compat_platform_op_t
#define do_platform_op(x)   compat_platform_op(_##x)

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
