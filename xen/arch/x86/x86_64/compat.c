/******************************************************************************
 * compat.c
 */

#include <xen/config.h>
#include <xen/hypercall.h>
#include <compat/xen.h>
#include <compat/physdev.h>

DEFINE_XEN_GUEST_HANDLE(physdev_op_compat_t);
#define physdev_op                    compat_physdev_op
#define physdev_op_t                  physdev_op_compat_t
#define do_physdev_op                 compat_physdev_op
#define do_physdev_op_compat(x)       compat_physdev_op_compat(_##x)

#define COMPAT
#define _XEN_GUEST_HANDLE(t) XEN_GUEST_HANDLE(t)
typedef int ret_t;

#include "../compat.c"

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
