/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * xc_version.c
 *
 * Wrappers aound XENVER_* hypercalls
 */

#include "xc_private.h"
#include <assert.h>

static int do_xen_version(xc_interface *xch, int cmd,
                          xc_hypercall_buffer_t *dest)
{
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(dest);
    return xencall2(xch->xcall, __HYPERVISOR_xen_version,
                    cmd, HYPERCALL_BUFFER_AS_ARG(dest));
}

int xc_version(xc_interface *xch, int cmd, void *arg)
{
    DECLARE_HYPERCALL_BOUNCE(arg, 0, XC_HYPERCALL_BUFFER_BOUNCE_OUT); /* Size unknown until cmd decoded */
    size_t sz;
    int rc;

    switch ( cmd )
    {
    case XENVER_version:
        sz = 0;
        break;
    case XENVER_extraversion:
        sz = sizeof(xen_extraversion_t);
        break;
    case XENVER_compile_info:
        sz = sizeof(xen_compile_info_t);
        break;
    case XENVER_capabilities:
        sz = sizeof(xen_capabilities_info_t);
        break;
    case XENVER_changeset:
        sz = sizeof(xen_changeset_info_t);
        break;
    case XENVER_platform_parameters:
        sz = sizeof(xen_platform_parameters_t);
        break;
    case XENVER_get_features:
        sz = sizeof(xen_feature_info_t);
        break;
    case XENVER_pagesize:
        sz = 0;
        break;
    case XENVER_guest_handle:
        sz = sizeof(xen_domain_handle_t);
        break;
    case XENVER_commandline:
        sz = sizeof(xen_commandline_t);
        break;
    case XENVER_build_id:
        {
            xen_build_id_t *build_id = (xen_build_id_t *)arg;
            sz = sizeof(*build_id) + build_id->len;
            HYPERCALL_BOUNCE_SET_DIR(arg, XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
            break;
        }
    default:
        ERROR("xc_version: unknown command %d\n", cmd);
        return -EINVAL;
    }

    HYPERCALL_BOUNCE_SET_SIZE(arg, sz);

    if ( (sz != 0) && xc_hypercall_bounce_pre(xch, arg) )
    {
        PERROR("Could not bounce buffer for version hypercall");
        return -ENOMEM;
    }

    rc = do_xen_version(xch, cmd, HYPERCALL_BUFFER(arg));

    if ( sz != 0 )
        xc_hypercall_bounce_post(xch, arg);

    return rc;
}
