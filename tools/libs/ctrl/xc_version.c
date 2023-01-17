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

/*
 * Raw hypercall wrapper, letting us pass NULL and things which aren't of
 * xc_hypercall_buffer_t *.
 */
static int do_xen_version_raw(xc_interface *xch, int cmd, void *hbuf)
{
    return xencall2(xch->xcall, __HYPERVISOR_xen_version,
                    cmd, (unsigned long)hbuf);
}

/*
 * Issues a xen_varbuf_t subop, using manual hypercall buffer handling to
 * avoid unnecessary buffering.
 *
 * On failure, returns NULL.  errno probably useful.
 * On success, returns a pointer which must be freed with xencall_free_buffer().
 */
static xen_varbuf_t *varbuf_op(xc_interface *xch, unsigned int subop)
{
    xen_varbuf_t *hbuf = NULL;
    ssize_t sz;

    sz = do_xen_version_raw(xch, subop, NULL);
    if ( sz < 0 )
        return NULL;

    hbuf = xencall_alloc_buffer(xch->xcall, sizeof(*hbuf) + sz);
    if ( !hbuf )
        return NULL;

    hbuf->len = sz;

    sz = do_xen_version_raw(xch, subop, hbuf);
    if ( sz < 0 )
    {
        xencall_free_buffer(xch->xcall, hbuf);
        return NULL;
    }

    hbuf->len = sz;
    return hbuf;
}

/*
 * Wrap varbuf_op() to obtain a simple string.  Copy out of the hypercall
 * buffer, stripping the xen_varbuf_t header and appending a NUL terminator.
 *
 * On failure, returns NULL, errno probably useful.
 * On success, returns a pointer which must be free()'d.
 */
static char *varbuf_simple_string(xc_interface *xch, unsigned int subop)
{
    xen_varbuf_t *hbuf = varbuf_op(xch, subop);
    char *res;

    if ( !hbuf )
        return NULL;

    res = malloc(hbuf->len + 1);
    if ( res )
    {
        memcpy(res, hbuf->buf, hbuf->len);
        res[hbuf->len] = '\0';
    }

    xencall_free_buffer(xch->xcall, hbuf);

    return res;
}

char *xc_xenver_extraversion(xc_interface *xch)
{
    return varbuf_simple_string(xch, XENVER_extraversion2);
}

char *xc_xenver_capabilities(xc_interface *xch)
{
    return varbuf_simple_string(xch, XENVER_capabilities2);
}

char *xc_xenver_changeset(xc_interface *xch)
{
    return varbuf_simple_string(xch, XENVER_changeset2);
}

char *xc_xenver_commandline(xc_interface *xch)
{
    return varbuf_simple_string(xch, XENVER_commandline2);
}

static void str2hex(char *dst, const unsigned char *src, size_t n)
{
    static const unsigned char hex[] = "0123456789abcdef";

    for ( ; n; n-- )
    {
        unsigned char c = *src++;

        *dst++ = hex[c >> 4];
        *dst++ = hex[c & 0xf];
    }
}

char *xc_xenver_buildid(xc_interface *xch)
{
    xen_varbuf_t *hbuf = varbuf_op(xch, XENVER_build_id);
    char *res;

    if ( !hbuf )
        return NULL;

    res = malloc((hbuf->len * 2) + 1);
    if ( res )
    {
        str2hex(res, hbuf->buf, hbuf->len);
        res[hbuf->len * 2] = '\0';
    }

    xencall_free_buffer(xch->xcall, hbuf);

    return res;
}
