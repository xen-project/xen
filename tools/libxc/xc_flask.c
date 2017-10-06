/******************************************************************************
 * xc_flask.c
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xc_private.h"
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>

#define OCON_ISID    0    /* initial SIDs */
#define OCON_PIRQ    1    /* physical irqs */
#define OCON_IOPORT  2    /* io ports */
#define OCON_IOMEM   3    /* io memory */
#define OCON_DEVICE  4    /* pci devices */
#define INITCONTEXTLEN  256

int xc_flask_op(xc_interface *xch, xen_flask_op_t *op)
{
    int ret = -1;
    DECLARE_HYPERCALL_BOUNCE(op, sizeof(*op), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    op->interface_version = XEN_FLASK_INTERFACE_VERSION;

    if ( xc_hypercall_bounce_pre(xch, op) )
    {
        PERROR("Could not bounce memory for flask op hypercall");
        goto out;
    }

    ret = xencall1(xch->xcall, __HYPERVISOR_xsm_op,
                   HYPERCALL_BUFFER_AS_ARG(op));
    if ( ret < 0 )
    {
        if ( errno == EACCES )
            fprintf(stderr, "XSM operation failed!\n");
    }

    xc_hypercall_bounce_post(xch, op);

 out:
    return ret;
}

int xc_flask_load(xc_interface *xch, char *buf, uint32_t size)
{
    int err;
    DECLARE_FLASK_OP;
    DECLARE_HYPERCALL_BOUNCE(buf, size, XC_HYPERCALL_BUFFER_BOUNCE_IN);
    if ( xc_hypercall_bounce_pre(xch, buf) )
    {
        PERROR("Could not bounce memory for flask op hypercall");
        return -1;
    }

    op.cmd = FLASK_LOAD;
    op.u.load.size = size;
    set_xen_guest_handle(op.u.load.buffer, buf);
    
    err = xc_flask_op(xch, &op);

    xc_hypercall_bounce_post(xch, buf);

    return err;
}

int xc_flask_context_to_sid(xc_interface *xch, char *buf, uint32_t size, uint32_t *sid)
{
    int err;
    DECLARE_FLASK_OP;
    DECLARE_HYPERCALL_BOUNCE(buf, size, XC_HYPERCALL_BUFFER_BOUNCE_IN);

    if ( xc_hypercall_bounce_pre(xch, buf) )
    {
        PERROR("Could not bounce memory for flask op hypercall");
        return -1;
    }

    op.cmd = FLASK_CONTEXT_TO_SID;
    op.u.sid_context.size = size;
    set_xen_guest_handle(op.u.sid_context.context, buf);
    
    err = xc_flask_op(xch, &op);

    if ( !err )
        *sid = op.u.sid_context.sid;

    xc_hypercall_bounce_post(xch, buf);

    return err;
}

int xc_flask_sid_to_context(xc_interface *xch, int sid, char *buf, uint32_t size)
{
    int err;
    DECLARE_FLASK_OP;
    DECLARE_HYPERCALL_BOUNCE(buf, size, XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( xc_hypercall_bounce_pre(xch, buf) )
    {
        PERROR("Could not bounce memory for flask op hypercall");
        return -1;
    }

    op.cmd = FLASK_SID_TO_CONTEXT;
    op.u.sid_context.sid = sid;
    op.u.sid_context.size = size;
    set_xen_guest_handle(op.u.sid_context.context, buf);
    
    err = xc_flask_op(xch, &op);

    xc_hypercall_bounce_post(xch, buf);
   
    return err;
}

int xc_flask_getenforce(xc_interface *xch)
{
    DECLARE_FLASK_OP;
    op.cmd = FLASK_GETENFORCE;
    
    return xc_flask_op(xch, &op);
}

int xc_flask_setenforce(xc_interface *xch, int mode)
{
    DECLARE_FLASK_OP;
    op.cmd = FLASK_SETENFORCE;
    op.u.enforce.enforcing = mode;
   
    return xc_flask_op(xch, &op);
}

int xc_flask_getbool_byid(xc_interface *xch, int id, char *name, uint32_t size, int *curr, int *pend)
{
    int rv;
    DECLARE_FLASK_OP;
    DECLARE_HYPERCALL_BOUNCE(name, size, XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( xc_hypercall_bounce_pre(xch, name) )
    {
        PERROR("Could not bounce memory for flask op hypercall");
        return -1;
    }

    op.cmd = FLASK_GETBOOL;
    op.u.boolean.bool_id = id;
    op.u.boolean.size = size;
    set_xen_guest_handle(op.u.boolean.name, name);

    rv = xc_flask_op(xch, &op);

    xc_hypercall_bounce_post(xch, name);

    if ( rv )
        return rv;
    
    if ( curr )
        *curr = op.u.boolean.enforcing;
    if ( pend )
        *pend = op.u.boolean.pending;

    return rv;
}

int xc_flask_getbool_byname(xc_interface *xch, char *name, int *curr, int *pend)
{
    int rv;
    DECLARE_FLASK_OP;
    DECLARE_HYPERCALL_BOUNCE(name, strlen(name), XC_HYPERCALL_BUFFER_BOUNCE_IN);

    if ( xc_hypercall_bounce_pre(xch, name) )
    {
        PERROR("Could not bounce memory for flask op hypercall");
        return -1;
    }

    op.cmd = FLASK_GETBOOL;
    op.u.boolean.bool_id = -1;
    op.u.boolean.size = strlen(name);
    set_xen_guest_handle(op.u.boolean.name, name);

    rv = xc_flask_op(xch, &op);

    xc_hypercall_bounce_post(xch, name);

    if ( rv )
        return rv;
    
    if ( curr )
        *curr = op.u.boolean.enforcing;
    if ( pend )
        *pend = op.u.boolean.pending;

    return rv;
}

int xc_flask_setbool(xc_interface *xch, char *name, int value, int commit)
{
    int rv;
    DECLARE_FLASK_OP;
    DECLARE_HYPERCALL_BOUNCE(name, strlen(name), XC_HYPERCALL_BUFFER_BOUNCE_IN);

    if ( xc_hypercall_bounce_pre(xch, name) )
    {
        PERROR("Could not bounce memory for flask op hypercall");
        return -1;
    }

    op.cmd = FLASK_SETBOOL;
    op.u.boolean.bool_id = -1;
    op.u.boolean.new_value = value;
    op.u.boolean.commit = 1;
    op.u.boolean.size = strlen(name);
    set_xen_guest_handle(op.u.boolean.name, name);

    rv = xc_flask_op(xch, &op);

    xc_hypercall_bounce_post(xch, name);

    return rv;
}


static int xc_flask_add(xc_interface *xch, uint32_t ocon, uint64_t low, uint64_t high, char *scontext)
{
    uint32_t sid;
    int err;
    DECLARE_FLASK_OP;

    err = xc_flask_context_to_sid(xch, scontext, strlen(scontext), &sid);
    if ( err )
        return err;

    op.cmd = FLASK_ADD_OCONTEXT;
    op.u.ocontext.ocon = ocon;
    op.u.ocontext.sid = sid;
    op.u.ocontext.low = low;
    op.u.ocontext.high = high;
    
    return xc_flask_op(xch, &op);
}

int xc_flask_add_pirq(xc_interface *xch, unsigned int pirq, char *scontext)
{
    return xc_flask_add(xch, OCON_PIRQ, pirq, pirq, scontext);
}

int xc_flask_add_ioport(xc_interface *xch, unsigned long low, unsigned long high,
                      char *scontext)
{
    return xc_flask_add(xch, OCON_IOPORT, low, high, scontext);
}

int xc_flask_add_iomem(xc_interface *xch, unsigned long low, unsigned long high,
                     char *scontext)
{
    return xc_flask_add(xch, OCON_IOMEM, low, high, scontext);
}

int xc_flask_add_device(xc_interface *xch, unsigned long device, char *scontext)
{
    return xc_flask_add(xch, OCON_DEVICE, device, device, scontext);
}

static int xc_flask_del(xc_interface *xch, uint32_t ocon, uint64_t low, uint64_t high)
{
    DECLARE_FLASK_OP;

    op.cmd = FLASK_DEL_OCONTEXT;
    op.u.ocontext.ocon = ocon;
    op.u.ocontext.low = low;
    op.u.ocontext.high = high;
    
    return xc_flask_op(xch, &op);
}

int xc_flask_del_pirq(xc_interface *xch, unsigned int pirq)
{
    return xc_flask_del(xch, OCON_PIRQ, pirq, pirq);
}

int xc_flask_del_ioport(xc_interface *xch, unsigned long low, unsigned long high)
{
    return xc_flask_del(xch, OCON_IOPORT, low, high);
}

int xc_flask_del_iomem(xc_interface *xch, unsigned long low, unsigned long high)
{
    return xc_flask_del(xch, OCON_IOMEM, low, high);
}

int xc_flask_del_device(xc_interface *xch, unsigned long device)
{
    return xc_flask_del(xch, OCON_DEVICE, device, device);
}

int xc_flask_access(xc_interface *xch, const char *scon, const char *tcon,
                uint16_t tclass, uint32_t req,
                uint32_t *allowed, uint32_t *decided,
                uint32_t *auditallow, uint32_t *auditdeny,
                uint32_t *seqno)
{
    DECLARE_FLASK_OP;
    int err;

    err = xc_flask_context_to_sid(xch, (char*)scon, strlen(scon), &op.u.access.ssid);
    if ( err )
        return err;
    err = xc_flask_context_to_sid(xch, (char*)tcon, strlen(tcon), &op.u.access.tsid);
    if ( err )
        return err;

    op.cmd = FLASK_ACCESS;
    op.u.access.tclass = tclass;
    op.u.access.req = req;
    
    err = xc_flask_op(xch, &op);

    if ( err )
        return err;

    if ( allowed )
        *allowed = op.u.access.allowed;
    if ( decided )
        *decided = 0xffffffff;
    if ( auditallow )
        *auditallow = op.u.access.audit_allow;
    if ( auditdeny )
        *auditdeny = op.u.access.audit_deny;
    if ( seqno )
        *seqno = op.u.access.seqno;

    if ( (op.u.access.allowed & req) != req )
        err = -EPERM;

    return err;
}

int xc_flask_avc_hashstats(xc_interface *xch, char *buf, int size)
{
    int err;
    DECLARE_FLASK_OP;
  
    op.cmd = FLASK_AVC_HASHSTATS;
  
    err = xc_flask_op(xch, &op);

    snprintf(buf, size,
             "entries: %d\nbuckets used: %d/%d\nlongest chain: %d\n",
             op.u.hash_stats.entries, op.u.hash_stats.buckets_used,
             op.u.hash_stats.buckets_total, op.u.hash_stats.max_chain_len);

    return err;
}

int xc_flask_avc_cachestats(xc_interface *xch, char *buf, int size)
{
    int err, n;
    int i = 0;
    DECLARE_FLASK_OP;

    n = snprintf(buf, size, "lookups hits misses allocations reclaims frees\n");
    buf += n;
    size -= n;
  
    op.cmd = FLASK_AVC_CACHESTATS;
    while ( size > 0 )
    {
        op.u.cache_stats.cpu = i;
        err = xc_flask_op(xch, &op);
        if ( err && errno == ENOENT )
            return 0;
        if ( err )
            return err;
        n = snprintf(buf, size, "%u %u %u %u %u %u\n",
                     op.u.cache_stats.lookups, op.u.cache_stats.hits,
                     op.u.cache_stats.misses, op.u.cache_stats.allocations,
                     op.u.cache_stats.reclaims, op.u.cache_stats.frees);
        buf += n;
        size -= n;
        i++;
    }

    return 0;
}

int xc_flask_policyvers(xc_interface *xch)
{
    DECLARE_FLASK_OP;
    op.cmd = FLASK_POLICYVERS;

    return xc_flask_op(xch, &op);
}

int xc_flask_getavc_threshold(xc_interface *xch)
{
    DECLARE_FLASK_OP;
    op.cmd = FLASK_GETAVC_THRESHOLD;
    
    return xc_flask_op(xch, &op);
}

int xc_flask_setavc_threshold(xc_interface *xch, int threshold)
{
    DECLARE_FLASK_OP;
    op.cmd = FLASK_SETAVC_THRESHOLD;
    op.u.setavc_threshold.threshold = threshold;

    return xc_flask_op(xch, &op);
}

int xc_flask_relabel_domain(xc_interface *xch, uint32_t domid, uint32_t sid)
{
    DECLARE_FLASK_OP;
    op.cmd = FLASK_RELABEL_DOMAIN;
    op.u.relabel.domid = domid;
    op.u.relabel.sid = sid;

    return xc_flask_op(xch, &op);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
