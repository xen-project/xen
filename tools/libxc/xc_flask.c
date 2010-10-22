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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "xc_private.h"
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define OCON_PIRQ_STR   "pirq"
#define OCON_IOPORT_STR "ioport"
#define OCON_IOMEM_STR  "iomem"
#define OCON_DEVICE_STR "pcidevice"
#define INITCONTEXTLEN  256

int xc_flask_op(xc_interface *xch, flask_op_t *op)
{
    int ret = -1;
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BOUNCE(op, sizeof(*op), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( xc_hypercall_bounce_pre(xch, op) )
    {
        PERROR("Could not bounce memory for flask op hypercall");
        goto out;
    }

    hypercall.op     = __HYPERVISOR_xsm_op;
    hypercall.arg[0] = HYPERCALL_BUFFER_AS_ARG(op);

    if ( (ret = do_xen_hypercall(xch, &hypercall)) < 0 )
    {
        if ( errno == EACCES )
            fprintf(stderr, "XSM operation failed!\n");
    }

    xc_hypercall_bounce_post(xch, op);

 out:
    return ret;
}

int xc_flask_load(xc_interface *xc_handle, char *buf, uint32_t size)
{
    int err;
    flask_op_t op;
    
    op.cmd = FLASK_LOAD;
    op.buf = buf;
    op.size = size;
    
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
        return err;

    return 0;
}

int xc_flask_context_to_sid(xc_interface *xc_handle, char *buf, uint32_t size, uint32_t *sid)
{
    int err;
    flask_op_t op;
    
    op.cmd = FLASK_CONTEXT_TO_SID;
    op.buf = buf;
    op.size = size;
    
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
        return err;
    
    sscanf(buf, "%u", sid);

    return 0;
}

int xc_flask_sid_to_context(xc_interface *xc_handle, int sid, char *buf, uint32_t size)
{
    int err;
    flask_op_t op;
    
    op.cmd = FLASK_SID_TO_CONTEXT;
    op.buf = buf;
    op.size = size;
    
    snprintf(buf, size, "%u", sid);

    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
        return err;

    return 0;
}

int xc_flask_getenforce(xc_interface *xc_handle)
{
    int err;
    flask_op_t op;
    char buf[20];            
    int size = 20;
    int mode;
 
    op.cmd = FLASK_GETENFORCE;
    op.buf = buf;
    op.size = size;
    
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
        return err;

    sscanf(buf, "%i", &mode);

    return mode;
}

int xc_flask_setenforce(xc_interface *xc_handle, int mode)
{
    int err;
    flask_op_t op;
    char buf[20];
    int size = 20; 
 
    op.cmd = FLASK_SETENFORCE;
    op.buf = buf;
    op.size = size;
   
    snprintf(buf, size, "%i", mode);
 
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
        return err;

    return 0;
}

static int xc_flask_add(xc_interface *xc_handle, char *cat, char *arg, char *scontext)
{
    char buf[512];
    flask_op_t op;

    memset(buf, 0, 512);
    snprintf(buf, 512, "%s %255s %s", cat, scontext, arg);
    op.cmd = FLASK_ADD_OCONTEXT;
    op.buf = buf;
    op.size = 512;
    
    return xc_flask_op(xc_handle, &op);
}

int xc_flask_add_pirq(xc_interface *xc_handle, unsigned int pirq, char *scontext)
{
    char arg[16];

    snprintf(arg, 16, "%u", pirq);
    return xc_flask_add(xc_handle, OCON_PIRQ_STR, arg, scontext);
}

int xc_flask_add_ioport(xc_interface *xc_handle, unsigned long low, unsigned long high,
                      char *scontext)
{
    char arg[64];

    snprintf(arg, 64, "%lu %lu", low, high);
    return xc_flask_add(xc_handle, OCON_IOPORT_STR, arg, scontext);
}

int xc_flask_add_iomem(xc_interface *xc_handle, unsigned long low, unsigned long high,
                     char *scontext)
{
    char arg[64];

    snprintf(arg, 64, "%lu %lu", low, high);
    return xc_flask_add(xc_handle, OCON_IOMEM_STR, arg, scontext);
}

int xc_flask_add_device(xc_interface *xc_handle, unsigned long device, char *scontext)
{
    char arg[32];

    snprintf(arg, 32, "%lu", device);
    return xc_flask_add(xc_handle, OCON_DEVICE_STR, arg, scontext);
}

static int xc_flask_del(xc_interface *xc_handle, char *cat, char *arg)
{
    char buf[256];
    flask_op_t op;

    memset(buf, 0, 256);
    snprintf(buf, 256, "%s %s", cat, arg);
    op.cmd = FLASK_DEL_OCONTEXT;
    op.buf = buf;
    op.size = 256;
    
    return xc_flask_op(xc_handle, &op);
}

int xc_flask_del_pirq(xc_interface *xc_handle, unsigned int pirq)
{
    char arg[16];

    snprintf(arg, 16, "%u", pirq);
    return xc_flask_del(xc_handle, OCON_PIRQ_STR, arg);
}

int xc_flask_del_ioport(xc_interface *xc_handle, unsigned long low, unsigned long high)
{
    char arg[64];

    snprintf(arg, 64, "%lu %lu", low, high);
    return xc_flask_del(xc_handle, OCON_IOPORT_STR, arg);
}

int xc_flask_del_iomem(xc_interface *xc_handle, unsigned long low, unsigned long high)
{
    char arg[64];

    snprintf(arg, 64, "%lu %lu", low, high);
    return xc_flask_del(xc_handle, OCON_IOMEM_STR, arg);
}

int xc_flask_del_device(xc_interface *xc_handle, unsigned long device)
{
    char arg[32];

    snprintf(arg, 32, "%lu", device);
    return xc_flask_del(xc_handle, OCON_DEVICE_STR, arg);
}

int xc_flask_access(xc_interface *xc_handle, const char *scon, const char *tcon,
                uint16_t tclass, uint32_t req,
                uint32_t *allowed, uint32_t *decided,
                uint32_t *auditallow, uint32_t *auditdeny,
                uint32_t *seqno)
{
/* maximum number of digits in a 16-bit decimal number: */
#define MAX_SHORT_DEC_LEN 5

    char *buf;
    int bufLen;
    int err;
    flask_op_t op;
    uint32_t dummy_allowed;
    uint32_t dummy_decided;
    uint32_t dummy_auditallow;
    uint32_t dummy_auditdeny;
    uint32_t dummy_seqno;
  
    if (!allowed)
        allowed = &dummy_allowed;
    if (!decided)
        decided = &dummy_decided;
    if (!auditallow)
        auditallow = &dummy_auditallow;
    if (!auditdeny)
        auditdeny = &dummy_auditdeny;
    if (!seqno)
        seqno = &dummy_seqno;

    if (!scon)
        return -EINVAL;
    if (!tcon)
        return -EINVAL;

    bufLen = strlen(scon) + 1 + strlen(tcon) + 1 +
        MAX_SHORT_DEC_LEN + 1 +
        sizeof(req)*2 + 1;
    buf = malloc(bufLen);
    snprintf(buf, bufLen, "%s %s %hu %x", scon, tcon, tclass, req);

    op.cmd = FLASK_ACCESS;
    op.buf = buf;
    op.size = strlen(buf)+1;
    
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }
   
    if (sscanf(op.buf, "%x %x %x %x %u",
               allowed, decided,
               auditallow, auditdeny,
               seqno) != 5) {
        err = -EILSEQ;
    }

    err = ((*allowed & req) == req)? 0 : -EPERM;

    return err;

}

int xc_flask_avc_hashstats(xc_interface *xc_handle, char *buf, int size)
{
    int err;
    flask_op_t op;
  
    op.cmd = FLASK_AVC_HASHSTATS;
    op.buf = buf;
    op.size = size;
  
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }

    return 0;
}

int xc_flask_avc_cachestats(xc_interface *xc_handle, char *buf, int size)
{
    int err;
    flask_op_t op;
  
    op.cmd = FLASK_AVC_CACHESTATS;
    op.buf = buf;
    op.size = size;
  
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }

    return 0;
}

int xc_flask_policyvers(xc_interface *xc_handle, char *buf, int size)
{
    int err;
    flask_op_t op;
  
    op.cmd = FLASK_POLICYVERS;
    op.buf = buf;
    op.size = size;

    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }

    return 0;
}

int xc_flask_getavc_threshold(xc_interface *xc_handle)
{
    int err;
    flask_op_t op;
    char buf[20];            
    int size = 20;
    int threshold;
 
    op.cmd = FLASK_GETAVC_THRESHOLD;
    op.buf = buf;
    op.size = size;
    
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
        return err;

    sscanf(buf, "%i", &threshold);

    return threshold;
}

int xc_flask_setavc_threshold(xc_interface *xc_handle, int threshold)
{
    int err;
    flask_op_t op;
    char buf[20];            
    int size = 20;
 
    op.cmd = FLASK_SETAVC_THRESHOLD;
    op.buf = buf;
    op.size = size;

    snprintf(buf, size, "%i", threshold);
 
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
        return err;

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
