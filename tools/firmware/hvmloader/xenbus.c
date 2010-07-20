/*
 * xenbus.c: static, synchronous, read-only xenbus client for hvmloader.
 *
 * Copyright (c) 2009 Tim Deegan, Citrix Systems (R&D) Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include "util.h"
#include "hypercall.h"
#include <errno.h>
#include <xen/sched.h>
#include <xen/event_channel.h>
#include <xen/hvm/params.h>
#include <xen/io/xs_wire.h>

struct xenstore_domain_interface *rings; /* Shared ring with dom0 */
evtchn_port_t event;                     /* Event-channel to dom0 */
char payload[XENSTORE_PAYLOAD_MAX + 1];  /* Unmarshalling area */

/* Connect our xenbus client to the backend.
 * Call once, before any other xenbus actions. */
void xenbus_setup(void)
{
    xen_hvm_param_t param;

    /* Ask Xen where the xenbus shared page is. */
    param.domid = DOMID_SELF;
    param.index = HVM_PARAM_STORE_PFN;
    if ( hypercall_hvm_op(HVMOP_get_param, &param) )
        BUG();
    rings = (void *) (unsigned long) (param.value << PAGE_SHIFT);

    /* Ask Xen where the xenbus event channel is. */
    param.domid = DOMID_SELF;
    param.index = HVM_PARAM_STORE_EVTCHN;
    if ( hypercall_hvm_op(HVMOP_get_param, &param) )
        BUG();
    event = param.value;

    printf("Xenbus rings @0x%lx, event channel %lu\n",
           (unsigned long) rings, (unsigned long) event);
}

/* Reset the xenbus connection so the next kernel can start again. */
void xenbus_shutdown(void)
{
    ASSERT(rings != NULL);

    /* We zero out the whole ring -- the backend can handle this, and it's 
     * not going to surprise any frontends since it's equivalent to never 
     * having used the rings. */
    memset(rings, 0, sizeof *rings);

    /* Clear the xenbus event-channel too */
    get_shared_info()->evtchn_pending[event / sizeof (unsigned long)]
        &= ~(1UL << ((event % sizeof (unsigned long))));    

    rings = NULL;
}

/* Helper functions: copy data in and out of the ring */
static void ring_write(char *data, uint32_t len)
{
    uint32_t part;

    ASSERT(len <= XENSTORE_PAYLOAD_MAX);

    while ( len )
    {
        /* Don't overrun the consumer pointer */
        part = (XENSTORE_RING_SIZE - 1) -
            MASK_XENSTORE_IDX(rings->req_prod - rings->req_cons);
        /* Don't overrun the end of the ring */
        if ( part > (XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(rings->req_prod)) )
            part = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(rings->req_prod);
        /* Don't write more than we were asked for */
        if ( part > len ) 
            part = len;

        memcpy(rings->req + MASK_XENSTORE_IDX(rings->req_prod), data, part);
        barrier(); /* = wmb before prod write, rmb before next cons read */
        rings->req_prod += part;
        len -= part;

        if ( len )
            hypercall_sched_op(SCHEDOP_yield, NULL);
    }
}

static void ring_read(char *data, uint32_t len)
{
    uint32_t part;

    ASSERT(len <= XENSTORE_PAYLOAD_MAX);

    while ( len )
    {
        /* Don't overrun the producer pointer */
        part = MASK_XENSTORE_IDX(rings->rsp_prod - rings->rsp_cons);
        /* Don't overrun the end of the ring */
        if ( part > (XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(rings->rsp_cons)) )
            part = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(rings->rsp_cons);
        /* Don't read more than we were asked for */
        if ( part > len )
            part = len;

        memcpy(data, rings->rsp + MASK_XENSTORE_IDX(rings->rsp_cons), part);
        barrier(); /* = wmb before cons write, rmb before next prod read */
        rings->rsp_cons += part;
        len -= part;
        
        if ( len )
            hypercall_sched_op(SCHEDOP_yield, NULL);
    }
}


/* Send a request and wait for the answer.
 * Returns 0 for success, or an errno for error.
 * The answer is returned in a static buffer which is only
 * valid until the next call of xenbus_send(). */
static int xenbus_send(uint32_t type, uint32_t len, char *data,
                       uint32_t *reply_len, char **reply_data)
{
    struct xsd_sockmsg hdr;
    evtchn_send_t send;
    int i;

    /* Not acceptable to use xenbus before setting it up */
    ASSERT(rings != NULL);

    /* Put the request on the ring */
    hdr.type = type;
    hdr.req_id = 0;  /* We only ever issue one request at a time */
    hdr.tx_id = 0;   /* We never use transactions */
    hdr.len = len;
    ring_write((char *) &hdr, sizeof hdr);
    ring_write(data, len);

    /* Tell the other end about the request */
    send.port = event;
    hypercall_event_channel_op(EVTCHNOP_send, &send);

    /* Properly we should poll the event channel now but that involves
     * mapping the shared-info page and handling the bitmaps. */

    /* Pull the reply off the ring */
    ring_read((char *) &hdr, sizeof(hdr));
    ring_read(payload, hdr.len);
    /* For sanity's sake, nul-terminate the answer */
    payload[hdr.len] = '\0';

    /* Handle errors */
    if ( hdr.type == XS_ERROR )
    {
        *reply_len = 0;
        for ( i = 0; i < ((sizeof xsd_errors) / (sizeof xsd_errors[0])); i++ )
            if ( !strcmp(xsd_errors[i].errstring, payload) )
                return xsd_errors[i].errnum;
        /* Default error value if we couldn't decode the ASCII error */
        return EIO;
    }

    *reply_data = payload;
    *reply_len = hdr.len;
    return 0;
}


/* Read a xenstore key.  Returns a nul-terminated string (even if the XS
 * data wasn't nul-terminated) or NULL.  The returned string is in a
 * static buffer, so only valid until the next xenstore/xenbus operation. */
char *xenstore_read(char *path)
{
    uint32_t len = 0;
    char *answer = NULL;

    /* Include the nul in the request */
    if ( xenbus_send(XS_READ, strlen(path) + 1, path, &len, &answer) )
        return NULL;
    /* We know xenbus_send() nul-terminates its answer, so just pass it on. */
    return answer;
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
