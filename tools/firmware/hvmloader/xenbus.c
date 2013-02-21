/*
 * xenbus.c: static, synchronous, read-only xenbus client for hvmloader.
 *
 * Copyright (c) 2009 Tim Deegan, Citrix Systems (R&D) Ltd.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "util.h"
#include "hypercall.h"
#include <errno.h>
#include <xen/sched.h>
#include <xen/event_channel.h>
#include <xen/hvm/params.h>
#include <xen/io/xs_wire.h>

static struct xenstore_domain_interface *rings; /* Shared ring with dom0 */
static evtchn_port_t event;                     /* Event-channel to dom0 */
static char payload[XENSTORE_PAYLOAD_MAX + 1];  /* Unmarshalling area */

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
    struct shared_info *shinfo = get_shared_info();

    ASSERT(rings != NULL);

    /* We zero out the whole ring -- the backend can handle this, and it's 
     * not going to surprise any frontends since it's equivalent to never 
     * having used the rings. */
    memset(rings, 0, sizeof *rings);

    /* Clear the event-channel state too. */
    memset(shinfo->vcpu_info, 0, sizeof(shinfo->vcpu_info));
    memset(shinfo->evtchn_pending, 0, sizeof(shinfo->evtchn_pending));
    memset(shinfo->evtchn_mask, 0, sizeof(shinfo->evtchn_mask));

    rings = NULL;
}

static void ring_wait(void)
{
    struct shared_info *shinfo = get_shared_info();
    struct sched_poll poll;

    memset(&poll, 0, sizeof(poll));
    set_xen_guest_handle(poll.ports, &event);
    poll.nr_ports = 1;

    while ( !test_and_clear_bit(event, shinfo->evtchn_pending) )
        hypercall_sched_op(SCHEDOP_poll, &poll);
}

/* Helper functions: copy data in and out of the ring */
static void ring_write(const char *data, uint32_t len)
{
    uint32_t part;

    ASSERT(len <= XENSTORE_PAYLOAD_MAX);

    while ( len )
    {
        /* Don't overrun the consumer pointer */
        while ( (part = (XENSTORE_RING_SIZE - 1) -
                 MASK_XENSTORE_IDX(rings->req_prod - rings->req_cons)) == 0 )
            ring_wait();
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
    }
}

static void ring_read(char *data, uint32_t len)
{
    uint32_t part;

    ASSERT(len <= XENSTORE_PAYLOAD_MAX);

    while ( len )
    {
        /* Don't overrun the producer pointer */
        while ( (part = MASK_XENSTORE_IDX(rings->rsp_prod -
                                          rings->rsp_cons)) == 0 )
            ring_wait();
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
    }
}

#define MAX_SEGMENTS    4

/* Send a request. */
static void xenbus_send(uint32_t type, ...)
{
    struct xsd_sockmsg hdr;
    va_list ap;
    struct {
        const char *data;
        uint32_t len;
    } seg[MAX_SEGMENTS];
    evtchn_send_t send;
    int i, n;

    /* Not acceptable to use xenbus before setting it up */
    ASSERT(rings != NULL);

    /* Put the request on the ring */
    hdr.type = type;
    hdr.req_id = 0;  /* We only ever issue one request at a time */
    hdr.tx_id = 0;   /* We never use transactions */
    hdr.len = 0;

    va_start(ap, type);
    for ( i = 0; ; i++ ) {
        seg[i].data = va_arg(ap, const char *);
        seg[i].len = va_arg(ap, uint32_t);

        if ( seg[i].data == NULL )
            break;

        hdr.len += seg[i].len;
    }
    n = i;
    va_end(ap);

    ring_write((char *) &hdr, sizeof hdr);
    for ( i = 0; i < n; i++ )
        ring_write(seg[i].data, seg[i].len);

    /* Tell the other end about the request */
    send.port = event;
    hypercall_event_channel_op(EVTCHNOP_send, &send);
}

/* Wait for the answer to a previous request.
 * Returns 0 for success, or an errno for error.
 * The answer is returned in a static buffer which is only
 * valid until the next call of xenbus_send(). */
static int xenbus_recv(uint32_t *reply_len, const char **reply_data)
{
    struct xsd_sockmsg hdr;

    /* Pull the reply off the ring */
    ring_read((char *) &hdr, sizeof(hdr));
    ring_read(payload, hdr.len);
    /* For sanity's sake, nul-terminate the answer */
    payload[hdr.len] = '\0';

    /* Handle errors */
    if ( hdr.type == XS_ERROR )
    {
        int i;

        *reply_len = 0;
        for ( i = 0; i < ((sizeof xsd_errors) / (sizeof xsd_errors[0])); i++ )
            if ( !strcmp(xsd_errors[i].errstring, payload) )
                return xsd_errors[i].errnum;
        /* Default error value if we couldn't decode the ASCII error */
        return EIO;
    }

    if ( reply_data )
        *reply_data = payload;
    if ( reply_len )
        *reply_len = hdr.len;
    return 0;
}


/* Read a xenstore key.  Returns a nul-terminated string (even if the XS
 * data wasn't nul-terminated) or NULL.  The returned string is in a
 * static buffer, so only valid until the next xenstore/xenbus operation.
 * If @default_resp is specified, it is returned in preference to a NULL or
 * empty string received from xenstore.
 */
const char *xenstore_read(const char *path, const char *default_resp)
{
    uint32_t len = 0;
    const char *answer = NULL;

    xenbus_send(XS_READ,
                path, strlen(path),
                "", 1, /* nul separator */
                NULL, 0);

    if ( xenbus_recv(&len, &answer) )
        answer = NULL;

    if ( (default_resp != NULL) && ((answer == NULL) || (*answer == '\0')) )
        answer = default_resp;

    /* We know xenbus_recv() nul-terminates its answer, so just pass it on. */
    return answer;
}

/* Write a xenstore key.  @value must be a nul-terminated string. Returns
 * zero on success or a xenstore error code on failure.
 */
int xenstore_write(const char *path, const char *value)
{
    xenbus_send(XS_WRITE,
                path, strlen(path),
                "", 1, /* nul separator */
                value, strlen(value),
                NULL, 0);

    return ( xenbus_recv(NULL, NULL) );
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
