/* control_interface.c
 *
 * Interfaces to control message rings to VMs.
 *
 * Most of this is directly based on the original xu interface to python 
 * written by Keir Fraser.
 *
 * (c) 2004, Andrew Warfield
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include "xcs.h"

static int xc_handle = -1;

/* Called at start-of-day when using the control channel interface. */
int ctrl_chan_init(void)
{
    if ( (xc_handle = xc_interface_open()) == -1 )
    {
        DPRINTF("Could not open Xen control interface");
        return -1;
    }
    
    return 0;
}

static control_if_t *map_control_interface(int fd, unsigned long pfn,
					   u32 dom)
{
    char *vaddr = xc_map_foreign_range( fd, dom, PAGE_SIZE,
					PROT_READ|PROT_WRITE, pfn );
    if ( vaddr == NULL )
        return NULL;
    return (control_if_t *)(vaddr + 2048);
}

static void unmap_control_interface(int fd, control_if_t *c)
{
    char *vaddr = (char *)c - 2048;
    (void)munmap(vaddr, PAGE_SIZE);
}

int ctrl_chan_notify(control_channel_t *cc)
{
    return xc_evtchn_send(xc_handle, cc->local_port);
}

int ctrl_chan_read_request(control_channel_t *cc, xcs_control_msg_t *dmsg)
{
    control_msg_t     *smsg;
    RING_IDX          c = cc->tx_ring.req_cons;

    if ( !RING_HAS_UNCONSUMED_REQUESTS(&cc->tx_ring) )
    {
        DPRINTF("no request to read\n");
        return -1;
    }
    
    rmb(); /* make sure we see the data associated with the request */
    smsg = RING_GET_REQUEST(&cc->tx_ring, c);
    memcpy(&dmsg->msg, smsg, sizeof(*smsg));
    if ( dmsg->msg.length > sizeof(dmsg->msg.msg) )
        dmsg->msg.length = sizeof(dmsg->msg.msg);
    cc->tx_ring.req_cons++;
    return 0;
}

int ctrl_chan_write_request(control_channel_t *cc, 
                            xcs_control_msg_t *smsg)
{
    control_msg_t *dmsg;
    RING_IDX       p = cc->rx_ring.req_prod_pvt;
    
    if ( RING_FULL(&cc->rx_ring) )
    {
        DPRINTF("no space to write request");
        return -ENOSPC;
    }

    dmsg = RING_GET_REQUEST(&cc->rx_ring, p);
    memcpy(dmsg, &smsg->msg, sizeof(*dmsg));

    wmb();
    cc->rx_ring.req_prod_pvt++;
    RING_PUSH_REQUESTS(&cc->rx_ring);
    
    return 0;
}

int ctrl_chan_read_response(control_channel_t *cc, xcs_control_msg_t *dmsg)
{
    control_msg_t     *smsg;
    RING_IDX          c = cc->rx_ring.rsp_cons;
    
    if ( !RING_HAS_UNCONSUMED_RESPONSES(&cc->rx_ring) )
    {
        DPRINTF("no response to read");
        return -1;
    }

    rmb(); /* make sure we see the data associated with the request */
    smsg = RING_GET_RESPONSE(&cc->rx_ring, c);
    memcpy(&dmsg->msg, smsg, sizeof(*smsg));
    if ( dmsg->msg.length > sizeof(dmsg->msg.msg) )
        dmsg->msg.length = sizeof(dmsg->msg.msg);
    cc->rx_ring.rsp_cons++;
    return 0;
}

int ctrl_chan_write_response(control_channel_t *cc, 
                             xcs_control_msg_t *smsg)
{
    control_msg_t  *dmsg;
    RING_IDX        p = cc->tx_ring.rsp_prod_pvt;

    /* akw: if the ring is synchronous, you should never need this test! */
    /* (but it was in the original code... )                             */
    if ( cc->tx_ring.req_cons == cc->tx_ring.rsp_prod_pvt )
    {
        DPRINTF("no space to write response");
        return -ENOSPC;
    }

    dmsg = RING_GET_RESPONSE(&cc->tx_ring, p);
    memcpy(dmsg, &smsg->msg, sizeof(*dmsg));

    wmb();
    cc->tx_ring.rsp_prod_pvt++;
    RING_PUSH_RESPONSES(&cc->tx_ring);
    
    return 0;
}

int ctrl_chan_request_to_read(control_channel_t *cc)
{
    return (RING_HAS_UNCONSUMED_REQUESTS(&cc->tx_ring));
}

int ctrl_chan_space_to_write_request(control_channel_t *cc)
{
    return (!(RING_FULL(&cc->rx_ring)));
}

int ctrl_chan_response_to_read(control_channel_t *cc)
{
    return (RING_HAS_UNCONSUMED_RESPONSES(&cc->rx_ring));
}

int ctrl_chan_space_to_write_response(control_channel_t *cc)
{
    /* again, there is something fishy here. */
    return ( cc->tx_ring.req_cons != cc->tx_ring.rsp_prod_pvt );
}

int ctrl_chan_connect(control_channel_t *cc)
{
    xc_dominfo_t info;

    if ( cc->connected )
    {
	return 0;
    }

    if ( (xc_domain_getinfo(xc_handle, cc->remote_dom, 1, &info) != 1) ||
         (info.domid != cc->remote_dom) )
    {
        DPRINTF("Failed to obtain domain status");
        return -1;
    }

    cc->interface = 
        map_control_interface(xc_handle, info.shared_info_frame,
			      cc->remote_dom);

    if ( cc->interface == NULL )
    {
        DPRINTF("Failed to map domain control interface");
        return -1;
    }

    /* Synchronise ring indexes. */
    BACK_RING_ATTACH(&cc->tx_ring, &cc->interface->tx_ring, CONTROL_RING_MEM);
    FRONT_RING_ATTACH(&cc->rx_ring, &cc->interface->rx_ring, CONTROL_RING_MEM);

    cc->connected = 1;

    return 0;
}

void ctrl_chan_disconnect(control_channel_t *cc)
{
    if ( cc->connected )
	unmap_control_interface(xc_handle, cc->interface);
    cc->connected = 0;
}


control_channel_t *ctrl_chan_new(u32 dom, int local_port, int remote_port)
{
    control_channel_t *cc;
   
    cc = (control_channel_t *)malloc(sizeof(control_channel_t));
    if ( cc == NULL ) return NULL;
    
    cc->connected  = 0;
    cc->remote_dom = dom;

    if ( dom == 0 )
    {
        /*
         * The control-interface event channel for DOM0 is already set up.
         * We use an ioctl to discover the port at our end of the channel.
         */
        local_port  = ioctl(xc_handle, IOCTL_PRIVCMD_INITDOMAIN_EVTCHN, 
                            NULL);
        remote_port = -1; /* We don't need the remote end of the DOM0 link. */
        if ( local_port < 0 )
        {
            DPRINTF("Could not open channel to DOM0");
            goto fail;
        }
    }
    else if ( xc_evtchn_bind_interdomain(xc_handle, 
                                         DOMID_SELF, dom, 
                                         &local_port, &remote_port) != 0 )
    {
        DPRINTF("Could not open channel to domain");
        goto fail;
    }

    cc->local_port  = local_port;
    cc->remote_port = remote_port;

    if ( ctrl_chan_connect(cc) != 0 )
        goto fail;

    return cc;
    
 fail:
    if ( dom != 0 )
        (void)xc_evtchn_close(xc_handle, DOMID_SELF, local_port);
 
    free(cc);
    
    return NULL;        
}

void ctrl_chan_free(control_channel_t *cc)
{
    ctrl_chan_disconnect(cc);
    if ( cc->remote_dom != 0 )
        (void)xc_evtchn_close(xc_handle, DOMID_SELF, cc->local_port);
    free(cc);
}


/* other libxc commands: */

int ctrl_chan_bind_virq(int virq, int *port)
{
    return xc_evtchn_bind_virq(xc_handle, virq, port);
}
