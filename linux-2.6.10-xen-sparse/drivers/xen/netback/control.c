/******************************************************************************
 * arch/xen/drivers/netif/backend/control.c
 * 
 * Routines for interfacing with the control plane.
 * 
 * Copyright (c) 2004, Keir Fraser
 */

#include "common.h"

static void netif_ctrlif_rx(ctrl_msg_t *msg, unsigned long id)
{
    switch ( msg->subtype )
    {
    case CMSG_NETIF_BE_CREATE:
        if ( msg->length != sizeof(netif_be_create_t) )
            goto parse_error;
        netif_create((netif_be_create_t *)&msg->msg[0]);
        break;        
    case CMSG_NETIF_BE_DESTROY:
        if ( msg->length != sizeof(netif_be_destroy_t) )
            goto parse_error;
        netif_destroy((netif_be_destroy_t *)&msg->msg[0]);
        break;        
    case CMSG_NETIF_BE_CONNECT:
        if ( msg->length != sizeof(netif_be_connect_t) )
            goto parse_error;
        netif_connect((netif_be_connect_t *)&msg->msg[0]);
        break;        
    case CMSG_NETIF_BE_DISCONNECT:
        if ( msg->length != sizeof(netif_be_disconnect_t) )
            goto parse_error;
        if ( !netif_disconnect((netif_be_disconnect_t *)&msg->msg[0],msg->id) )
            return; /* Sending the response is deferred until later. */
        break;        
    default:
        goto parse_error;
    }

    ctrl_if_send_response(msg);
    return;

 parse_error:
    DPRINTK("Parse error while reading message subtype %d, len %d\n",
            msg->subtype, msg->length);
    msg->length = 0;
    ctrl_if_send_response(msg);
}

void netif_ctrlif_init(void)
{
    ctrl_msg_t cmsg;
    netif_be_driver_status_t st;

    (void)ctrl_if_register_receiver(CMSG_NETIF_BE, netif_ctrlif_rx,
                                    CALLBACK_IN_BLOCKING_CONTEXT);

    /* Send a driver-UP notification to the domain controller. */
    cmsg.type      = CMSG_NETIF_BE;
    cmsg.subtype   = CMSG_NETIF_BE_DRIVER_STATUS;
    cmsg.length    = sizeof(netif_be_driver_status_t);
    st.status      = NETIF_DRIVER_STATUS_UP;
    memcpy(cmsg.msg, &st, sizeof(st));
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
}
