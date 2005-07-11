/******************************************************************************
 * arch/xen/drivers/usbif/backend/control.c
 * 
 * Routines for interfacing with the control plane.
 * 
 * Copyright (c) 2004, Keir Fraser
 */

#include "common.h"

static void usbif_ctrlif_rx(ctrl_msg_t *msg, unsigned long id)
{
    DPRINTK("Received usbif backend message, subtype=%d\n", msg->subtype);
    
    switch ( msg->subtype )
    {
    case CMSG_USBIF_BE_CREATE:
        usbif_create((usbif_be_create_t *)&msg->msg[0]);
        break;        
    case CMSG_USBIF_BE_DESTROY:
        usbif_destroy((usbif_be_destroy_t *)&msg->msg[0]);
        break;        
    case CMSG_USBIF_BE_CONNECT:
        usbif_connect((usbif_be_connect_t *)&msg->msg[0]);
        break;        
    case CMSG_USBIF_BE_DISCONNECT:
        if ( !usbif_disconnect((usbif_be_disconnect_t *)&msg->msg[0],msg->id) )
            return; /* Sending the response is deferred until later. */
        break;        
    case CMSG_USBIF_BE_CLAIM_PORT:
	usbif_claim_port((usbif_be_claim_port_t *)&msg->msg[0]);
        break;
    case CMSG_USBIF_BE_RELEASE_PORT:
        usbif_release_port((usbif_be_release_port_t *)&msg->msg[0]);
        break;
    default:
        DPRINTK("Parse error while reading message subtype %d, len %d\n",
                msg->subtype, msg->length);
        msg->length = 0;
        break;
    }

    ctrl_if_send_response(msg);
}

void usbif_ctrlif_init(void)
{
    ctrl_msg_t                       cmsg;
    usbif_be_driver_status_changed_t st;

    (void)ctrl_if_register_receiver(CMSG_USBIF_BE, usbif_ctrlif_rx, 
                                    CALLBACK_IN_BLOCKING_CONTEXT);

    /* Send a driver-UP notification to the domain controller. */
    cmsg.type      = CMSG_USBIF_BE;
    cmsg.subtype   = CMSG_USBIF_BE_DRIVER_STATUS_CHANGED;
    cmsg.length    = sizeof(usbif_be_driver_status_changed_t);
    st.status      = USBIF_DRIVER_STATUS_UP;
    memcpy(cmsg.msg, &st, sizeof(st));
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
}
