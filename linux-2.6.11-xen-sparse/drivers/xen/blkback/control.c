/******************************************************************************
 * arch/xen/drivers/blkif/backend/control.c
 * 
 * Routines for interfacing with the control plane.
 * 
 * Copyright (c) 2004, Keir Fraser
 */

#include "common.h"

static void blkif_ctrlif_rx(ctrl_msg_t *msg, unsigned long id)
{
    DPRINTK("Received blkif backend message, subtype=%d\n", msg->subtype);
    
    switch ( msg->subtype )
    {
    case CMSG_BLKIF_BE_CREATE:
        blkif_create((blkif_be_create_t *)&msg->msg[0]);
        break;        
    case CMSG_BLKIF_BE_DESTROY:
        blkif_destroy((blkif_be_destroy_t *)&msg->msg[0]);
        break;        
    case CMSG_BLKIF_BE_CONNECT:
        blkif_connect((blkif_be_connect_t *)&msg->msg[0]);
        break;        
    case CMSG_BLKIF_BE_DISCONNECT:
        if ( !blkif_disconnect((blkif_be_disconnect_t *)&msg->msg[0],msg->id) )
            return; /* Sending the response is deferred until later. */
        break;        
    case CMSG_BLKIF_BE_VBD_CREATE:
        vbd_create((blkif_be_vbd_create_t *)&msg->msg[0]);
        break;
    case CMSG_BLKIF_BE_VBD_DESTROY:
        vbd_destroy((blkif_be_vbd_destroy_t *)&msg->msg[0]);
        break;
    default:
        DPRINTK("Parse error while reading message subtype %d, len %d\n",
                msg->subtype, msg->length);
        msg->length = 0;
        break;
    }

    ctrl_if_send_response(msg);
}

void blkif_ctrlif_init(void)
{
    ctrl_msg_t cmsg;
    blkif_be_driver_status_t st;

    (void)ctrl_if_register_receiver(CMSG_BLKIF_BE, blkif_ctrlif_rx, 
                                    CALLBACK_IN_BLOCKING_CONTEXT);

    /* Send a driver-UP notification to the domain controller. */
    cmsg.type      = CMSG_BLKIF_BE;
    cmsg.subtype   = CMSG_BLKIF_BE_DRIVER_STATUS;
    cmsg.length    = sizeof(blkif_be_driver_status_t);
    st.status      = BLKIF_DRIVER_STATUS_UP;
    memcpy(cmsg.msg, &st, sizeof(st));
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
}
