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
    switch ( msg->subtype )
    {
    case CMSG_BLKIF_BE_CREATE:
        if ( msg->length != sizeof(blkif_create_t) )
            goto parse_error;
        blkif_create((blkif_create_t *)&msg->msg[0]);
        break;        
    case CMSG_BLKIF_BE_DESTROY:
        if ( msg->length != sizeof(blkif_destroy_t) )
            goto parse_error;
        blkif_destroy((blkif_destroy_t *)&msg->msg[0]);
        break;        
    case CMSG_BLKIF_BE_VBD_CREATE:
        if ( msg->length != sizeof(blkif_vbd_create_t) )
            goto parse_error;
        vbd_create((blkif_vbd_create_t *)&msg->msg[0]);
        break;
    case CMSG_BLKIF_BE_VBD_DESTROY:
        if ( msg->length != sizeof(blkif_vbd_destroy_t) )
            goto parse_error;
        vbd_destroy((blkif_vbd_destroy_t *)&msg->msg[0]);
        break;
    case CMSG_BLKIF_BE_VBD_GROW:
        if ( msg->length != sizeof(blkif_vbd_grow_t) )
            goto parse_error;
        vbd_grow((blkif_vbd_grow_t *)&msg->msg[0]);
        break;
    case CMSG_BLKIF_BE_VBD_SHRINK:
        if ( msg->length != sizeof(blkif_vbd_shrink_t) )
            goto parse_error;
        vbd_shrink((blkif_vbd_shrink_t *)&msg->msg[0]);
        break;
    default:
        goto parse_error;
    }

    ctrl_if_send_response(msg);
    return;

 parse_error:
    msg->length = 0;
    ctrl_if_send_response(msg);
}

int blkif_ctrlif_init(void)
{
    (void)ctrl_if_register_receiver(CMSG_BLKIF_BE, blkif_ctrlif_rx);
    return 0;
}
