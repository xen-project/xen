/******************************************************************************
 * blktap.c
 * 
 * XenLinux virtual block-device tap.
 * 
 * Copyright (c) 2004, Andrew Warfield
 *
 * Based on the original split block driver:
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 * Modifications by Mark A. Williamson are (c) Intel Research Cambridge
 * Copyright (c) 2004, Christian Limpach
 * 
 * Note that unlike the split block driver code, this driver has been developed
 * strictly for Linux 2.6
 */

#include "blktap.h"

int __init xlblktap_init(void)
{
    ctrl_msg_t               cmsg;
    blkif_fe_driver_status_t fe_st;
    blkif_be_driver_status_t be_st;

    printk(KERN_INFO "Initialising Xen block tap device\n");

    DPRINTK("   tap - Backend connection init:\n");


    (void)ctrl_if_register_receiver(CMSG_BLKIF_FE, blkif_ctrlif_rx,
                                    CALLBACK_IN_BLOCKING_CONTEXT);

    /* Send a driver-UP notification to the domain controller. */
    cmsg.type      = CMSG_BLKIF_FE;
    cmsg.subtype   = CMSG_BLKIF_FE_DRIVER_STATUS;
    cmsg.length    = sizeof(blkif_fe_driver_status_t);
    fe_st.status   = BLKIF_DRIVER_STATUS_UP;
    memcpy(cmsg.msg, &fe_st, sizeof(fe_st));
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);

    DPRINTK("   tap - Frontend connection init:\n");
    
    active_reqs_init();
    blkif_interface_init();
    blkdev_schedule_init();
    
    (void)ctrl_if_register_receiver(CMSG_BLKIF_BE, blkif_ctrlif_rx, 
                                    CALLBACK_IN_BLOCKING_CONTEXT);

    /* Send a driver-UP notification to the domain controller. */
    cmsg.type      = CMSG_BLKIF_BE;
    cmsg.subtype   = CMSG_BLKIF_BE_DRIVER_STATUS;
    cmsg.length    = sizeof(blkif_be_driver_status_t);
    be_st.status   = BLKIF_DRIVER_STATUS_UP;
    memcpy(cmsg.msg, &be_st, sizeof(be_st));
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);

    DPRINTK("   tap - Userland channel init:\n");

    blktap_init();

    DPRINTK("Blkif tap device initialized.\n");

    return 0;
}

#if 0 /* tap doesn't handle suspend/resume */
void blkdev_suspend(void)
{
}

void blkdev_resume(void)
{
    ctrl_msg_t               cmsg;
    blkif_fe_driver_status_t st;    

    /* Send a driver-UP notification to the domain controller. */
    cmsg.type      = CMSG_BLKIF_FE;
    cmsg.subtype   = CMSG_BLKIF_FE_DRIVER_STATUS;
    cmsg.length    = sizeof(blkif_fe_driver_status_t);
    st.status      = BLKIF_DRIVER_STATUS_UP;
    memcpy(cmsg.msg, &st, sizeof(st));
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
}
#endif

__initcall(xlblktap_init);
