/******************************************************************************
 * evtchn.h
 * 
 * Communication via Xen event channels.
 * Also definitions for the device that demuxes notifications to userspace.
 * 
 * Copyright (c) 2004, K A Fraser
 */

#ifndef __ASM_EVTCHN_H__
#define __ASM_EVTCHN_H__

#include <machine/hypervisor.h>
#include <machine/synch_bitops.h>
#include <machine/hypervisor-ifs.h>

/*
 * LOW-LEVEL DEFINITIONS
 */

/* Force a proper event-channel callback from Xen. */
void force_evtchn_callback(void);

/* Entry point for notifications into Linux subsystems. */
void evtchn_do_upcall(struct intrframe *frame);

/* Entry point for notifications into the userland character device. */
void evtchn_device_upcall(int port);

static inline void 
mask_evtchn(int port)
{
    shared_info_t *s = HYPERVISOR_shared_info;
    synch_set_bit(port, &s->evtchn_mask[0]);
}

static inline void 
unmask_evtchn(int port)
{
    shared_info_t *s = HYPERVISOR_shared_info;

    synch_clear_bit(port, &s->evtchn_mask[0]);

    /*
     * The following is basically the equivalent of 'hw_resend_irq'. Just like
     * a real IO-APIC we 'lose the interrupt edge' if the channel is masked.
     */
    if (  synch_test_bit        (port,    &s->evtchn_pending[0]) && 
         !synch_test_and_set_bit(port>>5, &s->evtchn_pending_sel) )
    {
        s->vcpu_data[0].evtchn_upcall_pending = 1;
        if ( !s->vcpu_data[0].evtchn_upcall_mask )
            force_evtchn_callback();
    }
}

static inline void 
clear_evtchn(int port)
{
    shared_info_t *s = HYPERVISOR_shared_info;
    synch_clear_bit(port, &s->evtchn_pending[0]);
}

static inline void 
notify_via_evtchn(int port)
{
    evtchn_op_t op;
    op.cmd = EVTCHNOP_send;
    op.u.send.local_port = port;
    (void)HYPERVISOR_event_channel_op(&op);
}

/*
 * CHARACTER-DEVICE DEFINITIONS
 */

#define PORT_NORMAL    0x0000
#define PORT_EXCEPTION 0x8000
#define PORTIDX_MASK   0x7fff

/* /dev/xen/evtchn resides at device number major=10, minor=200 */
#define EVTCHN_MINOR 200

/* /dev/xen/evtchn ioctls: */
/* EVTCHN_RESET: Clear and reinit the event buffer. Clear error condition. */
#define EVTCHN_RESET  _IO('E', 1)
/* EVTCHN_BIND: Bind to the specified event-channel port. */
#define EVTCHN_BIND   _IO('E', 2)
/* EVTCHN_UNBIND: Unbind from the specified event-channel port. */
#define EVTCHN_UNBIND _IO('E', 3)

#endif /* __ASM_EVTCHN_H__ */
