/******************************************************************************
 * evtchn.h
 * 
 * Communication via Xen event channels.
 * Also definitions for the device that demuxes notifications to userspace.
 * 
 * Copyright (c) 2004, K A Fraser
 * 
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef __ASM_EVTCHN_H__
#define __ASM_EVTCHN_H__

#include <linux/config.h>
#include <asm-xen/hypervisor.h>
#include <asm/ptrace.h>
#include <asm/synch_bitops.h>
#include <asm-xen/xen-public/event_channel.h>

/*
 * LOW-LEVEL DEFINITIONS
 */

/* Force a proper event-channel callback from Xen. */
void force_evtchn_callback(void);

/* Entry point for notifications into Linux subsystems. */
asmlinkage void evtchn_do_upcall(struct pt_regs *regs);

/* Entry point for notifications into the userland character device. */
void evtchn_device_upcall(int port);

static inline void mask_evtchn(int port)
{
    shared_info_t *s = HYPERVISOR_shared_info;
    synch_set_bit(port, &s->evtchn_mask[0]);
}

static inline void unmask_evtchn(int port)
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

static inline void clear_evtchn(int port)
{
    shared_info_t *s = HYPERVISOR_shared_info;
    synch_clear_bit(port, &s->evtchn_pending[0]);
}

static inline void notify_via_evtchn(int port)
{
    evtchn_op_t op;
    op.cmd = EVTCHNOP_send;
    op.u.send.local_port = port;
    (void)HYPERVISOR_event_channel_op(&op);
}

/*
 * CHARACTER-DEVICE DEFINITIONS
 */

/* /dev/xen/evtchn resides at device number major=10, minor=201 */
#define EVTCHN_MINOR 201

/* /dev/xen/evtchn ioctls: */
/* EVTCHN_RESET: Clear and reinit the event buffer. Clear error condition. */
#define EVTCHN_RESET  _IO('E', 1)
/* EVTCHN_BIND: Bind to teh specified event-channel port. */
#define EVTCHN_BIND   _IO('E', 2)
/* EVTCHN_UNBIND: Unbind from the specified event-channel port. */
#define EVTCHN_UNBIND _IO('E', 3)

#endif /* __ASM_EVTCHN_H__ */
