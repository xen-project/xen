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

#include <linux/config.h>
#include <asm/hypervisor.h>
#include <asm/ptrace.h>
#include <asm/synch_bitops.h>

/*
 * LOW-LEVEL DEFINITIONS
 */

/* Entry point for notifications into Linux subsystems. */
void evtchn_do_upcall(struct pt_regs *regs);

/* Entry point for notifications into the userland character device. */
void evtchn_device_upcall(int port, int exception);

static inline void mask_evtchn(int port)
{
    shared_info_t *s = HYPERVISOR_shared_info;
    synch_set_bit(port, &s->evtchn_mask[0]);
}

static inline void unmask_evtchn(int port)
{
    shared_info_t *s = HYPERVISOR_shared_info;
    int need_upcall = 0;

    synch_clear_bit(port, &s->evtchn_mask[0]);

    /*
     * The following is basically the equivalent of 'hw_resend_irq'. Just like
     * a real IO-APIC we 'lose the interrupt edge' if the channel is masked.
     */

    /* Asserted a standard notification? */
    if (  synch_test_bit        (port,    &s->evtchn_pending[0]) && 
         !synch_test_and_set_bit(port>>5, &s->evtchn_pending_sel) )
        need_upcall = 1;

    /* Asserted an exceptional notification? */
    if (  synch_test_bit        (port,    &s->evtchn_exception[0]) && 
         !synch_test_and_set_bit(port>>5, &s->evtchn_exception_sel) )
        need_upcall = 1;

    /* If asserted either type of notification, check the master flags. */
    if ( need_upcall &&
         !synch_test_and_set_bit(0,       &s->evtchn_upcall_pending) &&
         !synch_test_bit        (0,       &s->evtchn_upcall_mask) )
        evtchn_do_upcall(NULL);
}

static inline void clear_evtchn(int port)
{
    shared_info_t *s = HYPERVISOR_shared_info;
    synch_clear_bit(port, &s->evtchn_pending[0]);
}

static inline void clear_evtchn_exception(int port)
{
    shared_info_t *s = HYPERVISOR_shared_info;
    synch_clear_bit(port, &s->evtchn_exception[0]);
}

static inline void evtchn_clear_error_virq(void)
{
    /*
     * XXX This prevents a bogus 'VIRQ_ERROR' when interrupts are enabled
     * for the first time. This works because by this point all important
     * VIRQs (eg. timer) have been properly bound.
     */
    synch_clear_bit(0, &HYPERVISOR_shared_info->evtchn_pending[0]);
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
#define EVTCHN_RESET _IO('E', 1)

#endif /* __ASM_EVTCHN_H__ */
