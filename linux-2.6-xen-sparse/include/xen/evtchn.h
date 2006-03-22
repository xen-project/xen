/******************************************************************************
 * evtchn.h
 * 
 * Communication via Xen event channels.
 * Also definitions for the device that demuxes notifications to userspace.
 * 
 * Copyright (c) 2004-2005, K A Fraser
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
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
#include <linux/interrupt.h>
#include <asm/hypervisor.h>
#include <asm/ptrace.h>
#include <asm/synch_bitops.h>
#include <xen/interface/event_channel.h>
#include <linux/smp.h>

/*
 * LOW-LEVEL DEFINITIONS
 */

/*
 * Dynamically bind an event source to an IRQ-like callback handler.
 * On some platforms this may not be implemented via the Linux IRQ subsystem.
 * The IRQ argument passed to the callback handler is the same as returned
 * from the bind call. It may not correspond to a Linux IRQ number.
 * Returns IRQ or negative errno.
 * UNBIND: Takes IRQ to unbind from; automatically closes the event channel.
 */
extern int bind_evtchn_to_irqhandler(
	unsigned int evtchn,
	irqreturn_t (*handler)(int, void *, struct pt_regs *),
	unsigned long irqflags,
	const char *devname,
	void *dev_id);
extern int bind_virq_to_irqhandler(
	unsigned int virq,
	unsigned int cpu,
	irqreturn_t (*handler)(int, void *, struct pt_regs *),
	unsigned long irqflags,
	const char *devname,
	void *dev_id);
extern int bind_ipi_to_irqhandler(
	unsigned int ipi,
	unsigned int cpu,
	irqreturn_t (*handler)(int, void *, struct pt_regs *),
	unsigned long irqflags,
	const char *devname,
	void *dev_id);

/*
 * Common unbind function for all event sources. Takes IRQ to unbind from.
 * Automatically closes the underlying event channel (even for bindings
 * made with bind_evtchn_to_irqhandler()).
 */
extern void unbind_from_irqhandler(unsigned int irq, void *dev_id);

extern void irq_resume(void);

/* Entry point for notifications into Linux subsystems. */
asmlinkage void evtchn_do_upcall(struct pt_regs *regs);

/* Entry point for notifications into the userland character device. */
extern void evtchn_device_upcall(int port);

extern void mask_evtchn(int port);
extern void unmask_evtchn(int port);

static inline void clear_evtchn(int port)
{
	shared_info_t *s = HYPERVISOR_shared_info;
	synch_clear_bit(port, &s->evtchn_pending[0]);
}

static inline void notify_remote_via_evtchn(int port)
{
	evtchn_op_t op;
	op.cmd         = EVTCHNOP_send,
	op.u.send.port = port;
	(void)HYPERVISOR_event_channel_op(&op);
}

/*
 * Unlike notify_remote_via_evtchn(), this is safe to use across
 * save/restore. Notifications on a broken connection are silently dropped.
 */
extern void notify_remote_via_irq(int irq);

#endif /* __ASM_EVTCHN_H__ */

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
