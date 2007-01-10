/* 
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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/serial.h>
#include <linux/major.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include <asm/hypervisor.h>
#include <xen/evtchn.h>
#include <xen/xencons.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <xen/interface/io/console.h>

static int xencons_irq;

static inline struct xencons_interface *xencons_interface(void)
{
	return mfn_to_virt(xen_start_info->console.domU.mfn);
}

static inline void notify_daemon(void)
{
	/* Use evtchn: this is called early, before irq is set up. */
	notify_remote_via_evtchn(xen_start_info->console.domU.evtchn);
}

int xencons_ring_send(const char *data, unsigned len)
{
	int sent = 0;
	struct xencons_interface *intf = xencons_interface();
	XENCONS_RING_IDX cons, prod;

	cons = intf->out_cons;
	prod = intf->out_prod;
	mb();
	BUG_ON((prod - cons) > sizeof(intf->out));

	while ((sent < len) && ((prod - cons) < sizeof(intf->out)))
		intf->out[MASK_XENCONS_IDX(prod++, intf->out)] = data[sent++];

	wmb();
	intf->out_prod = prod;

	notify_daemon();

	return sent;
}

static irqreturn_t handle_input(int irq, void *unused, struct pt_regs *regs)
{
	struct xencons_interface *intf = xencons_interface();
	XENCONS_RING_IDX cons, prod;

	cons = intf->in_cons;
	prod = intf->in_prod;
	mb();
	BUG_ON((prod - cons) > sizeof(intf->in));

	while (cons != prod) {
		xencons_rx(intf->in+MASK_XENCONS_IDX(cons,intf->in), 1, regs);
		cons++;
	}

	mb();
	intf->in_cons = cons;

	notify_daemon();

	xencons_tx();

	return IRQ_HANDLED;
}

int xencons_ring_init(void)
{
	int irq;

	if (xencons_irq)
		unbind_from_irqhandler(xencons_irq, NULL);
	xencons_irq = 0;

	if (!is_running_on_xen() ||
	    is_initial_xendomain() ||
	    !xen_start_info->console.domU.evtchn)
		return -ENODEV;

	irq = bind_caller_port_to_irqhandler(
		xen_start_info->console.domU.evtchn,
		handle_input, 0, "xencons", NULL);
	if (irq < 0) {
		printk(KERN_ERR "XEN console request irq failed %i\n", irq);
		return irq;
	}

	xencons_irq = irq;

	/* In case we have in-flight data after save/restore... */
	notify_daemon();

	return 0;
}

void xencons_resume(void)
{
	(void)xencons_ring_init();
}
