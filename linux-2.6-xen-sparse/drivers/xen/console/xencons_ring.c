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
	return mfn_to_virt(xen_start_info->console_mfn);
}

static inline void notify_daemon(void)
{
	/* Use evtchn: this is called early, before irq is set up. */
	notify_remote_via_evtchn(xen_start_info->console_evtchn);
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
	int err;

	if (xencons_irq)
		unbind_from_irqhandler(xencons_irq, NULL);
	xencons_irq = 0;

	if (!xen_start_info->console_evtchn)
		return 0;

	err = bind_evtchn_to_irqhandler(
		xen_start_info->console_evtchn,
		handle_input, 0, "xencons", NULL);
	if (err <= 0) {
		printk(KERN_ERR "XEN console request irq failed %i\n", err);
		return err;
	}

	xencons_irq = err;

	/* In case we have in-flight data after save/restore... */
	notify_daemon();

	return 0;
}

void xencons_resume(void)
{
	(void)xencons_ring_init();
}

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
