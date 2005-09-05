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

#include <asm-xen/hypervisor.h>
#include <asm-xen/evtchn.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/err.h>
#include "xencons_ring.h"


struct ring_head
{
	u32 cons;
	u32 prod;
	char buf[0];
} __attribute__((packed));


#define XENCONS_RING_SIZE (PAGE_SIZE/2 - sizeof (struct ring_head))
#define XENCONS_IDX(cnt) ((cnt) % XENCONS_RING_SIZE)
#define XENCONS_FULL(ring) (((ring)->prod - (ring)->cons) == XENCONS_RING_SIZE)

static inline struct ring_head *outring(void)
{
	return machine_to_virt(xen_start_info->console_mfn << PAGE_SHIFT);
}

static inline struct ring_head *inring(void)
{
	return machine_to_virt(xen_start_info->console_mfn << PAGE_SHIFT)
		+ PAGE_SIZE/2;
}


/* don't block -  write as much as possible and return */
static int __xencons_ring_send(struct ring_head *ring, const char *data, unsigned len)
{
	int copied = 0;

	mb();
	while (copied < len && !XENCONS_FULL(ring)) {
		ring->buf[XENCONS_IDX(ring->prod)] = data[copied];
		ring->prod++;
		copied++;
	}
	mb();

	return copied;
}

int xencons_ring_send(const char *data, unsigned len)
{
	struct ring_head *out = outring();
	int sent = 0;
	
	sent = __xencons_ring_send(out, data, len);
	notify_via_evtchn(xen_start_info->console_evtchn);
	return sent;

}	


static xencons_receiver_func *xencons_receiver;

static irqreturn_t handle_input(int irq, void *unused, struct pt_regs *regs)
{
	struct ring_head *ring = inring();
	while (ring->cons < ring->prod) {
		if (xencons_receiver != NULL) {
			xencons_receiver(ring->buf + XENCONS_IDX(ring->cons),
					 1, regs);
		}
		ring->cons++;
	}
	return IRQ_HANDLED;
}

void xencons_ring_register_receiver(xencons_receiver_func *f)
{
	xencons_receiver = f;
}

int xencons_ring_init(void)
{
	int err;

	if (!xen_start_info->console_evtchn)
		return 0;

	err = bind_evtchn_to_irqhandler(xen_start_info->console_evtchn,
					handle_input, 0, "xencons", inring());
	if (err) {
		xprintk("XEN console request irq failed %i\n", err);
		return err;
	}

	return 0;
}

void xencons_suspend(void)
{

	if (!xen_start_info->console_evtchn)
		return;

	unbind_evtchn_from_irqhandler(xen_start_info->console_evtchn,
				      inring());
}

void xencons_resume(void)
{

	(void)xencons_ring_init();
}
