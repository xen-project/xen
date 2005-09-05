/******************************************************************************
 * ctrl_if.c
 * 
 * Management functions for special interface to the domain controller.
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

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <asm-xen/ctrl_if.h>
#include <asm-xen/evtchn.h>

#if 0
#define DPRINTK(_f, _a...) printk(KERN_ALERT "(file=%s, line=%d) " _f, \
                           __FILE__ , __LINE__ , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#endif

/*
 * Extra ring macros to sync a consumer index up to the public producer index. 
 * Generally UNSAFE, but we use it for recovery and shutdown in some cases.
 */
#define RING_DROP_PENDING_REQUESTS(_r)                                  \
    do {                                                                \
        (_r)->req_cons = (_r)->sring->req_prod;                         \
    } while (0)
#define RING_DROP_PENDING_RESPONSES(_r)                                 \
    do {                                                                \
        (_r)->rsp_cons = (_r)->sring->rsp_prod;                         \
    } while (0)

/*
 * Only used by initial domain which must create its own control-interface
 * event channel. This value is picked up by the user-space domain controller
 * via an ioctl.
 */
int initdom_ctrlif_domcontroller_port = -1;

static int        ctrl_if_evtchn;
static int        ctrl_if_irq;
static spinlock_t ctrl_if_lock;

static struct irqaction ctrl_if_irq_action;

static ctrl_front_ring_t ctrl_if_tx_ring;
static ctrl_back_ring_t  ctrl_if_rx_ring;

/* Incoming message requests. */
    /* Primary message type -> message handler. */
static ctrl_msg_handler_t ctrl_if_rxmsg_handler[256];
    /* Primary message type -> callback in process context? */
static unsigned long ctrl_if_rxmsg_blocking_context[256/sizeof(unsigned long)];
    /* Is it late enough during bootstrap to use schedule_task()? */
static int safe_to_schedule_task;
    /* Queue up messages to be handled in process context. */
static ctrl_msg_t ctrl_if_rxmsg_deferred[CONTROL_RING_SIZE];
static CONTROL_RING_IDX ctrl_if_rxmsg_deferred_prod;
static CONTROL_RING_IDX ctrl_if_rxmsg_deferred_cons;

/* Incoming message responses: message identifier -> message handler/id. */
static struct {
    ctrl_msg_handler_t fn;
    unsigned long      id;
} ctrl_if_txmsg_id_mapping[CONTROL_RING_SIZE];

/* For received messages that must be deferred to process context. */
static void __ctrl_if_rxmsg_deferred(void *unused);
static DECLARE_WORK(ctrl_if_rxmsg_deferred_work,
                    __ctrl_if_rxmsg_deferred,
                    NULL);

/* Deferred callbacks for people waiting for space in the transmit ring. */
static DECLARE_TASK_QUEUE(ctrl_if_tx_tq);

static DECLARE_WAIT_QUEUE_HEAD(ctrl_if_tx_wait);
static void __ctrl_if_tx_tasklet(unsigned long data);
static DECLARE_TASKLET(ctrl_if_tx_tasklet, __ctrl_if_tx_tasklet, 0);

static void __ctrl_if_rx_tasklet(unsigned long data);
static DECLARE_TASKLET(ctrl_if_rx_tasklet, __ctrl_if_rx_tasklet, 0);

#define get_ctrl_if() ((control_if_t *)((char *)HYPERVISOR_shared_info + 2048))

static void ctrl_if_notify_controller(void)
{
    notify_via_evtchn(ctrl_if_evtchn);
}

static void ctrl_if_rxmsg_default_handler(ctrl_msg_t *msg, unsigned long id)
{
    msg->length = 0;
    ctrl_if_send_response(msg);
}

static void __ctrl_if_tx_tasklet(unsigned long data)
{
    ctrl_msg_t *msg;
    int         was_full = RING_FULL(&ctrl_if_tx_ring);
    RING_IDX    i, rp;

    i  = ctrl_if_tx_ring.rsp_cons;
    rp = ctrl_if_tx_ring.sring->rsp_prod;
    rmb(); /* Ensure we see all requests up to 'rp'. */

    for ( ; i != rp; i++ )
    {
        msg = RING_GET_RESPONSE(&ctrl_if_tx_ring, i);
        
        DPRINTK("Rx-Rsp %u/%u :: %d/%d\n", i-1,
                ctrl_if_tx_ring.sring->rsp_prod,
                msg->type, msg->subtype);

        /* Execute the callback handler, if one was specified. */
        if ( msg->id != 0xFF )
        {
            (*ctrl_if_txmsg_id_mapping[msg->id].fn)(
                msg, ctrl_if_txmsg_id_mapping[msg->id].id);
            smp_mb(); /* Execute, /then/ free. */
            ctrl_if_txmsg_id_mapping[msg->id].fn = NULL;
        }
    }

    /*
     * Step over messages in the ring /after/ finishing reading them. As soon 
     * as the index is updated then the message may get blown away.
     */
    smp_mb();
    ctrl_if_tx_ring.rsp_cons = i;
            
    if ( was_full && !RING_FULL(&ctrl_if_tx_ring) )
    {
        wake_up(&ctrl_if_tx_wait);
        run_task_queue(&ctrl_if_tx_tq);
    }
}

static void __ctrl_if_rxmsg_deferred(void *unused)
{
    ctrl_msg_t *msg;
    CONTROL_RING_IDX dp;

    dp = ctrl_if_rxmsg_deferred_prod;
    rmb(); /* Ensure we see all deferred requests up to 'dp'. */

    while ( ctrl_if_rxmsg_deferred_cons != dp )
    {
        msg = &ctrl_if_rxmsg_deferred[MASK_CONTROL_IDX(
            ctrl_if_rxmsg_deferred_cons++)];
        (*ctrl_if_rxmsg_handler[msg->type])(msg, 0);
    }
}

static void __ctrl_if_rx_tasklet(unsigned long data)
{
    ctrl_msg_t    msg, *pmsg;
    CONTROL_RING_IDX dp;
    RING_IDX rp, i;

    i  = ctrl_if_rx_ring.req_cons;
    rp = ctrl_if_rx_ring.sring->req_prod;
    dp = ctrl_if_rxmsg_deferred_prod;
    rmb(); /* Ensure we see all requests up to 'rp'. */
 
    for ( ; i != rp; i++) 
    {
        pmsg = RING_GET_REQUEST(&ctrl_if_rx_ring, i);
        memcpy(&msg, pmsg, offsetof(ctrl_msg_t, msg));

        DPRINTK("Rx-Req %u/%u :: %d/%d\n", i-1,
                ctrl_if_rx_ring.sring->req_prod,
                msg.type, msg.subtype);

        if ( msg.length > sizeof(msg.msg) )
            msg.length = sizeof(msg.msg);
        
        if ( msg.length != 0 )
            memcpy(msg.msg, pmsg->msg, msg.length);

        if ( test_bit(msg.type, 
                      (unsigned long *)&ctrl_if_rxmsg_blocking_context) )
            memcpy(&ctrl_if_rxmsg_deferred[MASK_CONTROL_IDX(dp++)],
                   &msg, offsetof(ctrl_msg_t, msg) + msg.length);
        else
            (*ctrl_if_rxmsg_handler[msg.type])(&msg, 0);
    }

    ctrl_if_rx_ring.req_cons = i;

    if ( dp != ctrl_if_rxmsg_deferred_prod )
    {
        wmb();
        ctrl_if_rxmsg_deferred_prod = dp;
        schedule_work(&ctrl_if_rxmsg_deferred_work);
    }
}

static irqreturn_t ctrl_if_interrupt(int irq, void *dev_id,
                                     struct pt_regs *regs)
{
    if ( RING_HAS_UNCONSUMED_RESPONSES(&ctrl_if_tx_ring) )
        tasklet_schedule(&ctrl_if_tx_tasklet);

    if ( RING_HAS_UNCONSUMED_REQUESTS(&ctrl_if_rx_ring) )
        tasklet_schedule(&ctrl_if_rx_tasklet);

    return IRQ_HANDLED;
}

int
ctrl_if_send_message_noblock(
    ctrl_msg_t *msg, 
    ctrl_msg_handler_t hnd,
    unsigned long id)
{
    unsigned long flags;
    ctrl_msg_t   *dmsg;
    int           i;

    spin_lock_irqsave(&ctrl_if_lock, flags);

    if ( RING_FULL(&ctrl_if_tx_ring) )
    {
        spin_unlock_irqrestore(&ctrl_if_lock, flags);
        return -EAGAIN;
    }

    msg->id = 0xFF;
    if ( hnd != NULL )
    {
        for ( i = 0; ctrl_if_txmsg_id_mapping[i].fn != NULL; i++ )
            continue;
        ctrl_if_txmsg_id_mapping[i].fn = hnd;
        ctrl_if_txmsg_id_mapping[i].id = id;
        msg->id = i;
    }

    DPRINTK("Tx-Req %u/%u :: %d/%d\n", 
            ctrl_if_tx_ring.req_prod_pvt, 
            ctrl_if_tx_ring.rsp_cons,
            msg->type, msg->subtype);

    dmsg = RING_GET_REQUEST(&ctrl_if_tx_ring, 
            ctrl_if_tx_ring.req_prod_pvt);
    memcpy(dmsg, msg, sizeof(*msg));
    ctrl_if_tx_ring.req_prod_pvt++;
    RING_PUSH_REQUESTS(&ctrl_if_tx_ring);

    spin_unlock_irqrestore(&ctrl_if_lock, flags);

    ctrl_if_notify_controller();

    return 0;
}

int
ctrl_if_send_message_block(
    ctrl_msg_t *msg, 
    ctrl_msg_handler_t hnd, 
    unsigned long id,
    long wait_state)
{
    DECLARE_WAITQUEUE(wait, current);
    int rc;

    /* Fast path. */
    if ( (rc = ctrl_if_send_message_noblock(msg, hnd, id)) != -EAGAIN )
        return rc;

    add_wait_queue(&ctrl_if_tx_wait, &wait);

    for ( ; ; )
    {
        set_current_state(wait_state);

        if ( (rc = ctrl_if_send_message_noblock(msg, hnd, id)) != -EAGAIN )
            break;

        rc = -ERESTARTSYS;
        if ( signal_pending(current) && (wait_state == TASK_INTERRUPTIBLE) )
            break;

        schedule();
    }

    set_current_state(TASK_RUNNING);
    remove_wait_queue(&ctrl_if_tx_wait, &wait);

    return rc;
}

/* Allow a reponse-callback handler to find context of a blocked requester.  */
struct rsp_wait {
    ctrl_msg_t         *msg;  /* Buffer for the response message.            */
    struct task_struct *task; /* The task that is blocked on the response.   */
    int                 done; /* Indicate to 'task' that response is rcv'ed. */
};

static void __ctrl_if_get_response(ctrl_msg_t *msg, unsigned long id)
{
    struct rsp_wait    *wait = (struct rsp_wait *)id;
    struct task_struct *task = wait->task;

    memcpy(wait->msg, msg, sizeof(*msg));
    wmb();
    wait->done = 1;

    wake_up_process(task);
}

int
ctrl_if_send_message_and_get_response(
    ctrl_msg_t *msg, 
    ctrl_msg_t *rmsg,
    long wait_state)
{
    struct rsp_wait wait;
    int rc;

    wait.msg  = rmsg;
    wait.done = 0;
    wait.task = current;

    if ( (rc = ctrl_if_send_message_block(msg, __ctrl_if_get_response,
                                          (unsigned long)&wait,
                                          wait_state)) != 0 )
        return rc;

    for ( ; ; )
    {
        /* NB. Can't easily support TASK_INTERRUPTIBLE here. */
        set_current_state(TASK_UNINTERRUPTIBLE);
        if ( wait.done )
            break;
        schedule();
    }

    set_current_state(TASK_RUNNING);
    return 0;
}

int
ctrl_if_enqueue_space_callback(
    struct tq_struct *task)
{
    /* Fast path. */
    if ( !RING_FULL(&ctrl_if_tx_ring) )
        return 0;

    (void)queue_task(task, &ctrl_if_tx_tq);

    /*
     * We may race execution of the task queue, so return re-checked status. If
     * the task is not executed despite the ring being non-full then we will
     * certainly return 'not full'.
     */
    smp_mb();
    return RING_FULL(&ctrl_if_tx_ring);
}

void
ctrl_if_send_response(
    ctrl_msg_t *msg)
{
    unsigned long flags;
    ctrl_msg_t   *dmsg;

    /*
     * NB. The response may the original request message, modified in-place.
     * In this situation we may have src==dst, so no copying is required.
     */
    spin_lock_irqsave(&ctrl_if_lock, flags);

    DPRINTK("Tx-Rsp %u :: %d/%d\n", 
            ctrl_if_rx_ring.rsp_prod_pvt, 
            msg->type, msg->subtype);

    dmsg = RING_GET_RESPONSE(&ctrl_if_rx_ring, 
            ctrl_if_rx_ring.rsp_prod_pvt);
    if ( dmsg != msg )
        memcpy(dmsg, msg, sizeof(*msg));

    ctrl_if_rx_ring.rsp_prod_pvt++;
    RING_PUSH_RESPONSES(&ctrl_if_rx_ring);

    spin_unlock_irqrestore(&ctrl_if_lock, flags);

    ctrl_if_notify_controller();
}

int
ctrl_if_register_receiver(
    u8 type, 
    ctrl_msg_handler_t hnd, 
    unsigned int flags)
{
    unsigned long _flags;
    int inuse;

    spin_lock_irqsave(&ctrl_if_lock, _flags);

    inuse = (ctrl_if_rxmsg_handler[type] != ctrl_if_rxmsg_default_handler);

    if ( inuse )
    {
        printk(KERN_INFO "Receiver %p already established for control "
               "messages of type %d.\n", ctrl_if_rxmsg_handler[type], type);
    }
    else
    {
        ctrl_if_rxmsg_handler[type] = hnd;
        clear_bit(type, (unsigned long *)&ctrl_if_rxmsg_blocking_context);
        if ( flags == CALLBACK_IN_BLOCKING_CONTEXT )
        {
            set_bit(type, (unsigned long *)&ctrl_if_rxmsg_blocking_context);
            if ( !safe_to_schedule_task )
                BUG();
        }
    }

    spin_unlock_irqrestore(&ctrl_if_lock, _flags);

    return !inuse;
}

void 
ctrl_if_unregister_receiver(
    u8 type,
    ctrl_msg_handler_t hnd)
{
    unsigned long flags;

    spin_lock_irqsave(&ctrl_if_lock, flags);

    if ( ctrl_if_rxmsg_handler[type] != hnd )
        printk(KERN_INFO "Receiver %p is not registered for control "
               "messages of type %d.\n", hnd, type);
    else
        ctrl_if_rxmsg_handler[type] = ctrl_if_rxmsg_default_handler;

    spin_unlock_irqrestore(&ctrl_if_lock, flags);

    /* Ensure that @hnd will not be executed after this function returns. */
    tasklet_unlock_wait(&ctrl_if_rx_tasklet);
}

void ctrl_if_suspend(void)
{
    teardown_irq(ctrl_if_irq, &ctrl_if_irq_action);
    unbind_evtchn_from_irq(ctrl_if_evtchn);
}

void ctrl_if_resume(void)
{
    control_if_t *ctrl_if = get_ctrl_if();

    if ( xen_start_info->flags & SIF_INITDOMAIN )
    {
        /*
         * The initial domain must create its own domain-controller link.
         * The controller is probably not running at this point, but will
         * pick up its end of the event channel from 
         */
        evtchn_op_t op;
	extern void bind_evtchn_to_cpu(unsigned port, unsigned cpu);

        op.cmd = EVTCHNOP_bind_interdomain;
        op.u.bind_interdomain.dom1 = DOMID_SELF;
        op.u.bind_interdomain.dom2 = DOMID_SELF;
        op.u.bind_interdomain.port1 = 0;
        op.u.bind_interdomain.port2 = 0;
        if ( HYPERVISOR_event_channel_op(&op) != 0 )
            BUG();
        xen_start_info->domain_controller_evtchn = op.u.bind_interdomain.port1;
        initdom_ctrlif_domcontroller_port   = op.u.bind_interdomain.port2;
	bind_evtchn_to_cpu(op.u.bind_interdomain.port1, 0);
    }

    /* Sync up with shared indexes. */
    FRONT_RING_ATTACH(&ctrl_if_tx_ring, &ctrl_if->tx_ring, CONTROL_RING_MEM);
    BACK_RING_ATTACH(&ctrl_if_rx_ring, &ctrl_if->rx_ring, CONTROL_RING_MEM);

    ctrl_if_evtchn = xen_start_info->domain_controller_evtchn;
    ctrl_if_irq    = bind_evtchn_to_irq(ctrl_if_evtchn);

    memset(&ctrl_if_irq_action, 0, sizeof(ctrl_if_irq_action));
    ctrl_if_irq_action.handler = ctrl_if_interrupt;
    ctrl_if_irq_action.name    = "ctrl-if";
    (void)setup_irq(ctrl_if_irq, &ctrl_if_irq_action);
}

void __init ctrl_if_init(void)
{
    control_if_t *ctrl_if = get_ctrl_if();
    int i;

    for ( i = 0; i < 256; i++ )
        ctrl_if_rxmsg_handler[i] = ctrl_if_rxmsg_default_handler;

    FRONT_RING_ATTACH(&ctrl_if_tx_ring, &ctrl_if->tx_ring, CONTROL_RING_MEM);
    BACK_RING_ATTACH(&ctrl_if_rx_ring, &ctrl_if->rx_ring, CONTROL_RING_MEM);
    
    spin_lock_init(&ctrl_if_lock);

    ctrl_if_resume();
}


/* This is called after it is safe to call schedule_task(). */
static int __init ctrl_if_late_setup(void)
{
    safe_to_schedule_task = 1;
    return 0;
}
__initcall(ctrl_if_late_setup);


/*
 * !! The following are DANGEROUS FUNCTIONS !!
 * Use with care [for example, see xencons_force_flush()].
 */

int ctrl_if_transmitter_empty(void)
{
    return (ctrl_if_tx_ring.sring->req_prod == ctrl_if_tx_ring.rsp_cons);
    
}

void ctrl_if_discard_responses(void)
{
    RING_DROP_PENDING_RESPONSES(&ctrl_if_tx_ring);
}

EXPORT_SYMBOL(ctrl_if_send_message_noblock);
EXPORT_SYMBOL(ctrl_if_send_message_block);
EXPORT_SYMBOL(ctrl_if_send_message_and_get_response);
EXPORT_SYMBOL(ctrl_if_enqueue_space_callback);
EXPORT_SYMBOL(ctrl_if_send_response);
EXPORT_SYMBOL(ctrl_if_register_receiver);
EXPORT_SYMBOL(ctrl_if_unregister_receiver);
