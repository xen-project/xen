/******************************************************************************
 * ctrl_if.c
 * 
 * Management functions for special interface to the domain controller.
 * 
 * Copyright (c) 2004, K A Fraser
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <asm-xen/ctrl_if.h>
#include <asm-xen/evtchn.h>

#if 0
#define DPRINTK(_f, _a...) printk(KERN_ALERT "(file=%s, line=%d) " _f, \
                           __FILE__ , __LINE__ , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#endif

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

static CONTROL_RING_IDX ctrl_if_tx_resp_cons;
static CONTROL_RING_IDX ctrl_if_rx_req_cons;

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
static struct tq_struct ctrl_if_rxmsg_deferred_tq;
static DECLARE_TASK_QUEUE(ctrl_if_tx_tq);
#else
static struct work_struct ctrl_if_rxmsg_deferred_work;
static struct workqueue_struct *ctrl_if_tx_wq = NULL;
#endif

static DECLARE_WAIT_QUEUE_HEAD(ctrl_if_tx_wait);
static void __ctrl_if_tx_tasklet(unsigned long data);
static DECLARE_TASKLET(ctrl_if_tx_tasklet, __ctrl_if_tx_tasklet, 0);

static void __ctrl_if_rx_tasklet(unsigned long data);
static DECLARE_TASKLET(ctrl_if_rx_tasklet, __ctrl_if_rx_tasklet, 0);

#define get_ctrl_if() ((control_if_t *)((char *)HYPERVISOR_shared_info + 2048))
#define TX_FULL(_c)   \
    (((_c)->tx_req_prod - ctrl_if_tx_resp_cons) == CONTROL_RING_SIZE)

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
    control_if_t *ctrl_if = get_ctrl_if();
    ctrl_msg_t   *msg;
    int           was_full = TX_FULL(ctrl_if);

    while ( ctrl_if_tx_resp_cons != ctrl_if->tx_resp_prod )
    {
        msg = &ctrl_if->tx_ring[MASK_CONTROL_IDX(ctrl_if_tx_resp_cons)];

        DPRINTK("Rx-Rsp %u/%u :: %d/%d\n", 
                ctrl_if_tx_resp_cons,
                ctrl_if->tx_resp_prod,
                msg->type, msg->subtype);

        /* Execute the callback handler, if one was specified. */
        if ( msg->id != 0xFF )
        {
            (*ctrl_if_txmsg_id_mapping[msg->id].fn)(
                msg, ctrl_if_txmsg_id_mapping[msg->id].id);
            smp_mb(); /* Execute, /then/ free. */
            ctrl_if_txmsg_id_mapping[msg->id].fn = NULL;
        }

        /*
         * Step over the message in the ring /after/ finishing reading it. As 
         * soon as the index is updated then the message may get blown away.
         */
        smp_mb();
        ctrl_if_tx_resp_cons++;
    }

    if ( was_full && !TX_FULL(ctrl_if) )
    {
        wake_up(&ctrl_if_tx_wait);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
        run_task_queue(&ctrl_if_tx_tq);
#endif
    }
}

static void __ctrl_if_rxmsg_deferred(void *unused)
{
    ctrl_msg_t *msg;

    while ( ctrl_if_rxmsg_deferred_cons != ctrl_if_rxmsg_deferred_prod )
    {
        msg = &ctrl_if_rxmsg_deferred[MASK_CONTROL_IDX(
            ctrl_if_rxmsg_deferred_cons++)];
        (*ctrl_if_rxmsg_handler[msg->type])(msg, 0);
    }
}

static void __ctrl_if_rx_tasklet(unsigned long data)
{
    control_if_t *ctrl_if = get_ctrl_if();
    ctrl_msg_t    msg, *pmsg;

    while ( ctrl_if_rx_req_cons != ctrl_if->rx_req_prod )
    {
        pmsg = &ctrl_if->rx_ring[MASK_CONTROL_IDX(ctrl_if_rx_req_cons++)];
        memcpy(&msg, pmsg, offsetof(ctrl_msg_t, msg));

        DPRINTK("Rx-Req %u/%u :: %d/%d\n", 
                ctrl_if_rx_req_cons-1,
                ctrl_if->rx_req_prod,
                msg.type, msg.subtype);

        if ( msg.length != 0 )
            memcpy(msg.msg, pmsg->msg, msg.length);

        if ( test_bit(msg.type, 
                      (unsigned long *)&ctrl_if_rxmsg_blocking_context) )
        {
            pmsg = &ctrl_if_rxmsg_deferred[MASK_CONTROL_IDX(
                ctrl_if_rxmsg_deferred_prod++)];
            memcpy(pmsg, &msg, offsetof(ctrl_msg_t, msg) + msg.length);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
            schedule_task(&ctrl_if_rxmsg_deferred_tq);
#else
            schedule_work(&ctrl_if_rxmsg_deferred_work);
#endif
        }
        else
        {
            (*ctrl_if_rxmsg_handler[msg.type])(&msg, 0);
        }
    }
}

static irqreturn_t ctrl_if_interrupt(int irq, void *dev_id,
                                     struct pt_regs *regs)
{
    control_if_t *ctrl_if = get_ctrl_if();

    if ( ctrl_if_tx_resp_cons != ctrl_if->tx_resp_prod )
        tasklet_schedule(&ctrl_if_tx_tasklet);

    if ( ctrl_if_rx_req_cons != ctrl_if->rx_req_prod )
        tasklet_schedule(&ctrl_if_rx_tasklet);

    return IRQ_HANDLED;
}

int ctrl_if_send_message_noblock(
    ctrl_msg_t *msg, 
    ctrl_msg_handler_t hnd,
    unsigned long id)
{
    control_if_t *ctrl_if = get_ctrl_if();
    unsigned long flags;
    int           i;

    spin_lock_irqsave(&ctrl_if_lock, flags);

    if ( TX_FULL(ctrl_if) )
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
            ctrl_if->tx_req_prod, 
            ctrl_if_tx_resp_cons,
            msg->type, msg->subtype);

    memcpy(&ctrl_if->tx_ring[MASK_CONTROL_IDX(ctrl_if->tx_req_prod)], 
           msg, sizeof(*msg));
    wmb(); /* Write the message before letting the controller peek at it. */
    ctrl_if->tx_req_prod++;

    spin_unlock_irqrestore(&ctrl_if_lock, flags);

    ctrl_if_notify_controller();

    return 0;
}

int ctrl_if_send_message_block(
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

int ctrl_if_enqueue_space_callback(struct work_struct *work)
{
    control_if_t *ctrl_if = get_ctrl_if();

    /* Fast path. */
    if ( !TX_FULL(ctrl_if) )
        return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    (void)queue_task(work, &ctrl_if_tx_tq);
#else
    if ( ctrl_if_tx_wq )
        (void)queue_work(ctrl_if_tx_wq, work);
    else
        return 1;
#endif

    /*
     * We may race execution of the task queue, so return re-checked status. If
     * the task is not executed despite the ring being non-full then we will
     * certainly return 'not full'.
     */
    smp_mb();
    return TX_FULL(ctrl_if);
}

void ctrl_if_send_response(ctrl_msg_t *msg)
{
    control_if_t *ctrl_if = get_ctrl_if();
    unsigned long flags;
    ctrl_msg_t   *dmsg;

    /*
     * NB. The response may the original request message, modified in-place.
     * In this situation we may have src==dst, so no copying is required.
     */
    spin_lock_irqsave(&ctrl_if_lock, flags);

    DPRINTK("Tx-Rsp %u :: %d/%d\n", 
            ctrl_if->rx_resp_prod, 
            msg->type, msg->subtype);

    dmsg = &ctrl_if->rx_ring[MASK_CONTROL_IDX(ctrl_if->rx_resp_prod)];
    if ( dmsg != msg )
        memcpy(dmsg, msg, sizeof(*msg));

    wmb(); /* Write the message before letting the controller peek at it. */
    ctrl_if->rx_resp_prod++;

    spin_unlock_irqrestore(&ctrl_if_lock, flags);

    ctrl_if_notify_controller();
}

int ctrl_if_register_receiver(
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

void ctrl_if_unregister_receiver(u8 type, ctrl_msg_handler_t hnd)
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
    free_irq(ctrl_if_irq, NULL);
    unbind_evtchn_from_irq(ctrl_if_evtchn);
}

/** Reset the control interface progress pointers.
 * Marks the queues empty if 'clear' non-zero.
 */
void ctrl_if_reset(int clear){
    control_if_t *ctrl_if = get_ctrl_if();

    if(clear){
        *ctrl_if = (control_if_t){};
    }
    ctrl_if_tx_resp_cons = ctrl_if->tx_resp_prod;
    ctrl_if_rx_req_cons  = ctrl_if->rx_resp_prod;
}

void ctrl_if_resume(void)
{
    if ( start_info.flags & SIF_INITDOMAIN )
    {
        /*
         * The initial domain must create its own domain-controller link.
         * The controller is probably not running at this point, but will
         * pick up its end of the event channel from 
         */
        evtchn_op_t op;
        op.cmd = EVTCHNOP_bind_interdomain;
        op.u.bind_interdomain.dom1 = DOMID_SELF;
        op.u.bind_interdomain.dom2 = DOMID_SELF;
        if ( HYPERVISOR_event_channel_op(&op) != 0 )
            BUG();
        start_info.domain_controller_evtchn = op.u.bind_interdomain.port1;
        initdom_ctrlif_domcontroller_port   = op.u.bind_interdomain.port2;
    }

    ctrl_if_reset(0);

    ctrl_if_evtchn = start_info.domain_controller_evtchn;
    ctrl_if_irq    = bind_evtchn_to_irq(ctrl_if_evtchn);

#define SA_STATIC_ACTION 0x01000000 /* so that free_irq() doesn't do kfree() */
    memset(&ctrl_if_irq_action, 0, sizeof(ctrl_if_irq_action));
    ctrl_if_irq_action.handler = ctrl_if_interrupt;
    ctrl_if_irq_action.name    = "ctrl-if";
    ctrl_if_irq_action.flags   = SA_STATIC_ACTION;
    (void)setup_irq(ctrl_if_irq, &ctrl_if_irq_action);
}

void __init ctrl_if_init(void)
{
        int i;

    for ( i = 0; i < 256; i++ )
        ctrl_if_rxmsg_handler[i] = ctrl_if_rxmsg_default_handler;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    ctrl_if_rxmsg_deferred_tq.routine = __ctrl_if_rxmsg_deferred;
#else
    INIT_WORK(&ctrl_if_rxmsg_deferred_work,
              (void *)__ctrl_if_rxmsg_deferred,
              NULL);
#endif

    spin_lock_init(&ctrl_if_lock);

    ctrl_if_reset(1);
    ctrl_if_resume();
}


/* This is called after it is safe to call schedule_task(). */
static int __init ctrl_if_late_setup(void)
{
    safe_to_schedule_task = 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    ctrl_if_tx_wq = create_workqueue("ctrl_if_tx");
    if (ctrl_if_tx_wq == NULL)
        return 1;                 /* XXX */
#endif
    return 0;
}
__initcall(ctrl_if_late_setup);


/*
 * !! The following are DANGEROUS FUNCTIONS !!
 * Use with care [for example, see xencons_force_flush()].
 */

int ctrl_if_transmitter_empty(void)
{
    return (get_ctrl_if()->tx_req_prod == ctrl_if_tx_resp_cons);
}

void ctrl_if_discard_responses(void)
{
    ctrl_if_tx_resp_cons = get_ctrl_if()->tx_resp_prod;
}

