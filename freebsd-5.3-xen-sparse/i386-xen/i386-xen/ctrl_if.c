/******************************************************************************
 * ctrl_if.c
 * 
 * Management functions for special interface to the domain controller.
 * 
 * Copyright (c) 2004, K A Fraser
 * Copyright (c) 2004, K M Macy
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/selinfo.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/ioccom.h>
#include <sys/taskqueue.h>


#include <machine/cpufunc.h>
#include <machine/intr_machdep.h>
#include <machine/xen-os.h>
#include <machine/xen_intr.h>
#include <machine/bus.h>
#include <sys/rman.h>
#include <machine/resource.h>
#include <machine/synch_bitops.h>


#include <machine/hypervisor-ifs.h>

#include <machine/ctrl_if.h>
#include <machine/evtchn.h>

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
static struct mtx ctrl_if_lock;
static int *      ctrl_if_wchan = &ctrl_if_evtchn;


static ctrl_front_ring_t ctrl_if_tx_ring;
static ctrl_back_ring_t  ctrl_if_rx_ring;

/* Incoming message requests. */
    /* Primary message type -> message handler. */
static ctrl_msg_handler_t ctrl_if_rxmsg_handler[256];
    /* Primary message type -> callback in process context? */
static unsigned long ctrl_if_rxmsg_blocking_context[256/sizeof(unsigned long)];
    /* Queue up messages to be handled in process context. */
static ctrl_msg_t ctrl_if_rxmsg_deferred[CONTROL_RING_SIZE];
static CONTROL_RING_IDX ctrl_if_rxmsg_deferred_prod;
static CONTROL_RING_IDX ctrl_if_rxmsg_deferred_cons;

/* Incoming message responses: message identifier -> message handler/id. */
static struct {
    ctrl_msg_handler_t fn;
    unsigned long      id;
} ctrl_if_txmsg_id_mapping[CONTROL_RING_SIZE];

/*
 * FreeBSD task queues don't allow you to requeue an already executing task.
 * Since ctrl_if_interrupt clears the TX_FULL condition and schedules any 
 * waiting tasks, which themselves may need to schedule a new task 
 * (due to new a TX_FULL condition), we ping-pong between these A/B task queues.
 * The interrupt runs anything on the current queue and moves the index so that
 * future schedulings occur on the next queue.  We should never get into a 
 * situation where there is a task scheduleded on both the A & B queues.
 */
TASKQUEUE_DECLARE(ctrl_if_txA);
TASKQUEUE_DEFINE(ctrl_if_txA, NULL, NULL, {});
TASKQUEUE_DECLARE(ctrl_if_txB);
TASKQUEUE_DEFINE(ctrl_if_txB, NULL, NULL, {});
struct taskqueue **taskqueue_ctrl_if_tx[2] = { &taskqueue_ctrl_if_txA,
    				               &taskqueue_ctrl_if_txB };
static int ctrl_if_idx = 0;

static struct task ctrl_if_rx_tasklet;
static struct task ctrl_if_tx_tasklet;
    /* Passed to schedule_task(). */
static struct task ctrl_if_rxmsg_deferred_task;



#define get_ctrl_if() ((control_if_t *)((char *)HYPERVISOR_shared_info + 2048))

static void 
ctrl_if_notify_controller(void)
{
    notify_via_evtchn(ctrl_if_evtchn);
}

static void 
ctrl_if_rxmsg_default_handler(ctrl_msg_t *msg, unsigned long id)
{
    msg->length = 0;
    ctrl_if_send_response(msg);
}

static void 
__ctrl_if_tx_tasklet(void *context __unused, int pending __unused)
{
    ctrl_msg_t   *msg;
    int           was_full = RING_FULL(&ctrl_if_tx_ring);
    RING_IDX      i, rp;

    i  = ctrl_if_tx_ring.rsp_cons;
    rp = ctrl_if_tx_ring.sring->rsp_prod;
    rmb(); /* Ensure we see all requests up to 'rp'. */

    for ( ; i != rp; i++ )
    {
        msg = RING_GET_RESPONSE(&ctrl_if_tx_ring, i);

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
     * Step over the message in the ring /after/ finishing reading it. As 
     * soon as the index is updated then the message may get blown away.
     */
    smp_mb();
    ctrl_if_tx_ring.rsp_cons = i;

    if ( was_full && !RING_FULL(&ctrl_if_tx_ring) )
    {
        wakeup(ctrl_if_wchan);

	/* bump idx so future enqueues will occur on the next taskq
	 * process any currently pending tasks
	 */
	ctrl_if_idx++;
        taskqueue_run(*taskqueue_ctrl_if_tx[(ctrl_if_idx-1) & 1]);
    }

}

static void 
__ctrl_if_rxmsg_deferred_task(void *context __unused, int pending __unused)
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

static void 
__ctrl_if_rx_tasklet(void *context __unused, int pending __unused)
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
	
	if ( msg.length > sizeof(msg.msg))
	    msg.length = sizeof(msg.msg);
        if ( msg.length != 0 )
            memcpy(msg.msg, pmsg->msg, msg.length);
        if ( test_bit(msg.type, &ctrl_if_rxmsg_blocking_context) )
        {
            memcpy(&ctrl_if_rxmsg_deferred[MASK_CONTROL_IDX(dp++)], 
		    &msg, offsetof(ctrl_msg_t, msg) + msg.length);
        }
        else
        {
            (*ctrl_if_rxmsg_handler[msg.type])(&msg, 0);
        }
    }
    ctrl_if_rx_ring.req_cons = i;

    if ( dp != ctrl_if_rxmsg_deferred_prod )
    {
        wmb();
        ctrl_if_rxmsg_deferred_prod = dp;
        taskqueue_enqueue(taskqueue_thread, &ctrl_if_rxmsg_deferred_task);
    }

}

static void 
ctrl_if_interrupt(void *ctrl_sc)
/* (int irq, void *dev_id, struct pt_regs *regs) */
{

    
    if ( RING_HAS_UNCONSUMED_RESPONSES(&ctrl_if_tx_ring) )
	taskqueue_enqueue(taskqueue_swi, &ctrl_if_tx_tasklet);
    

    if ( RING_HAS_UNCONSUMED_REQUESTS(&ctrl_if_rx_ring) )
 	taskqueue_enqueue(taskqueue_swi, &ctrl_if_rx_tasklet);
    
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

    mtx_lock_irqsave(&ctrl_if_lock, flags);

    if ( RING_FULL(&ctrl_if_tx_ring) )
    {
        mtx_unlock_irqrestore(&ctrl_if_lock, flags);
        return EAGAIN;
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

    dmsg = RING_GET_REQUEST(&ctrl_if_tx_ring, 
            ctrl_if_tx_ring.req_prod_pvt);
    memcpy(dmsg, msg, sizeof(*msg));
    ctrl_if_tx_ring.req_prod_pvt++;
    RING_PUSH_REQUESTS(&ctrl_if_tx_ring);

    mtx_unlock_irqrestore(&ctrl_if_lock, flags);

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
    int rc, sst = 0;
    
    /* Fast path. */
    if ( (rc = ctrl_if_send_message_noblock(msg, hnd, id)) != EAGAIN ) 
        goto done;
    
    for ( ; ; )
    {

        if ( (rc = ctrl_if_send_message_noblock(msg, hnd, id)) != EAGAIN )
            break;

        if ( sst != 0) {
	    rc = EINTR;
	    goto done;
	}

        sst = tsleep(ctrl_if_wchan, PWAIT|PCATCH, "ctlrwt", 10);
    }
 done:
    
    return rc;
}

int 
ctrl_if_enqueue_space_callback(struct task *task)
{

    /* Fast path. */
    if ( !RING_FULL(&ctrl_if_tx_ring) )
        return 0;

    (void)taskqueue_enqueue(*taskqueue_ctrl_if_tx[(ctrl_if_idx & 1)], task);

    /*
     * We may race execution of the task queue, so return re-checked status. If
     * the task is not executed despite the ring being non-full then we will
     * certainly return 'not full'.
     */
    smp_mb();
    return RING_FULL(&ctrl_if_tx_ring);
}

void 
ctrl_if_send_response(ctrl_msg_t *msg)
{
    unsigned long flags;
    ctrl_msg_t   *dmsg;

    /*
     * NB. The response may the original request message, modified in-place.
     * In this situation we may have src==dst, so no copying is required.
     */
    mtx_lock_irqsave(&ctrl_if_lock, flags);
    dmsg =  RING_GET_RESPONSE(&ctrl_if_rx_ring, 
			      ctrl_if_rx_ring.rsp_prod_pvt);
    if ( dmsg != msg )
        memcpy(dmsg, msg, sizeof(*msg));
 
    ctrl_if_rx_ring.rsp_prod_pvt++;
    RING_PUSH_RESPONSES(&ctrl_if_rx_ring);

    mtx_unlock_irqrestore(&ctrl_if_lock, flags);

    ctrl_if_notify_controller();
}

int 
ctrl_if_register_receiver(
    uint8_t type, 
    ctrl_msg_handler_t hnd, 
    unsigned int flags)
{
    unsigned long _flags;
    int inuse;
    
    mtx_lock_irqsave(&ctrl_if_lock, _flags);

    inuse = (ctrl_if_rxmsg_handler[type] != ctrl_if_rxmsg_default_handler);

    if ( inuse )
    {
        printk("Receiver %p already established for control "
               "messages of type %d.\n", ctrl_if_rxmsg_handler[type], type);
    }
    else
    {
        ctrl_if_rxmsg_handler[type] = hnd;
        clear_bit(type, &ctrl_if_rxmsg_blocking_context);
        if ( flags == CALLBACK_IN_BLOCKING_CONTEXT )
        {
            set_bit(type, &ctrl_if_rxmsg_blocking_context);
        }
    }

    mtx_unlock_irqrestore(&ctrl_if_lock, _flags);
    
    return !inuse;
}

void 
ctrl_if_unregister_receiver(uint8_t type, ctrl_msg_handler_t hnd)
{
    unsigned long flags;

    mtx_lock_irqsave(&ctrl_if_lock, flags);

    if ( ctrl_if_rxmsg_handler[type] != hnd )
        printk("Receiver %p is not registered for control "
               "messages of type %d.\n", hnd, type);
    else
        ctrl_if_rxmsg_handler[type] = ctrl_if_rxmsg_default_handler;

    mtx_unlock_irqrestore(&ctrl_if_lock, flags);

    /* Ensure that @hnd will not be executed after this function returns. */
    /* XXX need rx_tasklet_lock -- can cheat for now?*/
#ifdef notyet
    tasklet_unlock_wait(&ctrl_if_rx_tasklet);
#endif
}

void 
ctrl_if_suspend(void)
{
    /* I'm not sure what the equivalent is - we aren't going to support suspend 
     * yet anyway 
     */
#ifdef notyet
    free_irq(ctrl_if_irq, NULL);
#endif
    unbind_evtchn_from_irq(ctrl_if_evtchn);
}
 
#if 0
/** Reset the control interface progress pointers.
 * Marks the queues empty if 'clear' non-zero.
 */
static void 
ctrl_if_reset(int clear)
{
    control_if_t *ctrl_if = get_ctrl_if();

    if (clear) {
	*ctrl_if = (control_if_t){};
    }
    
    ctrl_if_tx_resp_cons = ctrl_if->tx_resp_prod;
    ctrl_if_rx_req_cons  = ctrl_if->rx_resp_prod;
}

#endif
void 
ctrl_if_resume(void)
{
    control_if_t *ctrl_if = get_ctrl_if();

    TRACE_ENTER;
    if ( xen_start_info->flags & SIF_INITDOMAIN )
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
        op.u.bind_interdomain.port1 = 0;
        op.u.bind_interdomain.port2 = 0;
        if ( HYPERVISOR_event_channel_op(&op) != 0 )
            panic("event_channel_op failed\n");
        xen_start_info->domain_controller_evtchn = op.u.bind_interdomain.port1;
        initdom_ctrlif_domcontroller_port   = op.u.bind_interdomain.port2;
    }
    

    /* Sync up with shared indexes. */
    FRONT_RING_ATTACH(&ctrl_if_tx_ring, &ctrl_if->tx_ring, CONTROL_RING_MEM);
    BACK_RING_ATTACH(&ctrl_if_rx_ring, &ctrl_if->rx_ring, CONTROL_RING_MEM);

    ctrl_if_evtchn = xen_start_info->domain_controller_evtchn;
    ctrl_if_irq    = bind_evtchn_to_irq(ctrl_if_evtchn);
    
    /*
     * I have not taken the time to determine what the interrupt thread priorities
     * correspond to - this interface is used for network and disk, network would
     * seem higher priority, hence I'm using it
     */

    intr_add_handler("ctrl-if", ctrl_if_irq, (driver_intr_t*)ctrl_if_interrupt,
		     NULL, INTR_TYPE_NET, NULL);
    TRACE_EXIT;
    /* XXX currently assuming not MPSAFE */ 
}

static void 
ctrl_if_init(void *dummy __unused)
{
    control_if_t *ctrl_if = get_ctrl_if();

    int i;

    for ( i = 0; i < 256; i++ )
        ctrl_if_rxmsg_handler[i] = ctrl_if_rxmsg_default_handler;
    
    FRONT_RING_ATTACH(&ctrl_if_tx_ring, &ctrl_if->tx_ring, CONTROL_RING_MEM);
    BACK_RING_ATTACH(&ctrl_if_rx_ring, &ctrl_if->rx_ring, CONTROL_RING_MEM);

    mtx_init(&ctrl_if_lock, "ctrlif", NULL, MTX_SPIN | MTX_NOWITNESS);
    
    TASK_INIT(&ctrl_if_tx_tasklet, 0, __ctrl_if_tx_tasklet, NULL);

    TASK_INIT(&ctrl_if_rx_tasklet, 0, __ctrl_if_rx_tasklet, NULL);

    TASK_INIT(&ctrl_if_rxmsg_deferred_task, 0, __ctrl_if_rxmsg_deferred_task, NULL);


    ctrl_if_resume();
}

/*
 * !! The following are DANGEROUS FUNCTIONS !!
 * Use with care [for example, see xencons_force_flush()].
 */

int 
ctrl_if_transmitter_empty(void)
{
    return (ctrl_if_tx_ring.sring->req_prod == ctrl_if_tx_ring.rsp_cons);
}

void 
ctrl_if_discard_responses(void)
{
    RING_DROP_PENDING_RESPONSES(&ctrl_if_tx_ring);
}

SYSINIT(ctrl_if_init, SI_SUB_DRIVERS, SI_ORDER_FIRST, ctrl_if_init, NULL);
