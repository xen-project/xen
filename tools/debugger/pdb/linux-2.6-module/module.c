
/*
 * module.c
 *
 * Handles initial registration with pdb when the pdb module starts up
 * and cleanup when the module goes away (sortof :)
 * Also receives each request from pdb in domain 0 and dispatches to the
 * appropriate debugger function.
 */

#include <linux/module.h>
#include <linux/interrupt.h>

#include <asm-i386/kdebug.h>

#include <xen/evtchn.h>
#include <xen/ctrl_if.h>
#include <xen/hypervisor.h>
#include <xen/interface/io/domain_controller.h>
#include <xen/interface/xen.h>

#include <xen/interface/io/ring.h>

#include "pdb_module.h"
#include "pdb_debug.h"

#define PDB_RING_SIZE __RING_SIZE((pdb_sring_t *)0, PAGE_SIZE)

static pdb_back_ring_t pdb_ring;
static unsigned int    pdb_evtchn;
static unsigned int    pdb_irq;
static unsigned int    pdb_domain;

/* work queue */
static void pdb_work_handler(void *unused);
static DECLARE_WORK(pdb_deferred_work, pdb_work_handler, NULL);

/*
 * send response to a pdb request
 */
void
pdb_send_response (pdb_response_t *response)
{
    pdb_response_t *resp;

    resp = RING_GET_RESPONSE(&pdb_ring, pdb_ring.rsp_prod_pvt);

    memcpy(resp, response, sizeof(pdb_response_t));
    resp->domain = pdb_domain;
    
    wmb();                 /* Ensure other side can see the response fields. */
    pdb_ring.rsp_prod_pvt++;
    RING_PUSH_RESPONSES(&pdb_ring);
    notify_via_evtchn(pdb_evtchn);
    return;
}

/*
 * handle a debug command from the front end
 */
static void
pdb_process_request (pdb_request_t *request)
{
    pdb_response_t resp;
    struct task_struct *target;

    read_lock(&tasklist_lock);
    target = find_task_by_pid(request->process);
    if (target)
        get_task_struct(target);
    read_unlock(&tasklist_lock);

    resp.operation = request->operation;
    resp.process   = request->process;

    if (!target)
    {
        printk ("(linux) target not found 0x%x\n", request->process);
        resp.status = PDB_RESPONSE_ERROR;
        goto response;
    }

    switch (request->operation)
    {
    case PDB_OPCODE_PAUSE :
        pdb_suspend(target);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    case PDB_OPCODE_ATTACH :
        pdb_suspend(target);
        pdb_domain = request->u.attach.domain;
        printk("(linux) attach  dom:0x%x pid:0x%x\n",
               pdb_domain, request->process);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    case PDB_OPCODE_DETACH :
        pdb_resume(target);
        printk("(linux) detach 0x%x\n", request->process);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    case PDB_OPCODE_RD_REG :
        resp.u.rd_reg.reg = request->u.rd_reg.reg;
        pdb_read_register(target, &resp.u.rd_reg);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    case PDB_OPCODE_RD_REGS :
        pdb_read_registers(target, &resp.u.rd_regs);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    case PDB_OPCODE_WR_REG :
        pdb_write_register(target, &request->u.wr_reg);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    case PDB_OPCODE_RD_MEM :
        pdb_access_memory(target, request->u.rd_mem.address,
                          &resp.u.rd_mem.data, request->u.rd_mem.length, 
                          PDB_MEM_READ);
        resp.u.rd_mem.address = request->u.rd_mem.address;
        resp.u.rd_mem.length  = request->u.rd_mem.length;
        resp.status = PDB_RESPONSE_OKAY;
        break;
    case PDB_OPCODE_WR_MEM :
        pdb_access_memory(target, request->u.wr_mem.address,
                         &request->u.wr_mem.data, request->u.wr_mem.length, 
                          PDB_MEM_WRITE);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    case PDB_OPCODE_CONTINUE :
        pdb_continue(target);
        goto no_response;
        break;
    case PDB_OPCODE_STEP :
        pdb_step(target);
        resp.status = PDB_RESPONSE_OKAY;
        goto no_response;
        break;
    case PDB_OPCODE_SET_BKPT :
        pdb_insert_memory_breakpoint(target, request->u.bkpt.address,
                                     request->u.bkpt.length);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    case PDB_OPCODE_CLR_BKPT :
        pdb_remove_memory_breakpoint(target, request->u.bkpt.address,
                                     request->u.bkpt.length);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    case PDB_OPCODE_SET_WATCHPT :
        pdb_insert_watchpoint(target, &request->u.watchpt);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    case PDB_OPCODE_CLR_WATCHPT :
        pdb_remove_watchpoint(target, &request->u.watchpt);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    default:
        printk("(pdb) unknown request operation %d\n", request->operation);
        resp.status = PDB_RESPONSE_ERROR;
    }

 response:        
    pdb_send_response (&resp);

 no_response:
    return;
}

/*
 * work queue
 */
static void
pdb_work_handler (void *unused)
{
    pdb_request_t *req;
    RING_IDX i, rp;

    rp = pdb_ring.sring->req_prod;
    rmb();

    for ( i = pdb_ring.req_cons; 
          (i != rp) && !RING_REQUEST_CONS_OVERFLOW(&pdb_ring, i);
          i++ )
    {
        req = RING_GET_REQUEST(&pdb_ring, i);
        pdb_process_request(req);

    }
    pdb_ring.req_cons = i;
}

/*
 * receive a pdb request
 */
static irqreturn_t
pdb_interrupt (int irq, void *dev_id, struct pt_regs *ptregs)
{
    schedule_work(&pdb_deferred_work);

    return IRQ_HANDLED;
}

static void
pdb_send_connection_status(int status, unsigned long ring)
{
    ctrl_msg_t cmsg = 
    {
        .type = CMSG_DEBUG,
        .subtype = CMSG_DEBUG_CONNECTION_STATUS,
        .length  = sizeof(pdb_connection_t),
    };
    pdb_connection_t *conn = (pdb_connection_t *)cmsg.msg;

    conn->status = status;
    conn->ring = ring;
    conn->evtchn = 0;

    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
}


/*
 * this is called each time a message is received on the control channel
 */
static void
pdb_ctrlif_rx(ctrl_msg_t *msg, unsigned long id)
{
    switch (msg->subtype)
    {
    case CMSG_DEBUG_CONNECTION_STATUS:
        /* initialize event channel created by the pdb server */

        pdb_evtchn = ((pdb_connection_p) msg->msg)->evtchn;
        pdb_irq = bind_evtchn_to_irq(pdb_evtchn);

        if ( request_irq(pdb_irq, pdb_interrupt, 
                         SA_SAMPLE_RANDOM, "pdb", NULL) )
        {
            printk("(pdb) request irq failed: %d %d\n", pdb_evtchn, pdb_irq);
        }
        break;

    default:
        printk ("(pdb) unknown xcs control message: %d\n", msg->subtype);
        break;
    }

    return;
}


/********************************************************************/

static struct notifier_block pdb_exceptions_nb =
{
    .notifier_call = pdb_exceptions_notify,
    .priority = 0x1                                          /* low priority */
};


static int __init 
pdb_initialize (void)
{
    int err;
    pdb_sring_t *sring;

    printk("----\npdb initialize   %s %s\n", __DATE__, __TIME__);

    /*
    if ( xen_start_info.flags & SIF_INITDOMAIN )
        return 1;
    */

    pdb_evtchn = 0;
    pdb_irq    = 0;
    pdb_domain = 0;

    (void)ctrl_if_register_receiver(CMSG_DEBUG, pdb_ctrlif_rx,
                                    CALLBACK_IN_BLOCKING_CONTEXT);

    /* rings */
    sring = (pdb_sring_t *)__get_free_page(GFP_KERNEL);
    SHARED_RING_INIT(sring);
    BACK_RING_INIT(&pdb_ring, sring, PAGE_SIZE);
 
    /* notify pdb in dom 0 */
    pdb_send_connection_status(PDB_CONNECTION_STATUS_UP, 
                               virt_to_machine(pdb_ring.sring) >> PAGE_SHIFT);

    /* handler for int1 & int3 */
    err = register_die_notifier(&pdb_exceptions_nb);

    return err;
}

static void __exit
pdb_terminate(void)
{
    int err = 0;

    printk("pdb cleanup\n");

    (void)ctrl_if_unregister_receiver(CMSG_DEBUG, pdb_ctrlif_rx);

    if (pdb_irq)
    {
        free_irq(pdb_irq, NULL);
        pdb_irq = 0;
    }

    if (pdb_evtchn)
    {
        unbind_evtchn_from_irq(pdb_evtchn); 
        pdb_evtchn = 0;
    }

    pdb_send_connection_status(PDB_CONNECTION_STATUS_DOWN, 0);

    /* handler for int1 & int3 */
    err = unregister_die_notifier(&pdb_exceptions_nb);

	return;
}


module_init(pdb_initialize);
module_exit(pdb_terminate);


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

