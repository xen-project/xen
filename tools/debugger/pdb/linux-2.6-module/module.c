
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

#include <asm-xen/evtchn.h>
#include <asm-xen/ctrl_if.h>
#include <asm-xen/hypervisor.h>
#include <asm-xen/xen-public/io/domain_controller.h>
#include <asm-xen/xen-public/xen.h>

#include <asm-xen/xen-public/io/ring.h>

#include "pdb_module.h"

#define PDB_RING_SIZE __RING_SIZE((pdb_sring_t *)0, PAGE_SIZE)

static pdb_back_ring_t pdb_ring;
static unsigned int    pdb_evtchn;
static unsigned int    pdb_irq;

/*
 * send response to a pdb request
 */
static void
pdb_send_response (pdb_response_t *response)
{
    pdb_response_t *resp;

    resp = RING_GET_RESPONSE(&pdb_ring, pdb_ring.rsp_prod_pvt);

    memcpy(resp, response, sizeof(pdb_response_t));
    
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

    switch (request->operation)
    {
    case PDB_OPCODE_ATTACH :
        pdb_attach(request->process);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    case PDB_OPCODE_DETACH :
        pdb_detach(request->process);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    case PDB_OPCODE_RD_REG :
        pdb_read_register(request->process, &request->u.rd_reg, 
                          (unsigned long *)&resp.value);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    case PDB_OPCODE_WR_REG :
        pdb_write_register(request->process, &request->u.wr_reg);
        resp.status = PDB_RESPONSE_OKAY;
        break;
    default:
        printk("(pdb) unknown request operation %d\n", request->operation);
        resp.status = PDB_RESPONSE_ERROR;
    }
        
    resp.operation = request->operation;
            
    pdb_send_response (&resp);
    return;
}

/*
 * receive a pdb request
 */
static irqreturn_t
pdb_interrupt (int irq, void *dev_id, struct pt_regs *ptregs)
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

    return IRQ_HANDLED;
}


static void
pdb_send_connection_status(int status, memory_t ring)
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
printk ("pdb ctrlif rx\n");

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

static int __init 
pdb_initialize(void)
{
    pdb_sring_t *sring;

    printk("----\npdb initialize   %s %s\n", __DATE__, __TIME__);

    /*
    if ( xen_start_info.flags & SIF_INITDOMAIN )
        return 1;
    */

    (void)ctrl_if_register_receiver(CMSG_DEBUG, pdb_ctrlif_rx,
                                    CALLBACK_IN_BLOCKING_CONTEXT);

    /* rings */
    sring = (pdb_sring_t *)__get_free_page(GFP_KERNEL);
    SHARED_RING_INIT(sring);
    BACK_RING_INIT(&pdb_ring, sring, PAGE_SIZE);
 
    /* notify pdb in dom 0 */
    pdb_send_connection_status(PDB_CONNECTION_STATUS_UP, 
                               virt_to_machine(pdb_ring.sring) >> PAGE_SHIFT);

    return 0;
}

static void __exit
pdb_terminate(void)
{
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

