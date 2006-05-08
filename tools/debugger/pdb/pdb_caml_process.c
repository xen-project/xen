/*
 * pdb_caml_process.c
 *
 * http://www.cl.cam.ac.uk/netos/pdb
 *
 * PDB's OCaml interface library for debugging processes
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>

#include <xenctrl.h>
#include <xen/xen.h>
#include <xen/io/domain_controller.h>
#include "pdb_module.h"
#include "pdb_caml_xen.h"

typedef struct
{
    int domain;
    int process;
    int evtchn;
    pdb_front_ring_t *ring;
} context_t;

#define decode_context(_ctx, _ocaml)   \
{  \
    (_ctx)->domain  = Int_val(Field((_ocaml),0));  \
    (_ctx)->process = Int_val(Field((_ocaml),1));  \
    (_ctx)->evtchn  = Int_val(Field((_ocaml),2));  \
    (_ctx)->ring    =  (pdb_front_ring_t *)Int32_val(Field((_ocaml),3));  \
}

#define encode_context(_ctx, _ocaml)  \
{  \
    (_ocaml) = caml_alloc_tuple(2);  \
    Store_field((_ocaml), 0, Val_int((_ctx)->domain));  \
    Store_field((_ocaml), 1, Val_int((_ctx)->process));  \
}

/*
 * send a request to a pdb domain backend.
 *
 * puts the request on a ring and kicks the backend using an event channel.
 */
static void
send_request (pdb_front_ring_t *pdb_ring, int evtchn, pdb_request_t *request)
{
    pdb_request_t    *req;

    req = RING_GET_REQUEST(pdb_ring, pdb_ring->req_prod_pvt);

    memcpy(req, request, sizeof(pdb_request_t));

    pdb_ring->req_prod_pvt++;

    RING_PUSH_REQUESTS(pdb_ring);
    xc_evtchn_send(xc_handle, evtchn);
}

/*
 * process_handle_response : int32 -> int * int * string
 *
 * A backend domain has notified pdb (via an event channel)
 * that a command has finished.
 * We read the result from the channel and formulate a response
 * as a single string.  Also return the domain and process.
 */

static inline unsigned int
_flip (unsigned int orig)
{
    return (((orig << 24) & 0xff000000) | ((orig <<  8) & 0x00ff0000) |
            ((orig >>  8) & 0x0000ff00) | ((orig >> 24) & 0x000000ff));
}

value
process_handle_response (value ring)
{
    CAMLparam1(ring);
    CAMLlocal2(result, str);

    RING_IDX rp;
    pdb_response_p resp;
    pdb_front_ring_t *my_ring = (pdb_front_ring_t *)Int32_val(ring);
    char msg[2048];
    int msglen;

    memset(msg, 0, sizeof(msg));

    rp = my_ring->sring->rsp_prod;
    rmb();                     /* Ensure we see queued responses up to 'rp'. */

    /* default response is OK unless the command has something 
       more interesting to say */
    sprintf(msg, "OK");

    if (my_ring->rsp_cons != rp)
    {
        resp = RING_GET_RESPONSE(my_ring, my_ring->rsp_cons);

        switch (resp->operation)
        {
        case PDB_OPCODE_PAUSE :
        case PDB_OPCODE_ATTACH :
        case PDB_OPCODE_DETACH :
            break;
            
        case PDB_OPCODE_RD_REG :
        {
            sprintf(&msg[0], "%08x", _flip(resp->u.rd_reg.value));
            break;
        }

        case PDB_OPCODE_RD_REGS :
        {
            int loop;
            pdb_op_rd_regs_p regs = &resp->u.rd_regs;
            
            for (loop = 0; loop < GDB_REGISTER_FRAME_SIZE * 8; loop += 8)
            {
                sprintf(&msg[loop], "%08x", _flip(regs->reg[loop >> 3]));
            }
                
            break;
        }
        case PDB_OPCODE_WR_REG :
        {
            /* should check the return status */
            break;
        }

        case PDB_OPCODE_RD_MEM :
        {
            int loop;
            pdb_op_rd_mem_resp_p mem = &resp->u.rd_mem;

            for (loop = 0; loop < mem->length; loop ++)
            {
                sprintf(&msg[loop * 2], "%02x", mem->data[loop]);
            }
            break;
        }
        case PDB_OPCODE_WR_MEM :
        {
            /* should check the return status */
            break;
        }

        /* this is equivalent to process_xen_virq */
        case PDB_OPCODE_CONTINUE :
        {
            sprintf(msg, "S05");
            break;
        }
        case PDB_OPCODE_STEP :
        {
            sprintf(msg, "S05");
            break;
        }

        case PDB_OPCODE_SET_BKPT :
        case PDB_OPCODE_CLR_BKPT :
        case PDB_OPCODE_SET_WATCHPT :
        case PDB_OPCODE_CLR_WATCHPT :
        {
            break;
        }

        case PDB_OPCODE_WATCHPOINT :
        {
            sprintf(msg, "S05");
            break;
        }

        default :
            printf("(linux) UNKNOWN MESSAGE TYPE IN RESPONSE %d\n",
                   resp->operation);
            break;
        }

        my_ring->rsp_cons++;
    }

    msglen = strlen(msg);
    result = caml_alloc(3,0);
    str = alloc_string(msglen);
    memmove(&Byte(str,0), msg, msglen);

    Store_field(result, 0, Val_int(resp->domain));
    Store_field(result, 1, Val_int(resp->process));
    Store_field(result, 2, str);

    CAMLreturn(result);
}

/*
 * proc_attach_debugger : context_t -> unit
 */
value
proc_attach_debugger (value context)
{
    CAMLparam1(context);
    context_t ctx;
    pdb_request_t req;

    decode_context(&ctx, context);

    req.operation = PDB_OPCODE_ATTACH;
    req.u.attach.domain  = ctx.domain;
    req.process = ctx.process;

    send_request (ctx.ring, ctx.evtchn, &req);

    CAMLreturn(Val_unit);
}


/*
 * proc_detach_debugger : context_t -> unit
 */
value
proc_detach_debugger (value context)
{
    CAMLparam1(context);
    context_t ctx;
    pdb_request_t req;

    decode_context(&ctx, context);

    printf("(pdb) detach process [%d.%d] %d %p\n", ctx.domain, ctx.process,
           ctx.evtchn, ctx.ring);
    fflush(stdout);

    req.operation = PDB_OPCODE_DETACH;
    req.process = ctx.process;

    send_request (ctx.ring, ctx.evtchn, &req);

    CAMLreturn(Val_unit);
}


/*
 * proc_pause_target : int -> unit
 */
value
proc_pause_target (value context)
{
    CAMLparam1(context);
    context_t ctx;
    pdb_request_t req;

    decode_context(&ctx, context);

    printf("(pdb) pause target %d %d\n", ctx.domain, ctx.process);
    fflush(stdout);

    req.operation = PDB_OPCODE_PAUSE;
    req.process = ctx.process;

    send_request (ctx.ring, ctx.evtchn, &req);

    CAMLreturn(Val_unit);
}


/*
 * proc_read_register : context_t -> int -> unit
 */
value
proc_read_register (value context, value reg)
{
    CAMLparam1(context);

    pdb_request_t req;
    context_t ctx;
    int my_reg = Int_val(reg);

    decode_context(&ctx, context);

    req.operation = PDB_OPCODE_RD_REG;
    req.process = ctx.process;
    req.u.rd_reg.reg = my_reg;
    req.u.rd_reg.value = 0;

    send_request (ctx.ring, ctx.evtchn, &req);

    CAMLreturn(Val_unit);
}



/*
 * proc_read_registers : context_t -> unit
 */
value
proc_read_registers (value context)
{
    CAMLparam1(context);

    pdb_request_t req;
    context_t ctx;

    decode_context(&ctx, context);

    req.operation = PDB_OPCODE_RD_REGS;
    req.process = ctx.process;

    send_request (ctx.ring, ctx.evtchn, &req);

    CAMLreturn(Val_unit);
}


/*
 * proc_write_register : context_t -> register -> int32 -> unit
 */
value
proc_write_register (value context, value reg, value newval)
{
    CAMLparam3(context, reg, newval);

    int my_reg = Int_val(reg);
    unsigned long my_newval = Int32_val(newval);

    context_t ctx;
    pdb_request_t req;

    decode_context(&ctx, context);

    req.operation = PDB_OPCODE_WR_REG;
    req.process = ctx.process;
    req.u.wr_reg.value = my_newval;

    switch (my_reg)
    {
    case GDB_EAX: req.u.wr_reg.reg = LINUX_EAX; break;
    case GDB_ECX: req.u.wr_reg.reg = LINUX_ECX; break;
    case GDB_EDX: req.u.wr_reg.reg = LINUX_EDX; break;
    case GDB_EBX: req.u.wr_reg.reg = LINUX_EBX; break;

    case GDB_ESP: req.u.wr_reg.reg = LINUX_ESP; break;
    case GDB_EBP: req.u.wr_reg.reg = LINUX_EBP; break;
    case GDB_ESI: req.u.wr_reg.reg = LINUX_ESI; break;
    case GDB_EDI: req.u.wr_reg.reg = LINUX_EDI; break;

    case GDB_EIP: req.u.wr_reg.reg = LINUX_EIP; break;
    case GDB_EFL: req.u.wr_reg.reg = LINUX_EFL; break;
 
    case GDB_CS:  req.u.wr_reg.reg = LINUX_CS; break;
    case GDB_SS:  req.u.wr_reg.reg = LINUX_SS; break;
    case GDB_DS:  req.u.wr_reg.reg = LINUX_DS; break;
    case GDB_ES:  req.u.wr_reg.reg = LINUX_ES; break;
    case GDB_FS:  req.u.wr_reg.reg = LINUX_FS; break;
    case GDB_GS:  req.u.wr_reg.reg = LINUX_GS; break;
    }

    send_request(ctx.ring, ctx.evtchn, &req);

    CAMLreturn(Val_unit);
}


/*
 * proc_read_memory : context_t -> int32 -> int -> unit
 */
value
proc_read_memory (value context, value address, value length)
{
    CAMLparam3(context, address, length);

    context_t ctx;
    pdb_request_t req;

    decode_context(&ctx, context);

    req.operation = PDB_OPCODE_RD_MEM;
    req.process = ctx.process;
    req.u.rd_mem.address = Int32_val(address);
    req.u.rd_mem.length  = Int_val(length);

    send_request(ctx.ring, ctx.evtchn, &req);
    
    CAMLreturn(Val_unit);
}


/*
 * proc_write_memory : context_t -> int32 -> int list -> unit
 */
value
proc_write_memory (value context, value address, value val_list)
{
    CAMLparam3(context, address, val_list);
    CAMLlocal1(node);

    context_t ctx;
    pdb_request_t req;
    uint32_t length = 0;

    decode_context(&ctx, context);

    req.operation = PDB_OPCODE_WR_MEM;
    req.process = ctx.process;

    node = val_list;
    if ( Int_val(node) == 0 )       /* gdb functionalty test uses empty list */
    {
        req.u.wr_mem.address = Int32_val(address);
        req.u.wr_mem.length  = 0;
    }
    else
    {
        while ( Int_val(Field(node,1)) != 0 )
        {
            req.u.wr_mem.data[length++] = Int_val(Field(node, 0));
            node = Field(node,1);
        }
        req.u.wr_mem.data[length++] = Int_val(Field(node, 0));
        
        req.u.wr_mem.address = Int32_val(address);
        req.u.wr_mem.length  = length;
    }
 
    send_request(ctx.ring, ctx.evtchn, &req);
   
    CAMLreturn(Val_unit);
}


/*
 * proc_continue_target : context_t -> unit
 */
value
proc_continue_target (value context)
{
    CAMLparam1(context);

    context_t ctx;
    pdb_request_t req;

    decode_context(&ctx, context);

    req.operation = PDB_OPCODE_CONTINUE;
    req.process = ctx.process;
 
    send_request(ctx.ring, ctx.evtchn, &req);

    CAMLreturn(Val_unit);
}

/*
 * proc_step_target : context_t -> unit
 */
value
proc_step_target (value context)
{
    CAMLparam1(context);

    context_t ctx;
    pdb_request_t req;

    decode_context(&ctx, context);

    req.operation = PDB_OPCODE_STEP;
    req.process = ctx.process;
 
    send_request(ctx.ring, ctx.evtchn, &req);

    CAMLreturn(Val_unit);
}



/*
 * proc_insert_memory_breakpoint : context_t -> int32 -> int -> unit
 */
value
proc_insert_memory_breakpoint (value context, value address, value length)
{
    CAMLparam3(context, address, length);

    context_t ctx;
    pdb_request_t req;

    decode_context(&ctx, context);

    req.operation = PDB_OPCODE_SET_BKPT;
    req.process = ctx.process;
    req.u.bkpt.address = (unsigned long) Int32_val(address);
    req.u.bkpt.length  =  Int_val(length);

    send_request(ctx.ring, ctx.evtchn, &req);

    CAMLreturn(Val_unit);
}

/*
 * proc_remove_memory_breakpoint : context_t -> int32 -> int -> unit
 */
value
proc_remove_memory_breakpoint (value context, value address, value length)
{
    CAMLparam3(context, address, length);

    context_t ctx;
    pdb_request_t req;

    decode_context(&ctx, context);

    req.operation = PDB_OPCODE_CLR_BKPT;
    req.process = ctx.process;
    req.u.bkpt.address = (unsigned long) Int32_val(address);
    req.u.bkpt.length  =  Int_val(length);

    send_request(ctx.ring, ctx.evtchn, &req);

    CAMLreturn(Val_unit);
}

/*
 * proc_insert_watchpoint : context_t -> bwcpoint_t -> int32 -> int -> unit
 */
value
proc_insert_watchpoint (value context, value kind, value address, value length)
{
    CAMLparam3(context, address, length);

    context_t ctx;
    pdb_request_t req;

    decode_context(&ctx, context);

    req.operation = PDB_OPCODE_SET_WATCHPT;
    req.process = ctx.process;
    req.u.watchpt.type    =  Int_val(kind);
    req.u.watchpt.address = (unsigned long) Int32_val(address);
    req.u.watchpt.length  =  Int_val(length);

    send_request(ctx.ring, ctx.evtchn, &req);

    CAMLreturn(Val_unit);
}

/*
 * proc_remove_watchpoint : context_t -> bwcpoint_t -> int32 -> int -> unit
 */
value
proc_remove_watchpoint (value context, value kind, value address, value length)
{
    CAMLparam3(context, address, length);

    context_t ctx;
    pdb_request_t req;

    decode_context(&ctx, context);

    req.operation = PDB_OPCODE_CLR_WATCHPT;
    req.process = ctx.process;
    req.u.watchpt.type    =  Int_val(kind);
    req.u.watchpt.address = (unsigned long) Int32_val(address);
    req.u.watchpt.length  =  Int_val(length);

    send_request(ctx.ring, ctx.evtchn, &req);

    CAMLreturn(Val_unit);
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */


