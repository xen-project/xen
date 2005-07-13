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

#include <xc.h>
#include <xen/xen.h>
#include <xen/io/domain_controller.h>
#include <xen/linux/privcmd.h>
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
 * read a response from a pdb domain backend.
 *
 * grabs the response off a ring.
 */
static void
read_response (pdb_front_ring_t *pdb_ring, pdb_response_p response)
{
    RING_IDX loop, rp;

    rp = pdb_ring->sring->rsp_prod;
    rmb(); /* Ensure we see queued responses up to 'rp'. */

    for ( loop = pdb_ring->rsp_cons; loop != rp; loop++ )
    {
        pdb_response_p resp;

        resp = RING_GET_RESPONSE(pdb_ring, loop);
        memcpy(response, resp, sizeof(pdb_response_t));

        /*        
        printf ("got response %x %x %x\n", response->operation, 
                response->status, response->value);
        */
    }
    pdb_ring->rsp_cons = loop;
}

/*
 * process_handle_response : int32 -> unit
 */

value
process_handle_response (value ring)
{
    CAMLparam1(ring);

    pdb_front_ring_t *my_ring = (pdb_front_ring_t *)Int32_val(ring);
    pdb_response_t resp;

    if ( my_ring )
        read_response(my_ring, &resp);

    CAMLreturn(Val_unit);
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
    pdb_response_t resp;

    decode_context(&ctx, context);

    printf("(pdb) attach process [%d.%d] %d %p\n", ctx.domain, ctx.process,
           ctx.evtchn, ctx.ring);
    fflush(stdout);

    req.operation = PDB_OPCODE_ATTACH;
    req.domain  = ctx.domain;
    req.process = ctx.process;

    send_request (ctx.ring, ctx.evtchn, &req);

    printf("awaiting response\n");
    fflush(stdout);

    read_response (ctx.ring, &resp);

    printf("response %d %d\n", resp.operation, resp.status);
    fflush(stdout);

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
    req.domain  = ctx.domain;
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

    decode_context(&ctx, context);

    printf("(pdb) pause target %d %d\n", ctx.domain, ctx.process);
    fflush(stdout);

    CAMLreturn(Val_unit);
}


/*
 * proc_read_registers : context_t -> int32
 */
value
proc_read_registers (value context)
{
    CAMLparam1(context);
    CAMLlocal1(result);

    u32 regs[REGISTER_FRAME_SIZE];

    pdb_request_t req;
    context_t ctx;
    int loop;

    decode_context(&ctx, context);

    req.operation = PDB_OPCODE_RD_REG;
    req.domain  = ctx.domain;
    req.process = ctx.process;

    for (loop = 0; loop < REGISTER_FRAME_SIZE; loop++)
    {
        pdb_response_t resp;

        req.u.rd_reg.reg = loop;
        send_request(ctx.ring, ctx.evtchn, &req);
        read_response(ctx.ring, &resp);
        regs[loop] = resp.value;
    }

    result = caml_alloc_tuple(16);

    Store_field(result,  0, caml_copy_int32(regs[LINUX_EAX]));
    Store_field(result,  1, caml_copy_int32(regs[LINUX_ECX]));
    Store_field(result,  2, caml_copy_int32(regs[LINUX_EDX]));
    Store_field(result,  3, caml_copy_int32(regs[LINUX_EBX]));
    Store_field(result,  4, caml_copy_int32(regs[LINUX_ESP]));
    Store_field(result,  5, caml_copy_int32(regs[LINUX_EBP]));
    Store_field(result,  6, caml_copy_int32(regs[LINUX_ESI]));
    Store_field(result,  7, caml_copy_int32(regs[LINUX_EDI]));
    Store_field(result,  8, caml_copy_int32(regs[LINUX_EIP]));
    Store_field(result,  9, caml_copy_int32(regs[LINUX_EFL]));
    Store_field(result, 10, caml_copy_int32(regs[LINUX_CS]));          /* 16 */
    Store_field(result, 11, caml_copy_int32(regs[LINUX_SS]));          /* 16 */
    Store_field(result, 12, caml_copy_int32(regs[LINUX_DS]));          /* 16 */
    Store_field(result, 13, caml_copy_int32(regs[LINUX_ES]));          /* 16 */
    Store_field(result, 14, caml_copy_int32(regs[LINUX_FS]));          /* 16 */
    Store_field(result, 15, caml_copy_int32(regs[LINUX_GS]));          /* 16 */

    CAMLreturn(result);
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
    pdb_response_t resp;

    decode_context(&ctx, context);

    req.operation = PDB_OPCODE_WR_REG;
    req.domain = ctx.domain;
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
    read_response(ctx.ring, &resp);

    CAMLreturn(Val_unit);
}


/*
 * proc_read_memory : context_t -> int32 -> int -> int
 */
value
proc_read_memory (value context, value address, value length)
{
    CAMLparam3(context, address, length);
    CAMLlocal2(result, temp);

    context_t ctx;
    int loop;
    char *buffer;
    /*    memory_t my_address = Int32_val(address); */
    u32 my_length = Int_val(length);

    printf ("(pdb) read memory\n");

    decode_context(&ctx, context);

    buffer = malloc(my_length);
    if ( buffer == NULL )
    {
        printf("(pdb) read memory: malloc failed.\n");  fflush(stdout);
        failwith("read memory error");
    }

    /*
    if ( xendebug_read_memory(xc_handle, ctx.domain, ctx.vcpu, 
                              my_address, my_length, buffer) )
    {
        printf("(pdb) read memory error!\n");  fflush(stdout);
        failwith("read memory error");
    }
    */

    memset(buffer, 0xff, my_length);

    result = caml_alloc(2,0);
    if ( my_length > 0 )                                              /* car */
    {
        Store_field(result, 0, Val_int(buffer[my_length - 1] & 0xff));
    }
    else

    {
        Store_field(result, 0, Val_int(0));                    
    }
    Store_field(result, 1, Val_int(0));                               /* cdr */

    for (loop = 1; loop < my_length; loop++)
    {
        temp = result;
        result = caml_alloc(2,0);
        Store_field(result, 0, Val_int(buffer[my_length - loop - 1] & 0xff));
        Store_field(result, 1, temp);
    }

    CAMLreturn(result);
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

    char buffer[4096];  /* a big buffer */
    memory_t  my_address;
    u32 length = 0;

    printf ("(pdb) write memory\n");

    decode_context(&ctx, context);

    node = val_list;
    if ( Int_val(node) == 0 )       /* gdb functionalty test uses empty list */
    {
        CAMLreturn(Val_unit);
    }

    while ( Int_val(Field(node,1)) != 0 )
    {
        buffer[length++] = Int_val(Field(node, 0));
        node = Field(node,1);
    }
    buffer[length++] = Int_val(Field(node, 0));

    my_address = (memory_t) Int32_val(address);

    /*
    if ( xendebug_write_memory(xc_handle, ctx.domain, ctx.vcpu,
                               my_address, length, buffer) )
    {
        printf("(pdb) write memory error!\n");  fflush(stdout);
        failwith("write memory error");
    }
    */
    {
        int loop;
        for (loop = 0; loop < length; loop++)
        {
            printf (" %02x", buffer[loop]);
        }
        printf ("\n");
    }

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

    decode_context(&ctx, context);

    /*
    if ( xendebug_continue(xc_handle, ctx.domain, ctx.vcpu) )
    {
        printf("(pdb) continue\n");  fflush(stdout);
        failwith("continue");
    }
    */
    printf ("CONTINUE\n");

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

    decode_context(&ctx, context);

    /*
    if ( xendebug_step(xc_handle, ctx.domain, ctx.vcpu) )
    {
        printf("(pdb) step\n");  fflush(stdout);
        failwith("step");
    }
    */
    printf ("STEP\n");

    CAMLreturn(Val_unit);
}



/*
 * proc_insert_memory_breakpoint : context_t -> int32 -> int list -> unit
 */
value
proc_insert_memory_breakpoint (value context, value address, value length)
{
    CAMLparam3(context, address, length);

    context_t ctx;
    memory_t my_address = (memory_t) Int32_val(address);
    int my_length = Int_val(length);

    decode_context(&ctx, context);

    printf ("(pdb) insert memory breakpoint 0x%lx %d\n",
            my_address, my_length);

    /*
    if ( xendebug_insert_memory_breakpoint(xc_handle, ctx.domain, ctx.vcpu,
                                           my_address, my_length) )
    {
        printf("(pdb) error: insert memory breakpoint\n");  fflush(stdout);
        failwith("insert memory breakpoint");
    }
    */

    CAMLreturn(Val_unit);
}

/*
 * proc_remove_memory_breakpoint : context_t -> int32 -> int list -> unit
 */
value
proc_remove_memory_breakpoint (value context, value address, value length)
{
    CAMLparam3(context, address, length);

    context_t ctx;

    memory_t my_address = (memory_t) Int32_val(address);
    int my_length = Int_val(length);

    printf ("(pdb) remove memory breakpoint 0x%lx %d\n",
            my_address, my_length);

    decode_context(&ctx, context);

    /*
    if ( xendebug_remove_memory_breakpoint(xc_handle, 
                                           ctx.domain, ctx.vcpu,
                                           my_address, my_length) )
    {
        printf("(pdb) error: remove memory breakpoint\n");  fflush(stdout);
        failwith("remove memory breakpoint");
    }
    */

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


