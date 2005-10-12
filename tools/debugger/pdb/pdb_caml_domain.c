/*
 * pdb_caml_xc.c
 *
 * http://www.cl.cam.ac.uk/netos/pdb
 *
 * PDB's OCaml interface library for debugging domains
 */

#include <xenctrl.h>
#include <xendebug.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>

#include "pdb_caml_xen.h"

typedef struct
{
    int domain;
    int vcpu;
} context_t;

#define decode_context(_ctx, _ocaml)   \
{  \
    (_ctx)->domain = Int_val(Field((_ocaml),0));  \
    (_ctx)->vcpu = Int_val(Field((_ocaml),1));  \
}

#define encode_context(_ctx, _ocaml)  \
{  \
    (_ocaml) = caml_alloc_tuple(2);  \
    Store_field((_ocaml), 0, Val_int((_ctx)->domain));  \
    Store_field((_ocaml), 1, Val_int((_ctx)->vcpu));  \
}


/****************************************************************************/

/*
 * dom_read_register : context_t -> int -> int32
 */
value
dom_read_register (value context, value reg)
{
    CAMLparam2(context, reg);
    CAMLlocal1(result);

    int my_reg = Int_val(reg);
    cpu_user_regs_t *regs;
    context_t ctx;

    decode_context(&ctx, context);

    if ( xendebug_read_registers(xc_handle, ctx.domain, ctx.vcpu, &regs) )
    {
        printf("(pdb) read registers error!\n");  fflush(stdout);
        failwith("read registers error");
    }

    dump_regs(regs);

    result = caml_alloc_tuple(16);

    switch (my_reg)
    {
    case GDB_EAX: result = caml_copy_int32(regs->eax); break;
    case GDB_ECX: result = caml_copy_int32(regs->ecx); break;
    case GDB_EDX: result = caml_copy_int32(regs->edx); break;
    case GDB_EBX: result = caml_copy_int32(regs->ebx); break;
    case GDB_ESP: result = caml_copy_int32(regs->esp); break;
    case GDB_EBP: result = caml_copy_int32(regs->ebp); break;
    case GDB_ESI: result = caml_copy_int32(regs->esi); break;
    case GDB_EDI: result = caml_copy_int32(regs->edi); break;
    case GDB_EIP: result = caml_copy_int32(regs->eip); break;
    case GDB_EFL: result = caml_copy_int32(regs->eflags); break;
    case GDB_CS:  result = caml_copy_int32(regs->cs);  break;
    case GDB_SS: result = caml_copy_int32(regs->ss); break;
    case GDB_DS: result = caml_copy_int32(regs->ds); break;
    case GDB_ES: result = caml_copy_int32(regs->es); break;
    case GDB_FS: result = caml_copy_int32(regs->fs); break;
    case GDB_GS: result = caml_copy_int32(regs->gs); break;
    }

    CAMLreturn(result);
}

/*
 * dom_read_registers : context_t -> int32
 */
value
dom_read_registers (value context)
{
    CAMLparam1(context);
    CAMLlocal1(result);

    cpu_user_regs_t *regs;
    context_t ctx;

    decode_context(&ctx, context);

    if ( xendebug_read_registers(xc_handle, ctx.domain, ctx.vcpu, &regs) )
    {
        printf("(pdb) read registers error!\n");  fflush(stdout);
        failwith("read registers error");
    }

    dump_regs(regs);

    result = caml_alloc_tuple(16);

    Store_field(result,  0, caml_copy_int32(regs->eax));
    Store_field(result,  1, caml_copy_int32(regs->ecx));
    Store_field(result,  2, caml_copy_int32(regs->edx));
    Store_field(result,  3, caml_copy_int32(regs->ebx));
    Store_field(result,  4, caml_copy_int32(regs->esp));
    Store_field(result,  5, caml_copy_int32(regs->ebp));
    Store_field(result,  6, caml_copy_int32(regs->esi));
    Store_field(result,  7, caml_copy_int32(regs->edi));
    Store_field(result,  8, caml_copy_int32(regs->eip));
    Store_field(result,  9, caml_copy_int32(regs->eflags));
    Store_field(result, 10, caml_copy_int32(regs->cs));                /* 16 */
    Store_field(result, 11, caml_copy_int32(regs->ss));                /* 16 */
    Store_field(result, 12, caml_copy_int32(regs->ds));                /* 16 */
    Store_field(result, 13, caml_copy_int32(regs->es));                /* 16 */
    Store_field(result, 14, caml_copy_int32(regs->fs));                /* 16 */
    Store_field(result, 15, caml_copy_int32(regs->gs));                /* 16 */

    CAMLreturn(result);
}


/*
 * dom_write_register : context_t -> register -> int32 -> unit
 */
value
dom_write_register (value context, value reg, value newval)
{
    CAMLparam3(context, reg, newval);

    int my_reg = Int_val(reg);
    int val = Int32_val(newval);

    context_t ctx;
    cpu_user_regs_t *regs;

    printf("(pdb) write register\n");

    decode_context(&ctx, context);

    if ( xendebug_read_registers(xc_handle, ctx.domain, ctx.vcpu, &regs) )
    {
        printf("(pdb) write register (get) error!\n");  fflush(stdout);
        failwith("write register error");
    }

    switch (my_reg)
    {
    case GDB_EAX: regs->eax = val; break;
    case GDB_ECX: regs->ecx = val; break;
    case GDB_EDX: regs->edx = val; break;
    case GDB_EBX: regs->ebx = val; break;

    case GDB_ESP: regs->esp = val; break;
    case GDB_EBP: regs->ebp = val; break;
    case GDB_ESI: regs->esi = val; break;
    case GDB_EDI: regs->edi = val; break;
 
    case GDB_EIP: regs->eip = val; break;
    case GDB_EFL: regs->eflags = val; break;

    case GDB_CS:  regs->cs  = val; break;
    case GDB_SS:  regs->ss  = val; break;
    case GDB_DS:  regs->ds  = val; break;
    case GDB_ES:  regs->es  = val; break;
    case GDB_FS:  regs->fs  = val; break;
    case GDB_GS:  regs->gs  = val; break;
    }

    if ( xendebug_write_registers(xc_handle, ctx.domain, ctx.vcpu, regs) )
    {
        printf("(pdb) write register (set) error!\n");  fflush(stdout);
        failwith("write register error");
    }

    CAMLreturn(Val_unit);
}

/*
 * dom_read_memory : context_t -> int32 -> int -> int
 */
value
dom_read_memory (value context, value address, value length)
{
    CAMLparam3(context, address, length);
    CAMLlocal2(result, temp);

    context_t ctx;
    int loop;
    char *buffer;
    unsigned long my_address = Int32_val(address);
    uint32_t my_length = Int_val(length);

    printf ("(pdb) read memory\n");

    decode_context(&ctx, context);

    buffer = malloc(my_length);
    if ( buffer == NULL )
    {
        printf("(pdb) read memory: malloc failed.\n");  fflush(stdout);
        failwith("read memory error");
    }

    if ( xendebug_read_memory(xc_handle, ctx.domain, ctx.vcpu, 
                              my_address, my_length, buffer) )
    {
        printf("(pdb) read memory error!\n");  fflush(stdout);
        failwith("read memory error");
    }

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
 * dom_write_memory : context_t -> int32 -> int list -> unit
 */
value
dom_write_memory (value context, value address, value val_list)
{
    CAMLparam3(context, address, val_list);
    CAMLlocal1(node);

    context_t ctx;

    char buffer[4096];  /* a big buffer */
    unsigned long  my_address;
    uint32_t length = 0;

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

    my_address = (unsigned long) Int32_val(address);

    if ( xendebug_write_memory(xc_handle, ctx.domain, ctx.vcpu,
                               my_address, length, buffer) )
    {
        printf("(pdb) write memory error!\n");  fflush(stdout);
        failwith("write memory error");
    }

    CAMLreturn(Val_unit);
}

/*
 * dom_continue_target : context_t -> unit
 */
value
dom_continue_target (value context)
{
    CAMLparam1(context);

    context_t ctx;

    decode_context(&ctx, context);

    if ( xendebug_continue(xc_handle, ctx.domain, ctx.vcpu) )
    {
        printf("(pdb) continue\n");  fflush(stdout);
        failwith("continue");
    }

    CAMLreturn(Val_unit);
}

/*
 * dom_step_target : context_t -> unit
 */
value
dom_step_target (value context)
{
    CAMLparam1(context);

    context_t ctx;

    decode_context(&ctx, context);

    if ( xendebug_step(xc_handle, ctx.domain, ctx.vcpu) )
    {
        printf("(pdb) step\n");  fflush(stdout);
        failwith("step");
    }

    CAMLreturn(Val_unit);
}



/*
 * dom_insert_memory_breakpoint : context_t -> int32 -> int list -> unit
 */
value
dom_insert_memory_breakpoint (value context, value address, value length)
{
    CAMLparam3(context, address, length);

    context_t ctx;
    unsigned long my_address = (unsigned long) Int32_val(address);
    int my_length = Int_val(length);

    decode_context(&ctx, context);

    printf ("(pdb) insert memory breakpoint 0x%lx %d\n",
            my_address, my_length);

    if ( xendebug_insert_memory_breakpoint(xc_handle, ctx.domain, ctx.vcpu,
                                           my_address, my_length) )
    {
        printf("(pdb) error: insert memory breakpoint\n");  fflush(stdout);
        failwith("insert memory breakpoint");
    }


    CAMLreturn(Val_unit);
}

/*
 * dom_remove_memory_breakpoint : context_t -> int32 -> int list -> unit
 */
value
dom_remove_memory_breakpoint (value context, value address, value length)
{
    CAMLparam3(context, address, length);

    context_t ctx;

    unsigned long my_address = (unsigned long) Int32_val(address);
    int my_length = Int_val(length);

    printf ("(pdb) remove memory breakpoint 0x%lx %d\n",
            my_address, my_length);

    decode_context(&ctx, context);

    if ( xendebug_remove_memory_breakpoint(xc_handle, 
                                           ctx.domain, ctx.vcpu,
                                           my_address, my_length) )
    {
        printf("(pdb) error: remove memory breakpoint\n");  fflush(stdout);
        failwith("remove memory breakpoint");
    }

    CAMLreturn(Val_unit);
}

/*
 * dom_attach_debugger : int -> int -> unit
 */
value
dom_attach_debugger (value domain, value vcpu)
{
    CAMLparam2(domain, vcpu);

    int my_domain = Int_val(domain);
    int my_vcpu = Int_val(vcpu);

    printf ("(pdb) attach domain [%d.%d]\n", my_domain, my_vcpu);

    if ( xendebug_attach(xc_handle, my_domain, my_vcpu) )
    {
        printf("(pdb) attach error!\n");  fflush(stdout);
        failwith("attach error");
    }

    CAMLreturn(Val_unit);
}


/*
 * dom_detach_debugger : int -> int -> unit
 */
value
dom_detach_debugger (value domain, value vcpu)
{
    CAMLparam2(domain, vcpu);

    int my_domain = Int_val(domain);
    int my_vcpu = Int_val(vcpu);

    printf ("(pdb) detach domain [%d.%d]\n", my_domain, my_vcpu);

    if ( xendebug_detach(xc_handle, my_domain, my_vcpu) )
    {
        printf("(pdb) detach error!\n");  fflush(stdout);
        failwith("detach error");
    }

    CAMLreturn(Val_unit);
}


/*
 * dom_pause_target : int -> unit
 */
value
dom_pause_target (value domid)
{
    CAMLparam1(domid);

    int my_domid = Int_val(domid);

    printf ("(pdb) pause target %d\n", my_domid);

    xc_domain_pause(xc_handle, my_domid);

    CAMLreturn(Val_unit);
}

/****************************************************************************/
/****************************************************************************/

/*
 * query_domain_stop : unit -> (int * int) list
 */
value
query_domain_stop (value unit)
{
    CAMLparam1(unit);
    CAMLlocal3(result, temp, node);

    int max_domains = 20;
    int dom_list[max_domains];
    int loop, count;

    count = xendebug_query_domain_stop(xc_handle, dom_list, max_domains);
    if ( count < 0 )
    {
        printf("(pdb) query domain stop!\n");  fflush(stdout);
        failwith("query domain stop");
    }

    printf ("QDS [%d]: \n", count);
    for (loop = 0; loop < count; loop ++)
        printf (" %d", dom_list[loop]);
    printf ("\n");

    result = caml_alloc(2,0);
    if ( count > 0 )                                                  /* car */
    {
        node = caml_alloc(2,0);
        Store_field(node, 0, Val_int(dom_list[0]));             /* domain id */
        Store_field(node, 1, Val_int(0));                            /* vcpu */
        Store_field(result, 0, node);
    }
    else
    {
        Store_field(result, 0, Val_int(0));                    
    }
    Store_field(result, 1, Val_int(0));                               /* cdr */

    for ( loop = 1; loop < count; loop++ )
    {
        temp = result;
        result = caml_alloc(2,0);
        node = caml_alloc(2,0);
        Store_field(node, 0, Val_int(dom_list[loop]));          /* domain id */
        Store_field(node, 1, Val_int(0));                            /* vcpu */
        Store_field(result, 0, node);
        Store_field(result, 1, temp);
    }

    CAMLreturn(result);
}

/****************************************************************************/



/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

