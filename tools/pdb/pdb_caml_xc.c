/*
 * pdb_caml_xc.c
 *
 * http://www.cl.cam.ac.uk/netos/pdb
 *
 * OCaml to libxc interface library for PDB
 */

#include <xc.h>
#include <xc_debug.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>

int pdb_evtchn_bind_virq (int xc_handle, int virq, int *port);
int xen_evtchn_bind (int evtchn_fd, int idx);
int xen_evtchn_unbind (int evtchn_fd, int idx);

/* this order comes from xen/include/public/arch-x86_32.h */
enum x86_registers { PDB_EBX, PDB_ECX, PDB_EDX, PDB_ESI, PDB_EDI,
                     PDB_EBP, PDB_EAX, PDB_Error_code, PDB_Entry_vector, 
                     PDB_EIP, PDB_CS, PDB_EFLAGS, PDB_ESP, PDB_SS,
                     PDB_ES, PDB_DS, PDB_FS, PDB_GS };

static void dump_regs (cpu_user_regs_t *ctx);

static int xc_handle = -1;

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
 * open_context : unit -> unit
 */
value
open_context (value unit)
{
    CAMLparam1(unit);

    xc_handle = xc_interface_open();

    if ( xc_handle < 0 )
    {
        fprintf(stderr, "(pdb) error opening xc interface: %d (%s)\n",
                errno, strerror(errno));
    }

    CAMLreturn(Val_unit);
}

/*
 * close_context : unit -> unit
 */
value
close_context (value unit)
{
    CAMLparam1(unit);
    int rc;
    
    if ( (rc = xc_interface_close(xc_handle)) < 0 )
    {
        fprintf(stderr, "(pdb) error closing xc interface: %d (%s)\n",
                errno, strerror(errno));
    }

    CAMLreturn(Val_unit);
}

/*
 * read_registers : context_t -> int32
 */
value
read_registers (value context)
{
    CAMLparam1(context);
    CAMLlocal1(result);

    cpu_user_regs_t *regs;
    context_t ctx;

    decode_context(&ctx, context);

    if ( xc_debug_read_registers(xc_handle, ctx.domain, ctx.vcpu, &regs) )
    {
        printf("(pdb) read registers error!\n");  fflush(stdout);
        failwith("read registers error");
    }

    dump_regs(regs);

    result = caml_alloc_tuple(18);                                  /* FIXME */

    Store_field(result,  0, caml_copy_int32(regs->ebx));
    Store_field(result,  1, caml_copy_int32(regs->ecx));
    Store_field(result,  2, caml_copy_int32(regs->edx));
    Store_field(result,  3, caml_copy_int32(regs->esi));
    Store_field(result,  4, caml_copy_int32(regs->edi));
    Store_field(result,  5, caml_copy_int32(regs->ebp));
    Store_field(result,  6, caml_copy_int32(regs->eax));
    Store_field(result,  7, caml_copy_int32(regs->error_code));        /* 16 */
    Store_field(result,  8, caml_copy_int32(regs->entry_vector));      /* 16 */
    Store_field(result,  9, caml_copy_int32(regs->eip));
    Store_field(result, 10, caml_copy_int32(regs->cs));                /* 16 */
    Store_field(result, 11, caml_copy_int32(regs->eflags));
    Store_field(result, 12, caml_copy_int32(regs->esp));
    Store_field(result, 13, caml_copy_int32(regs->ss));                /* 16 */
    Store_field(result, 14, caml_copy_int32(regs->es));                /* 16 */
    Store_field(result, 15, caml_copy_int32(regs->ds));                /* 16 */
    Store_field(result, 16, caml_copy_int32(regs->fs));                /* 16 */
    Store_field(result, 17, caml_copy_int32(regs->gs));                /* 16 */

    CAMLreturn(result);
}


/*
 * write_register : context_t -> register -> int32 -> unit
 */
value
write_register (value context, value reg, value newval)
{
    CAMLparam3(context, reg, newval);

    int my_reg = Int_val(reg);
    int val = Int32_val(newval);

    context_t ctx;
    cpu_user_regs_t *regs;

    printf("(pdb) write register\n");

    decode_context(&ctx, context);

    if ( xc_debug_read_registers(xc_handle, ctx.domain, ctx.vcpu, &regs) )
    {
        printf("(pdb) write register (get) error!\n");  fflush(stdout);
        failwith("write register error");
    }

    switch (my_reg)
    {
    case PDB_EBX: regs->ebx = val; break;
    case PDB_ECX: regs->ecx = val; break;
    case PDB_EDX: regs->edx = val; break;
    case PDB_ESI: regs->esi = val; break;
    case PDB_EDI: regs->edi = val; break;

    case PDB_EBP: regs->ebp = val; break;
    case PDB_EAX: regs->eax = val; break;
    case PDB_Error_code: regs->error_code = val; break;
    case PDB_Entry_vector: regs->entry_vector = val; break;
 
    case PDB_EIP: regs->eip = val; break;
    case PDB_CS:  regs->cs  = val; break;
    case PDB_EFLAGS: regs->eflags = val; break;
    case PDB_ESP: regs->esp = val; break;
    case PDB_SS:  regs->ss  = val; break;
    case PDB_ES:  regs->es  = val; break;
    case PDB_DS:  regs->ds  = val; break;
    case PDB_FS:  regs->fs  = val; break;
    case PDB_GS:  regs->gs  = val; break;
    }

    if ( xc_debug_write_registers(xc_handle, ctx.domain, ctx.vcpu, regs) )
    {
        printf("(pdb) write register (set) error!\n");  fflush(stdout);
        failwith("write register error");
    }

    CAMLreturn(Val_unit);
}

/*
 * read_memory : context_t -> int32 -> int -> int
 */
value
read_memory (value context, value address, value length)
{
    CAMLparam3(context, address, length);
    CAMLlocal2(result, temp);

    context_t ctx;
    int loop;
    char *buffer;
    memory_t my_address = Int32_val(address);
    u32 my_length = Int_val(length);

    printf ("(pdb) read memory\n");

    decode_context(&ctx, context);

    buffer = malloc(my_length);
    if (buffer == NULL)
    {
        printf("(pdb) read memory: malloc failed.\n");  fflush(stdout);
        failwith("read memory error");
    }

    if ( xc_debug_read_memory(xc_handle, ctx.domain, ctx.vcpu, 
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
 * write_memory : context_t -> int32 -> int list -> unit
 */
value
write_memory (value context, value address, value val_list)
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

    if ( xc_debug_write_memory(xc_handle, ctx.domain, ctx.vcpu,
                               my_address, length, buffer) )
    {
        printf("(pdb) write memory error!\n");  fflush(stdout);
        failwith("write memory error");
    }

    CAMLreturn(Val_unit);
}


/*********************************************************************/

void
dump_regs (cpu_user_regs_t *regs)
{
    printf ("   eax: %x\n", regs->eax);
    printf ("   ecx: %x\n", regs->ecx);
    printf ("   edx: %x\n", regs->edx);
    printf ("   ebx: %x\n", regs->ebx);
    printf ("   esp: %x\n", regs->esp);
    printf ("   ebp: %x\n", regs->ebp);
    printf ("   esi: %x\n", regs->esi);
    printf ("   edi: %x\n", regs->edi);
    printf ("   eip: %x\n", regs->eip);
    printf (" flags: %x\n", regs->eflags);
    printf ("    cs: %x\n", regs->cs);
    printf ("    ss: %x\n", regs->ss);
    printf ("    es: %x\n", regs->es);
    printf ("    ds: %x\n", regs->ds);
    printf ("    fs: %x\n", regs->fs);
    printf ("    gs: %x\n", regs->gs);

    return;
}

/*
 * continue_target : context_t -> unit
 */
value
continue_target (value context)
{
    CAMLparam1(context);

    context_t ctx;

    decode_context(&ctx, context);

    if ( xc_debug_continue(xc_handle, ctx.domain, ctx.vcpu) )
    {
        printf("(pdb) continue\n");  fflush(stdout);
        failwith("continue");
    }

    CAMLreturn(Val_unit);
}

/*
 * step_target : context_t -> unit
 */
value
step_target (value context)
{
    CAMLparam1(context);

    context_t ctx;

    decode_context(&ctx, context);

    if ( xc_debug_step(xc_handle, ctx.domain, ctx.vcpu) )
    {
        printf("(pdb) step\n");  fflush(stdout);
        failwith("step");
    }

    CAMLreturn(Val_unit);
}



/*
 * insert_memory_breakpoint : context_t -> int32 -> int list -> unit
 */
value
insert_memory_breakpoint (value context, value address, value length)
{
    CAMLparam3(context, address, length);

    context_t ctx;
    memory_t my_address = (memory_t) Int32_val(address);
    int my_length = Int_val(length);

    decode_context(&ctx, context);

    printf ("(pdb) insert memory breakpoint 0x%lx %d\n",
            my_address, my_length);

    if ( xc_debug_insert_memory_breakpoint(xc_handle, ctx.domain, ctx.vcpu,
                                           my_address, my_length) )
    {
        printf("(pdb) error: insert memory breakpoint\n");  fflush(stdout);
        failwith("insert memory breakpoint");
    }


    CAMLreturn(Val_unit);
}

/*
 * remove_memory_breakpoint : context_t -> int32 -> int list -> unit
 */
value
remove_memory_breakpoint (value context, value address, value length)
{
    CAMLparam3(context, address, length);

    context_t ctx;

    memory_t my_address = (memory_t) Int32_val(address);
    int my_length = Int_val(length);

    printf ("(pdb) remove memory breakpoint 0x%lx %d\n",
            my_address, my_length);

    decode_context(&ctx, context);

    if ( xc_debug_remove_memory_breakpoint(xc_handle, 
                                           ctx.domain, ctx.vcpu,
                                           my_address, my_length) )
    {
        printf("(pdb) error: remove memory breakpoint\n");  fflush(stdout);
        failwith("remove memory breakpoint");
    }

    CAMLreturn(Val_unit);
}

/*
 * attach_debugger : int -> int -> unit
 */
value
attach_debugger (value domain, value vcpu)
{
    CAMLparam2(domain, vcpu);

    int my_domain = Int_val(domain);
    int my_vcpu = Int_val(vcpu);

    printf ("(pdb) attach domain [%d.%d]\n", my_domain, my_vcpu);

    if ( xc_debug_attach(xc_handle, my_domain, my_vcpu) )
    {
        printf("(pdb) attach error!\n");  fflush(stdout);
        failwith("attach error");
    }

    CAMLreturn(Val_unit);
}


/*
 * detach_debugger : int -> int -> unit
 */
value
detach_debugger (value domain, value vcpu)
{
    CAMLparam2(domain, vcpu);

    int my_domain = Int_val(domain);
    int my_vcpu = Int_val(vcpu);

    printf ("(pdb) detach domain [%d.%d]\n", my_domain, my_vcpu);

    if ( xc_debug_detach(xc_handle, my_domain, my_vcpu) )
    {
        printf("(pdb) detach error!\n");  fflush(stdout);
        failwith("detach error");
    }

    CAMLreturn(Val_unit);
}


/*
 * debugger_status : unit -> unit
 */
value
debugger_status (value unit)
{
    CAMLparam1(unit);

    printf ("(pdb) debugger status\n");

    CAMLreturn(Val_unit);
}

/*
 * pause_target : int -> unit
 */
value
pause_target (value domid)
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

    count = xc_debug_query_domain_stop(xc_handle, dom_list, max_domains);
    if ( count < 0 )
    {
        printf("(pdb) query domain stop!\n");  fflush(stdout);
        failwith("query domain stop");
    }

    printf ("QDS: %d\n", count);
    for (loop = 0; loop < count; loop ++)
        printf ("  %d %d\n", loop, dom_list[loop]);

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
/****************************************************************************/

#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * evtchn_open : string -> int -> int -> Unix.file_descr
 *
 * OCaml's Unix library doesn't have mknod, so it makes more sense just write
 * this in C.  This code is from Keir/Andy.
 */
value
evtchn_open (value filename, value major, value minor)
{
    CAMLparam3(filename, major, minor);

    char *myfilename = String_val(filename);
    int   mymajor = Int_val(major);
    int   myminor = Int_val(minor);
    int   evtchn_fd;
    struct stat st;
    
    /* Make sure any existing device file links to correct device. */
    if ( (lstat(myfilename, &st) != 0) ||
         !S_ISCHR(st.st_mode) ||
         (st.st_rdev != makedev(mymajor, myminor)) )
    {
        (void)unlink(myfilename);
    }

 reopen:
    evtchn_fd = open(myfilename, O_RDWR); 
    if ( evtchn_fd == -1 )
    {
        if ( (errno == ENOENT) &&
             ((mkdir("/dev/xen", 0755) == 0) || (errno == EEXIST)) &&
             (mknod(myfilename, S_IFCHR|0600, makedev(mymajor,myminor)) == 0) )
        {
            goto reopen;
        }
        return -errno;
    }

    CAMLreturn(Val_int(evtchn_fd));
}

/*
 * evtchn_bind_virq : int -> int
 */
value
evtchn_bind_virq (value virq)
{
    CAMLparam1(virq);

    int port;

    if ( pdb_evtchn_bind_virq(xc_handle, Int_val(virq), &port) < 0 )
    {
        printf("(pdb) evtchn_bind_virq error!\n");  fflush(stdout);
        failwith("evtchn_bind_virq error");
    }

    CAMLreturn(Val_int(port));
}

/*
 * evtchn_bind : Unix.file_descr -> int -> unit
 */
value
evtchn_bind (value fd, value idx)
{
    CAMLparam2(fd, idx);

    int myfd = Int_val(fd);
    int myidx = Int_val(idx);

    if ( xen_evtchn_bind(myfd, myidx) < 0 )
    {
        printf("(pdb) evtchn_bind error!\n");  fflush(stdout);
        failwith("evtchn_bind error");
    }

    CAMLreturn(Val_unit);
}

/*
 * evtchn_unbind : Unix.file_descr -> int -> unit
 */
value
evtchn_unbind (value fd, value idx)
{
    CAMLparam2(fd, idx);

    int myfd = Int_val(fd);
    int myidx = Int_val(idx);

    if ( xen_evtchn_unbind(myfd, myidx) < 0 )
    {
        printf("(pdb) evtchn_unbind error!\n");  fflush(stdout);
        failwith("evtchn_unbind error");
    }

    CAMLreturn(Val_unit);
}

/*
 * evtchn_read : Unix.file_descr -> int
 */
value
evtchn_read (value fd)
{
    CAMLparam1(fd);

    u16 v;
    int bytes;
    int rc = -1;
    int myfd = Int_val(fd);

    while ( (bytes = read(myfd, &v, sizeof(v))) == -1 )
    {
        if ( errno == EINTR )  continue;
        rc = -errno;
        goto exit;
    }
    
    if ( bytes == sizeof(v) )
        rc = v;
    
 exit:
    CAMLreturn(Val_int(rc));
}


/*
 * evtchn_close : Unix.file_descr -> unit
 */
value
evtchn_close (value fd)
{
    CAMLparam1(fd);
    int myfd = Int_val(fd);

    (void)close(myfd);

    CAMLreturn(Val_unit);
}

/*
 * evtchn_unmask : Unix.file_descr -> int -> unit
 */
value
evtchn_unmask (value fd, value idx)
{
    CAMLparam1(fd);

    int myfd = Int_val(fd);
    u16 myidx = Int_val(idx);

    (void)write(myfd, &myidx, sizeof(myidx));

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

