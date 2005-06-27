/*
 * pdb_caml_xc.c
 *
 * http://www.cl.cam.ac.uk/netos/pdb
 *
 * PDB's OCaml interface library for debugging domains
 */

#include <xc.h>
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

int xc_handle = -1;


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
 * debugger_status : unit -> unit
 */
value
debugger_status (value unit)
{
    CAMLparam1(unit);

    CAMLreturn(Val_unit);
}

/****************************************************************************/
/****************************************************************************/

/*
 * evtchn_bind_virq : int -> int
 */
value
evtchn_bind_virq (value virq)
{
    CAMLparam1(virq);

    int port;
    int my_virq = Int_val(virq);

    if ( xc_evtchn_bind_virq(xc_handle, my_virq, &port) < 0 )
    {
        printf("(pdb) evtchn_bind_virq error!\n");  fflush(stdout);
        failwith("evtchn_bind_virq error");
    }

    CAMLreturn(Val_int(port));
}

/*
 * evtchn_bind_interdomain : int -> int * int
 */
value
evtchn_bind_interdomain (value remote_domain)
{
    CAMLparam1(remote_domain);
    CAMLlocal1(result);

    int my_remote_domain = Int_val(remote_domain);
    int local_domain = 0;
    int local_port = 0;
    int remote_port = 0;

    if ( xc_evtchn_bind_interdomain(xc_handle, local_domain, my_remote_domain,
                                    &local_port, &remote_port) < 0 )
    {
        printf("(pdb) evtchn_bind_interdomain error!\n");  fflush(stdout);
        failwith("evtchn_bind_interdomain error");
    }

    result = caml_alloc_tuple(2);                                   /* FIXME */
    Store_field(result, 0, Val_int(local_port));
    Store_field(result, 1, Val_int(remote_port));

    CAMLreturn(result);
}

void *
map_ring(u32 dom, unsigned long mfn )
{
    return xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                PROT_READ | PROT_WRITE, mfn);
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

