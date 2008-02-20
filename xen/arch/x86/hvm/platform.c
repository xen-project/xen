/*
 * platform.c: handling x86 platform related MMIO instructions
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/domain_page.h>
#include <asm/page.h>
#include <xen/event.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <asm/regs.h>
#include <asm/x86_emulate.h>
#include <asm/paging.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/io.h>
#include <public/hvm/ioreq.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/hvm/emulate.h>

int inst_copy_from_guest(
    unsigned char *buf, unsigned long guest_eip, int inst_len)
{
    if ( inst_len > MAX_INST_LEN || inst_len <= 0 )
        return 0;
    if ( hvm_fetch_from_guest_virt_nofault(buf, guest_eip, inst_len) )
        return 0;
    return inst_len;
}

void send_pio_req(unsigned long port, unsigned long count, int size,
                  paddr_t value, int dir, int df, int value_is_ptr)
{
    struct vcpu *v = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;

    if ( size == 0 || count == 0 ) {
        printk("null pio request? port %lx, count %lx, "
               "size %d, value %"PRIpaddr", dir %d, value_is_ptr %d.\n",
               port, count, size, value, dir, value_is_ptr);
    }

    vio = get_ioreq(v);
    if ( vio == NULL ) {
        printk("bad shared page: %lx\n", (unsigned long) vio);
        domain_crash_synchronous();
    }

    p = &vio->vp_ioreq;
    if ( p->state != STATE_IOREQ_NONE )
        printk("WARNING: send pio with something already pending (%d)?\n",
               p->state);

    p->dir = dir;
    p->data_is_ptr = value_is_ptr;

    p->type = IOREQ_TYPE_PIO;
    p->size = size;
    p->addr = port;
    p->count = count;
    p->df = df;

    p->io_count++;

    p->data = value;

    if ( hvm_portio_intercept(p) )
    {
        p->state = STATE_IORESP_READY;
        hvm_io_assist();
        return;
    }

    hvm_send_assist_req(v);
}

void send_mmio_req(unsigned char type, paddr_t gpa,
                   unsigned long count, int size, paddr_t value,
                   int dir, int df, int value_is_ptr)
{
    struct vcpu *v = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;

    if ( size == 0 || count == 0 ) {
        printk("null mmio request? type %d, gpa %"PRIpaddr", "
               "count %lx, size %d, value %"PRIpaddr", dir %d, "
               "value_is_ptr %d.\n",
               type, gpa, count, size, value, dir, value_is_ptr);
    }

    vio = get_ioreq(v);
    if (vio == NULL) {
        printk("bad shared page\n");
        domain_crash_synchronous();
    }

    p = &vio->vp_ioreq;

    if ( p->state != STATE_IOREQ_NONE )
        printk("WARNING: send mmio with something already pending (%d)?\n",
               p->state);
    p->dir = dir;
    p->data_is_ptr = value_is_ptr;

    p->type = type;
    p->size = size;
    p->addr = gpa;
    p->count = count;
    p->df = df;

    p->io_count++;

    p->data = value;

    if ( hvm_mmio_intercept(p) || hvm_buffered_io_intercept(p) )
    {
        p->state = STATE_IORESP_READY;
        hvm_io_assist();
        return;
    }

    hvm_send_assist_req(v);
}

void send_timeoffset_req(unsigned long timeoff)
{
    ioreq_t p[1];

    if ( timeoff == 0 )
        return;

    memset(p, 0, sizeof(*p));

    p->type = IOREQ_TYPE_TIMEOFFSET;
    p->size = 8;
    p->count = 1;
    p->dir = IOREQ_WRITE;
    p->data = timeoff;

    p->state = STATE_IOREQ_READY;

    if ( !hvm_buffered_io_send(p) )
        printk("Unsuccessful timeoffset update\n");
}

/* Ask ioemu mapcache to invalidate mappings. */
void send_invalidate_req(void)
{
    struct vcpu *v = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;

    vio = get_ioreq(v);
    if ( vio == NULL )
    {
        printk("bad shared page: %lx\n", (unsigned long) vio);
        domain_crash_synchronous();
    }

    p = &vio->vp_ioreq;
    if ( p->state != STATE_IOREQ_NONE )
        printk("WARNING: send invalidate req with something "
               "already pending (%d)?\n", p->state);

    p->type = IOREQ_TYPE_INVALIDATE;
    p->size = 4;
    p->dir = IOREQ_WRITE;
    p->data = ~0UL; /* flush all */
    p->io_count++;

    hvm_send_assist_req(v);
}

int handle_mmio(void)
{
    struct hvm_emulate_ctxt ctxt;
    struct vcpu *curr = current;
    int rc;

    hvm_emulate_prepare(&ctxt, guest_cpu_user_regs());

    rc = hvm_emulate_one(&ctxt);

    switch ( rc )
    {
    case X86EMUL_UNHANDLEABLE:
        gdprintk(XENLOG_WARNING,
                 "MMIO emulation failed @ %04x:%lx: "
                 "%02x %02x %02x %02x %02x %02x\n",
                 hvmemul_get_seg_reg(x86_seg_cs, &ctxt)->sel,
                 ctxt.insn_buf_eip,
                 ctxt.insn_buf[0], ctxt.insn_buf[1],
                 ctxt.insn_buf[2], ctxt.insn_buf[3],
                 ctxt.insn_buf[4], ctxt.insn_buf[5]);
        return 0;
    case X86EMUL_EXCEPTION:
        if ( ctxt.flags.exn_pending )
            hvm_inject_exception(ctxt.exn_vector, 0, 0);
        break;
    default:
        break;
    }

    hvm_emulate_writeback(&ctxt);

    curr->arch.hvm_vcpu.mmio_in_progress = curr->arch.hvm_vcpu.io_in_progress;

    return 1;
}

DEFINE_PER_CPU(int, guest_handles_in_xen_space);

/* Note that copy_{to,from}_user_hvm require the PTE to be writable even
   when they're only trying to read from it.  The guest is expected to
   deal with this. */
unsigned long copy_to_user_hvm(void *to, const void *from, unsigned len)
{
    int rc;

    if ( this_cpu(guest_handles_in_xen_space) )
    {
        memcpy(to, from, len);
        return 0;
    }

    rc = hvm_copy_to_guest_virt_nofault((unsigned long)to, (void *)from, len);
    return rc ? len : 0; /* fake a copy_to_user() return code */
}

unsigned long copy_from_user_hvm(void *to, const void *from, unsigned len)
{
    int rc;

    if ( this_cpu(guest_handles_in_xen_space) )
    {
        memcpy(to, from, len);
        return 0;
    }

    rc = hvm_copy_from_guest_virt_nofault(to, (unsigned long)from, len);
    return rc ? len : 0; /* fake a copy_from_user() return code */
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
