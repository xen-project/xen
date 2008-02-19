/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * sioemu.c: Self IO emulation - hypercall and return.
 * Copyright (c) 2008, Tristan Gingold <tgingold@free.fr>
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

#include <asm/vcpu.h>
#include <asm/vmx_vcpu.h>
#include <asm/sioemu.h>
#include <public/arch-ia64/sioemu.h>
#include <asm/dom_fw.h>
#include <asm/debugger.h>

static REGS *
sioemu_deliver (void)
{
    VCPU *vcpu = current;
    REGS *regs = vcpu_regs(vcpu);
    unsigned long psr = vmx_vcpu_get_psr(vcpu);

    if (vcpu->vcpu_info->evtchn_upcall_mask)
        panic_domain (NULL, "sioemu_deliver: aleady in stub mode\n");

    /* All cleared, but keep BN.  */
    vmx_vcpu_set_psr(vcpu, IA64_PSR_MC | (psr & IA64_PSR_BN));

    /* Save registers. */
    vcpu->arch.arch_vmx.stub_saved[0] = regs->r16;
    vcpu->arch.arch_vmx.stub_saved[1] = regs->r17;
    vcpu->arch.arch_vmx.stub_saved[2] = regs->r18;
    vcpu->arch.arch_vmx.stub_saved[3] = regs->r19;
    vcpu->arch.arch_vmx.stub_saved[4] = regs->r20;
    vcpu->arch.arch_vmx.stub_saved[5] = regs->r21;
    vcpu->arch.arch_vmx.stub_saved[6] = regs->r22;
    vcpu->arch.arch_vmx.stub_saved[7] = regs->r23;
    vcpu->arch.arch_vmx.stub_saved[8] = regs->r24;
    vcpu->arch.arch_vmx.stub_saved[9] = regs->r25;
    vcpu->arch.arch_vmx.stub_saved[10] = regs->r26;
    vcpu->arch.arch_vmx.stub_saved[11] = regs->r27;
    vcpu->arch.arch_vmx.stub_saved[12] = regs->r28;
    vcpu->arch.arch_vmx.stub_saved[13] = regs->r29;
    vcpu->arch.arch_vmx.stub_saved[14] = regs->r30;
    vcpu->arch.arch_vmx.stub_saved[15] = regs->r31;
    vcpu->arch.arch_vmx.stub_nats =
        (regs->eml_unat >> IA64_PT_REGS_R16_SLOT) & 0xffff;

    /* Context. */
    regs->r28 = regs->cr_iip;
    regs->r29 = psr;
    regs->r30 = regs->cr_ifs;

    regs->cr_ifs = 0;  // pre-cover

    regs->cr_iip = vcpu->arch.event_callback_ip;
    regs->eml_unat &= ~(0xffffUL << IA64_PT_REGS_R16_SLOT);

    /* Parameters.  */
    regs->r16 = 0;
    regs->r17 = vcpu->arch.arch_vmx.stub_buffer;

    /* Mask events.  */
    vcpu->vcpu_info->evtchn_upcall_mask = 1;

    debugger_event(XEN_IA64_DEBUG_ON_EVENT);

    return regs;
}

void
sioemu_callback_return (void)
{
    VCPU *vcpu = current;
    REGS *regs = vcpu_regs(vcpu);
    u64 cmd = regs->r16;
    u64 arg1 = regs->r19;
    u64 arg2 = regs->r20;
    u64 arg3 = regs->r21;

    if ((cmd & ~0x1UL) != 0)
        panic_domain (NULL,
                      "sioemu_callback_return: bad operation (%lx)\n", cmd);

    /* First restore registers.  */
    regs->cr_iip = regs->r28;
    regs->cr_ifs = regs->r30;
    vmx_vcpu_set_psr (vcpu, regs->r29);

    regs->eml_unat &= ~(0xffffUL << IA64_PT_REGS_R16_SLOT);
    regs->eml_unat |= vcpu->arch.arch_vmx.stub_nats << IA64_PT_REGS_R16_SLOT;

    regs->r16 = vcpu->arch.arch_vmx.stub_saved[0];
    regs->r17 = vcpu->arch.arch_vmx.stub_saved[1];
    regs->r18 = vcpu->arch.arch_vmx.stub_saved[2];
    regs->r19 = vcpu->arch.arch_vmx.stub_saved[3];
    regs->r20 = vcpu->arch.arch_vmx.stub_saved[4];
    regs->r21 = vcpu->arch.arch_vmx.stub_saved[5];
    regs->r22 = vcpu->arch.arch_vmx.stub_saved[6];
    regs->r23 = vcpu->arch.arch_vmx.stub_saved[7];
    regs->r24 = vcpu->arch.arch_vmx.stub_saved[8];
    regs->r25 = vcpu->arch.arch_vmx.stub_saved[9];
    regs->r26 = vcpu->arch.arch_vmx.stub_saved[10];
    regs->r27 = vcpu->arch.arch_vmx.stub_saved[11];
    regs->r28 = vcpu->arch.arch_vmx.stub_saved[12];
    regs->r29 = vcpu->arch.arch_vmx.stub_saved[13];
    regs->r30 = vcpu->arch.arch_vmx.stub_saved[14];
    regs->r31 = vcpu->arch.arch_vmx.stub_saved[15];

    /* Unmask events.  */
    vcpu->vcpu_info->evtchn_upcall_mask = 0;

    /* Then apply commands.  */
    if (cmd & 1) {
        emulate_io_update (vcpu, arg1, arg2, arg3);
    }
}

void
sioemu_deliver_event (void)
{
    REGS *regs;

    regs = sioemu_deliver ();

    regs->r16 = 0;
}

void
sioemu_io_emulate (unsigned long padr, unsigned long data,
                  unsigned long data1, unsigned long word)
{
    REGS *regs;

    regs = sioemu_deliver ();
    regs->r16 = 1;
    regs->r19 = padr;
    regs->r20 = data;
    regs->r21 = data1;
    regs->r22 = word;
}

static int
sioemu_add_io_physmap (struct domain *d, unsigned long start,
                      unsigned long size, unsigned long type)
{
    unsigned long i;
    int res;

    /* Check type.  */
    if (type == 0 || (type & GPFN_IO_MASK) != type)
        return -EINVAL;
    if ((start & (PAGE_SIZE -1)) || (size & (PAGE_SIZE - 1)))
        return -EINVAL;

    /* Check area is currently unassigned.  */
    for (i = start; i < start + size; i += PAGE_SIZE) {
        unsigned long mpa = ____lookup_domain_mpa(d, i);
        if (mpa != GPFN_INV_MASK && mpa != INVALID_MFN)
            return -EBUSY;
    }

    /* Set.  */
    for (i = start; i < start + size; i += PAGE_SIZE) {
        res = __assign_domain_page(d, i, type, ASSIGN_writable);
        if (res != 0)
            return res;
    }

    return 0;
}

void
sioemu_hypercall (struct pt_regs *regs)
{
    //printk ("sioemu_hypercall: r2=%lx r8=%lx r9=%lx\n",
    //        regs->r2, regs->r8, regs->r9);

    if (current->vcpu_info->evtchn_upcall_mask == 0)
        panic_domain (NULL, "sioemu_hypercall: not in stub mode\n");

    switch (regs->r2 & FW_HYPERCALL_NUM_MASK_LOW)
    {
    case SIOEMU_HYPERCALL_SET_CALLBACK:
        current->arch.event_callback_ip = regs->r8;
        current->arch.arch_vmx.stub_buffer = regs->r9;
        break;
    case SIOEMU_HYPERCALL_START_FW:
        regs->cr_iip = regs->r8;
        vmx_vcpu_set_psr (current, regs->r9);
        current->vcpu_info->evtchn_upcall_mask = 0;
        break;
    case SIOEMU_HYPERCALL_ADD_IO_PHYSMAP:
        regs->r8 = sioemu_add_io_physmap (current->domain,
                                          regs->r8, regs->r9, regs->r10);
        break;
    case SIOEMU_HYPERCALL_GET_TIME:
    {
        uint64_t sec, nsec;
        get_wallclock (&sec, &nsec);
        regs->r8 = (sec << 30) + nsec;
        break;
    }
    default:
        panic_domain (NULL, "bad sioemu hypercall %lx\n", regs->r2);
        break;
    }
}
