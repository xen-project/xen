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
#include <asm/sal.h>
#include <asm/vlsapic.h>

struct sioemu_callback_info *
sioemu_deliver (void)
{
    VCPU *vcpu = current;
    REGS *regs = vcpu_regs(vcpu);
    struct sioemu_callback_info *info = vcpu->arch.arch_vmx.sioemu_info_mva;
    unsigned long psr = vmx_vcpu_get_psr(vcpu);

    if (vcpu->vcpu_info->evtchn_upcall_mask)
        panic_domain (NULL, "sioemu_deliver: aleady in stub mode\n");
    if (info == NULL)
        panic_domain (NULL, "sioemu_deliver: set_callback not called\n");

    /* All cleared, but keep BN.  */
    vmx_vcpu_set_psr(vcpu, IA64_PSR_MC | (psr & IA64_PSR_BN));

    /* Set info.  */
    info->ip = regs->cr_iip;
    info->psr = psr;
    info->ifs = regs->cr_ifs;
    info->nats = (((regs->eml_unat >> IA64_PT_REGS_R8_SLOT) & 0x0f) << 8)
        | (((regs->eml_unat >> IA64_PT_REGS_R2_SLOT) & 1) << 2);
    info->r8 = regs->r8;
    info->r9 = regs->r9;
    info->r10 = regs->r10;
    info->r11 = regs->r11;
    info->r2 = regs->r2;

    regs->cr_ifs = 0;	// pre-cover
    regs->cr_iip = vcpu->arch.event_callback_ip;
    regs->eml_unat &= ~(1UL << IA64_PT_REGS_R8_SLOT);
    regs->r8 = vcpu->arch.arch_vmx.sioemu_info_gpa;

    /* Mask events.  */
    vcpu->vcpu_info->evtchn_upcall_mask = 1;

    debugger_event(XEN_IA64_DEBUG_ON_EVENT);

    return info;
}

static void
sioemu_callback_return (void)
{
    VCPU *vcpu = current;
    REGS *regs = vcpu_regs(vcpu);
    struct sioemu_callback_info *info = vcpu->arch.arch_vmx.sioemu_info_mva;

    if (info == NULL)
        panic_domain (NULL, "sioemu_deliver: set_callback not called\n");
    if ((info->cause & ~0x1UL) != 0)
        panic_domain (NULL, "sioemu_callback_return: bad operation (%lx)\n",
                      info->cause);

    /* First restore registers.  */
    regs->cr_iip = info->ip;
    regs->cr_ifs = info->ifs;
    vmx_vcpu_set_psr (vcpu, info->psr);
    regs->r8 = info->r8;
    regs->r9 = info->r9;
    regs->r10 = info->r10;
    regs->r11 = info->r11;
    regs->r2 = info->r2;
    regs->eml_unat &= ~((0x0fUL << IA64_PT_REGS_R8_SLOT)
                        | (1UL << IA64_PT_REGS_R2_SLOT));
    regs->eml_unat |= (((info->nats >> 8) & 0x0f) << IA64_PT_REGS_R8_SLOT)
        | (((info->nats >> 2) & 1) << IA64_PT_REGS_R2_SLOT);

    /* Unmask events.  */
    vcpu->vcpu_info->evtchn_upcall_mask = 0;

    /* Then apply commands.  */
    if (info->cause & 1) {
        emulate_io_update (vcpu, info->arg0, info->arg1, info->arg2);
    }
}

void
sioemu_deliver_event (void)
{
    struct sioemu_callback_info *info;

    info = sioemu_deliver ();
    info->cause = SIOEMU_CB_EVENT;
}

void
sioemu_io_emulate (unsigned long padr, unsigned long data,
                  unsigned long data1, unsigned long word)
{
    struct sioemu_callback_info *info;

    info = sioemu_deliver ();
    info->cause = SIOEMU_CB_IO_EMULATE;
    info->arg0 = padr;
    info->arg1 = data;
    info->arg2 = data1;
    info->arg3 = word;
}

void
sioemu_sal_assist (struct vcpu *v)
{
    struct sioemu_callback_info *info;

    info = sioemu_deliver ();
    info->cause = SIOEMU_CB_SAL_ASSIST;
}

static int
sioemu_set_callback (struct vcpu *v, unsigned long cb_ip, unsigned long paddr)
{
    struct page_info *page;
    unsigned long mfn;
    pte_t pte;

    v->arch.event_callback_ip = cb_ip;
    if ((paddr & 0xfff) || v->arch.arch_vmx.sioemu_info_mva)
        return -EINVAL;
    pte = *lookup_noalloc_domain_pte(v->domain, paddr);
    if (!pte_present(pte) || !pte_mem(pte))
        return -EINVAL;
    mfn = pte_pfn(pte);
    ASSERT(mfn_valid(mfn));

    page = mfn_to_page(mfn);
    if (get_page(page, v->domain) == 0)
        return -EINVAL;
    v->arch.arch_vmx.sioemu_info_gpa = paddr;
    v->arch.arch_vmx.sioemu_info_mva = mfn_to_virt(mfn);
    return 0;
}

static int
sioemu_add_io_physmap (struct domain *d, unsigned long start,
                      unsigned long size, unsigned long type)
{
    unsigned long i;
    int res;

    /* Convert to ppn.  */
    type <<= PAGE_SHIFT;

    /* Check type.  */
    if (type == 0 || (type & _PAGE_PPN_MASK) != type)
        return -EINVAL;
    if ((start & (PAGE_SIZE -1)) || (size & (PAGE_SIZE - 1)))
        return -EINVAL;

    /* Check area is currently unassigned.  */
    for (i = start; i < start + size; i += PAGE_SIZE) {
        if (____lookup_domain_mpa(d, i) != INVALID_MFN)
            return -EBUSY;
    }

    /* Set.  */
    for (i = start; i < start + size; i += PAGE_SIZE) {
        res = __assign_domain_page(d, i, type, ASSIGN_writable | ASSIGN_io);
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
        panic_domain(NULL, "sioemu_hypercall: not in stub mode\n");

    switch (regs->r2 & FW_HYPERCALL_NUM_MASK_LOW)
    {
    case SIOEMU_HYPERCALL_SET_CALLBACK:
        regs->r8 = sioemu_set_callback(current, regs->r8, regs->r9);
        break;
    case SIOEMU_HYPERCALL_START_FW:
        regs->cr_iip = regs->r8;
        vmx_vcpu_set_psr(current, regs->r9);
        current->vcpu_info->evtchn_upcall_mask = 0;
        break;
    case SIOEMU_HYPERCALL_ADD_IO_PHYSMAP:
        regs->r8 = sioemu_add_io_physmap(current->domain,
                                         regs->r8, regs->r9, regs->r10);
        break;
    case SIOEMU_HYPERCALL_GET_TIME:
    {
        uint64_t sec, nsec, now;
        get_wallclock(&sec, &nsec, &now);
        regs->r8 = (sec << 30) + nsec;
        regs->r9 = now;
        break;
    }
    case SIOEMU_HYPERCALL_FLUSH_CACHE:
        regs->r8 = ia64_sal_cache_flush(regs->r8);
        break;
    case SIOEMU_HYPERCALL_FREQ_BASE:
        regs->r8 = ia64_sal_freq_base(regs->r8, &regs->r9, &regs->r10);
        break;
    case SIOEMU_HYPERCALL_DELIVER_INT:
        regs->r8 = vlsapic_deliver_int(current->domain,
                                       regs->r8, regs->r9, regs->r10);
        break;
    case SIOEMU_HYPERCALL_CALLBACK_RETURN:
        sioemu_callback_return ();
        vcpu_decrement_iip(current);
        break;
    default:
        panic_domain (NULL, "bad sioemu hypercall %lx\n", regs->r2);
        break;
    }
}
