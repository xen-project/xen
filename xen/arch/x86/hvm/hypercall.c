/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/hvm/hypercall.c
 *
 * HVM hypercall dispatching routines
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */
#include <xen/lib.h>
#include <xen/hypercall.h>
#include <xen/ioreq.h>
#include <xen/nospec.h>

#include <asm/hvm/emulate.h>
#include <asm/hvm/support.h>
#include <asm/hvm/viridian.h>
#include <asm/multicall.h>

#include <public/hvm/hvm_op.h>
#include <public/hvm/params.h>

long hvm_memory_op(unsigned long cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    long rc;

    switch ( cmd & MEMOP_CMD_MASK )
    {
    case XENMEM_machphys_mapping:
        return -ENOSYS;
    }

    if ( !current->hcall_compat )
        rc = do_memory_op(cmd, arg);
    else
        rc = compat_memory_op(cmd, arg);

    return rc;
}

#ifdef CONFIG_GRANT_TABLE
long hvm_grant_table_op(
    unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) uop, unsigned int count)
{
    switch ( cmd )
    {
    case GNTTABOP_query_size:
    case GNTTABOP_setup_table:
    case GNTTABOP_set_version:
    case GNTTABOP_get_version:
    case GNTTABOP_copy:
    case GNTTABOP_map_grant_ref:
    case GNTTABOP_unmap_grant_ref:
    case GNTTABOP_swap_grant_ref:
        break;

    default: /* All other commands need auditing. */
        return -ENOSYS;
    }

    if ( !current->hcall_compat )
        return do_grant_table_op(cmd, uop, count);
    else
        return compat_grant_table_op(cmd, uop, count);
}
#endif

long hvm_physdev_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    const struct vcpu *curr = current;
    const struct domain *currd = curr->domain;

    switch ( cmd )
    {
    case PHYSDEVOP_map_pirq:
    case PHYSDEVOP_unmap_pirq:
        break;

    case PHYSDEVOP_eoi:
    case PHYSDEVOP_irq_status_query:
    case PHYSDEVOP_get_free_pirq:
        if ( !has_pirq(currd) )
            return -ENOSYS;
        break;

    case PHYSDEVOP_setup_gsi:
    case PHYSDEVOP_pci_mmcfg_reserved:
    case PHYSDEVOP_pci_device_add:
    case PHYSDEVOP_pci_device_remove:
    case PHYSDEVOP_pci_device_reset:
    case PHYSDEVOP_dbgp_op:
        if ( !is_hardware_domain(currd) )
            return -ENOSYS;
        break;

    default:
        return -ENOSYS;
    }

    if ( !curr->hcall_compat )
        return do_physdev_op(cmd, arg);
    else
        return compat_physdev_op(cmd, arg);
}

int hvm_hypercall(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    int mode = hvm_guest_x86_mode(curr);
    unsigned long eax = regs->eax;
    unsigned int token;

    switch ( mode )
    {
    case X86_MODE_64BIT:
        eax = regs->rax;
        fallthrough;
    case X86_MODE_32BIT:
    case X86_MODE_16BIT:
        if ( currd->arch.monitor.guest_request_userspace_enabled &&
             eax == __HYPERVISOR_hvm_op &&
             (mode == X86_MODE_64BIT ? regs->rdi : regs->ebx) ==
             HVMOP_guest_request_vm_event )
            break;

        if ( likely(!hvm_get_cpl(curr)) )
            break;
        fallthrough;
    case X86_MODE_VM86:
        regs->rax = -EPERM;
        return HVM_HCALL_completed;
    case X86_MODE_REAL:
        break;
    }

    if ( (eax & 0x80000000U) && is_viridian_domain(currd) )
    {
        int ret;

        /* See comment below. */
        token = hvmemul_cache_disable(curr);

        ret = viridian_hypercall(regs);

        hvmemul_cache_restore(curr, token);

        return ret;
    }

    /*
     * Caching is intended for instruction emulation only. Disable it
     * for any accesses by hypercall argument copy-in / copy-out.
     */
    token = hvmemul_cache_disable(curr);

    curr->hcall_preempted = false;

    if ( mode == 8 )
    {
        HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%lu(%lx, %lx, %lx, %lx, %lx)",
                    eax, regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r8);

        call_handlers_hvm64(eax, regs->rax, regs->rdi, regs->rsi, regs->rdx,
                            regs->r10, regs->r8);

        if ( !curr->hcall_preempted && regs->rax != -ENOSYS )
            clobber_regs(regs, eax, hvm, 64);
    }
    else
    {
        HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%lu(%x, %x, %x, %x, %x)", eax,
                    regs->ebx, regs->ecx, regs->edx, regs->esi, regs->edi);

        curr->hcall_compat = true;
        call_handlers_hvm32(eax, regs->eax, regs->ebx, regs->ecx, regs->edx,
                            regs->esi, regs->edi);
        curr->hcall_compat = false;

        if ( !curr->hcall_preempted && regs->eax != -ENOSYS )
            clobber_regs(regs, eax, hvm, 32);
    }

    hvmemul_cache_restore(curr, token);

    HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%lu -> %lx", eax, regs->rax);

    if ( unlikely(curr->mapcache_invalidate) )
    {
        curr->mapcache_invalidate = false;
        ioreq_signal_mapcache_invalidate();
    }

    perfc_incra(hypercalls, eax);

    return curr->hcall_preempted ? HVM_HCALL_preempted : HVM_HCALL_completed;
}

enum mc_disposition hvm_do_multicall_call(struct mc_state *state)
{
    struct vcpu *curr = current;

    if ( hvm_guest_x86_mode(curr) == X86_MODE_64BIT )
    {
        struct multicall_entry *call = &state->call;

        call_handlers_hvm64(call->op, call->result, call->args[0], call->args[1],
                            call->args[2], call->args[3], call->args[4]);
    }
    else
    {
        struct compat_multicall_entry *call = &state->compat_call;

        call_handlers_hvm32(call->op, call->result, call->args[0], call->args[1],
                            call->args[2], call->args[3], call->args[4]);
    }

    return !hvm_get_cpl(curr) ? mc_continue : mc_preempt;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
