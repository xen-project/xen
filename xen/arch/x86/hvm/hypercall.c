/******************************************************************************
 * arch/hvm/hypercall.c
 *
 * HVM hypercall dispatching routines
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */
#include <xen/lib.h>
#include <xen/hypercall.h>
#include <xen/nospec.h>

#include <asm/hvm/emulate.h>
#include <asm/hvm/support.h>
#include <asm/hvm/viridian.h>

#include <public/hvm/hvm_op.h>
#include <public/hvm/params.h>

static long hvm_memory_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    const struct vcpu *curr = current;
    long rc;

    switch ( cmd & MEMOP_CMD_MASK )
    {
    case XENMEM_machine_memory_map:
    case XENMEM_machphys_mapping:
        return -ENOSYS;
    }

    if ( !curr->hcall_compat )
        rc = do_memory_op(cmd, arg);
    else
        rc = compat_memory_op(cmd, arg);

    if ( (cmd & MEMOP_CMD_MASK) == XENMEM_decrease_reservation )
        curr->domain->arch.hvm.qemu_mapcache_invalidate = true;

    return rc;
}

#ifdef CONFIG_GRANT_TABLE
static long hvm_grant_table_op(
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

static long hvm_physdev_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    const struct vcpu *curr = current;
    const struct domain *currd = curr->domain;

    switch ( cmd )
    {
    case PHYSDEVOP_map_pirq:
    case PHYSDEVOP_unmap_pirq:
    case PHYSDEVOP_eoi:
    case PHYSDEVOP_irq_status_query:
    case PHYSDEVOP_get_free_pirq:
        if ( !has_pirq(currd) )
            return -ENOSYS;
        break;

    case PHYSDEVOP_pci_mmcfg_reserved:
        if ( !has_vpci(currd) || !is_hardware_domain(currd) )
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

#define HYPERCALL(x)                                         \
    [ __HYPERVISOR_ ## x ] = { (hypercall_fn_t *) do_ ## x,  \
                               (hypercall_fn_t *) do_ ## x }

#define HVM_CALL(x)                                          \
    [ __HYPERVISOR_ ## x ] = { (hypercall_fn_t *) hvm_ ## x, \
                               (hypercall_fn_t *) hvm_ ## x }

#define COMPAT_CALL(x)                                       \
    [ __HYPERVISOR_ ## x ] = { (hypercall_fn_t *) do_ ## x,  \
                               (hypercall_fn_t *) compat_ ## x }

#define do_arch_1             paging_domctl_continuation

static const hypercall_table_t hvm_hypercall_table[] = {
    HVM_CALL(memory_op),
#ifdef CONFIG_GRANT_TABLE
    HVM_CALL(grant_table_op),
#endif
    HYPERCALL(vm_assist),
    COMPAT_CALL(vcpu_op),
    HVM_CALL(physdev_op),
    COMPAT_CALL(xen_version),
    HYPERCALL(console_io),
    HYPERCALL(event_channel_op),
    COMPAT_CALL(sched_op),
    COMPAT_CALL(set_timer_op),
    HYPERCALL(xsm_op),
    HYPERCALL(hvm_op),
    HYPERCALL(sysctl),
    HYPERCALL(domctl),
#ifdef CONFIG_ARGO
    COMPAT_CALL(argo_op),
#endif
    COMPAT_CALL(platform_op),
#ifdef CONFIG_PV
    COMPAT_CALL(mmuext_op),
#endif
    HYPERCALL(xenpmu_op),
    COMPAT_CALL(dm_op),
#ifdef CONFIG_HYPFS
    HYPERCALL(hypfs_op),
#endif
    HYPERCALL(arch_1)
};

#undef do_arch_1

#undef HYPERCALL
#undef HVM_CALL
#undef COMPAT_CALL

int hvm_hypercall(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    int mode = hvm_guest_x86_mode(curr);
    unsigned long eax = regs->eax;
    unsigned int token;

    switch ( mode )
    {
    case 8:
        eax = regs->rax;
        /* Fallthrough to permission check. */
    case 4:
    case 2:
        if ( currd->arch.monitor.guest_request_userspace_enabled &&
            eax == __HYPERVISOR_hvm_op &&
            (mode == 8 ? regs->rdi : regs->ebx) == HVMOP_guest_request_vm_event )
            break;

        if ( unlikely(hvm_get_cpl(curr)) )
        {
    default:
            regs->rax = -EPERM;
            return HVM_HCALL_completed;
        }
    case 0:
        break;
    }

    if ( (eax & 0x80000000) && is_viridian_domain(currd) )
    {
        int ret;

        /* See comment below. */
        token = hvmemul_cache_disable(curr);

        ret = viridian_hypercall(regs);

        hvmemul_cache_restore(curr, token);

        return ret;
    }

    BUILD_BUG_ON(ARRAY_SIZE(hvm_hypercall_table) >
                 ARRAY_SIZE(hypercall_args_table));

    if ( eax >= ARRAY_SIZE(hvm_hypercall_table) )
    {
        regs->rax = -ENOSYS;
        return HVM_HCALL_completed;
    }

    eax = array_index_nospec(eax, ARRAY_SIZE(hvm_hypercall_table));

    if ( !hvm_hypercall_table[eax].native )
    {
        regs->rax = -ENOSYS;
        return HVM_HCALL_completed;
    }

    /*
     * Caching is intended for instruction emulation only. Disable it
     * for any accesses by hypercall argument copy-in / copy-out.
     */
    token = hvmemul_cache_disable(curr);

    curr->hcall_preempted = false;

    if ( mode == 8 )
    {
        unsigned long rdi = regs->rdi;
        unsigned long rsi = regs->rsi;
        unsigned long rdx = regs->rdx;
        unsigned long r10 = regs->r10;
        unsigned long r8 = regs->r8;
        unsigned long r9 = regs->r9;

        HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%lu(%lx, %lx, %lx, %lx, %lx, %lx)",
                    eax, rdi, rsi, rdx, r10, r8, r9);

#ifndef NDEBUG
        /* Deliberately corrupt parameter regs not used by this hypercall. */
        switch ( hypercall_args_table[eax].native )
        {
        case 0: rdi = 0xdeadbeefdeadf00dUL;
        case 1: rsi = 0xdeadbeefdeadf00dUL;
        case 2: rdx = 0xdeadbeefdeadf00dUL;
        case 3: r10 = 0xdeadbeefdeadf00dUL;
        case 4: r8 = 0xdeadbeefdeadf00dUL;
        case 5: r9 = 0xdeadbeefdeadf00dUL;
        }
#endif

        regs->rax = hvm_hypercall_table[eax].native(rdi, rsi, rdx, r10, r8,
                                                    r9);

#ifndef NDEBUG
        if ( !curr->hcall_preempted )
        {
            /* Deliberately corrupt parameter regs used by this hypercall. */
            switch ( hypercall_args_table[eax].native )
            {
            case 6: regs->r9  = 0xdeadbeefdeadf00dUL;
            case 5: regs->r8  = 0xdeadbeefdeadf00dUL;
            case 4: regs->r10 = 0xdeadbeefdeadf00dUL;
            case 3: regs->rdx = 0xdeadbeefdeadf00dUL;
            case 2: regs->rsi = 0xdeadbeefdeadf00dUL;
            case 1: regs->rdi = 0xdeadbeefdeadf00dUL;
            }
        }
#endif
    }
    else
    {
        unsigned int ebx = regs->ebx;
        unsigned int ecx = regs->ecx;
        unsigned int edx = regs->edx;
        unsigned int esi = regs->esi;
        unsigned int edi = regs->edi;
        unsigned int ebp = regs->ebp;

        HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%lu(%x, %x, %x, %x, %x, %x)", eax,
                    ebx, ecx, edx, esi, edi, ebp);

#ifndef NDEBUG
        /* Deliberately corrupt parameter regs not used by this hypercall. */
        switch ( hypercall_args_table[eax].compat )
        {
        case 0: ebx = 0xdeadf00d;
        case 1: ecx = 0xdeadf00d;
        case 2: edx = 0xdeadf00d;
        case 3: esi = 0xdeadf00d;
        case 4: edi = 0xdeadf00d;
        case 5: ebp = 0xdeadf00d;
        }
#endif

        curr->hcall_compat = true;
        regs->rax = hvm_hypercall_table[eax].compat(ebx, ecx, edx, esi, edi,
                                                    ebp);
        curr->hcall_compat = false;

#ifndef NDEBUG
        if ( !curr->hcall_preempted )
        {
            /* Deliberately corrupt parameter regs used by this hypercall. */
            switch ( hypercall_args_table[eax].compat )
            {
            case 6: regs->rbp = 0xdeadf00d;
            case 5: regs->rdi = 0xdeadf00d;
            case 4: regs->rsi = 0xdeadf00d;
            case 3: regs->rdx = 0xdeadf00d;
            case 2: regs->rcx = 0xdeadf00d;
            case 1: regs->rbx = 0xdeadf00d;
            }
        }
#endif
    }

    hvmemul_cache_restore(curr, token);

    HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%lu -> %lx", eax, regs->rax);

    if ( curr->hcall_preempted )
        return HVM_HCALL_preempted;

    if ( unlikely(currd->arch.hvm.qemu_mapcache_invalidate) &&
         test_and_clear_bool(currd->arch.hvm.qemu_mapcache_invalidate) )
        send_invalidate_req();

    return HVM_HCALL_completed;
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
