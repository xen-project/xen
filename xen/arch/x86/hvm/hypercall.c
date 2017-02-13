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

#include <asm/hvm/support.h>

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

    if ( curr->arch.hvm_vcpu.hcall_64bit )
        rc = do_memory_op(cmd, arg);
    else
        rc = compat_memory_op(cmd, arg);

    if ( (cmd & MEMOP_CMD_MASK) == XENMEM_decrease_reservation )
        curr->domain->arch.hvm_domain.qemu_mapcache_invalidate = true;

    return rc;
}

static int grant_table_op_is_allowed(unsigned int cmd)
{
    switch (cmd) {
    case GNTTABOP_query_size:
    case GNTTABOP_setup_table:
    case GNTTABOP_set_version:
    case GNTTABOP_get_version:
    case GNTTABOP_copy:
    case GNTTABOP_map_grant_ref:
    case GNTTABOP_unmap_grant_ref:
    case GNTTABOP_swap_grant_ref:
        return 1;
    default:
        /* all other commands need auditing */
        return 0;
    }
}

static long hvm_grant_table_op(
    unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) uop, unsigned int count)
{
    if ( !grant_table_op_is_allowed(cmd) )
        return -ENOSYS; /* all other commands need auditing */
    return do_grant_table_op(cmd, uop, count);
}

static long hvm_physdev_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    switch ( cmd )
    {
    default:
        if ( !is_pvh_vcpu(current) || !is_hardware_domain(current->domain) )
            return -ENOSYS;
        /* fall through */
    case PHYSDEVOP_map_pirq:
    case PHYSDEVOP_unmap_pirq:
    case PHYSDEVOP_eoi:
    case PHYSDEVOP_irq_status_query:
    case PHYSDEVOP_get_free_pirq:
        return do_physdev_op(cmd, arg);
    }
}

static long hvm_grant_table_op_compat32(unsigned int cmd,
                                        XEN_GUEST_HANDLE_PARAM(void) uop,
                                        unsigned int count)
{
    if ( !grant_table_op_is_allowed(cmd) )
        return -ENOSYS;
    return compat_grant_table_op(cmd, uop, count);
}

static long hvm_physdev_op_compat32(
    int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    switch ( cmd )
    {
        case PHYSDEVOP_map_pirq:
        case PHYSDEVOP_unmap_pirq:
        case PHYSDEVOP_eoi:
        case PHYSDEVOP_irq_status_query:
        case PHYSDEVOP_get_free_pirq:
            return compat_physdev_op(cmd, arg);
        break;
    default:
            return -ENOSYS;
        break;
    }
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

#define do_physdev_op         hvm_physdev_op
#define compat_physdev_op     hvm_physdev_op_compat32
#define do_grant_table_op     hvm_grant_table_op
#define compat_grant_table_op hvm_grant_table_op_compat32
#define do_arch_1             paging_domctl_continuation

static const hypercall_table_t hvm_hypercall_table[] = {
    HVM_CALL(memory_op),
    COMPAT_CALL(grant_table_op),
    COMPAT_CALL(vcpu_op),
    COMPAT_CALL(physdev_op),
    COMPAT_CALL(xen_version),
    HYPERCALL(console_io),
    HYPERCALL(event_channel_op),
    COMPAT_CALL(sched_op),
    COMPAT_CALL(set_timer_op),
    HYPERCALL(xsm_op),
    HYPERCALL(hvm_op),
    HYPERCALL(sysctl),
    HYPERCALL(domctl),
#ifdef CONFIG_TMEM
    HYPERCALL(tmem_op),
#endif
    COMPAT_CALL(platform_op),
    COMPAT_CALL(mmuext_op),
    HYPERCALL(xenpmu_op),
    COMPAT_CALL(dm_op),
    HYPERCALL(arch_1)
};

#undef do_physdev_op
#undef compat_physdev_op
#undef do_grant_table_op
#undef compat_grant_table_op
#undef do_arch_1

#undef HYPERCALL
#undef HVM_CALL
#undef COMPAT_CALL

int hvm_hypercall(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    int mode = hvm_guest_x86_mode(curr);
    unsigned long eax = regs->_eax;

    switch ( mode )
    {
    case 8:
        eax = regs->rax;
        /* Fallthrough to permission check. */
    case 4:
    case 2:
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
        return viridian_hypercall(regs);

    BUILD_BUG_ON(ARRAY_SIZE(hvm_hypercall_table) >
                 ARRAY_SIZE(hypercall_args_table));

    if ( (eax >= ARRAY_SIZE(hvm_hypercall_table)) ||
         !hvm_hypercall_table[eax].native )
    {
        regs->rax = -ENOSYS;
        return HVM_HCALL_completed;
    }

    curr->arch.hvm_vcpu.hcall_preempted = 0;

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

        curr->arch.hvm_vcpu.hcall_64bit = 1;
        regs->rax = hvm_hypercall_table[eax].native(rdi, rsi, rdx, r10, r8,
                                                    r9);

        curr->arch.hvm_vcpu.hcall_64bit = 0;

#ifndef NDEBUG
        if ( !curr->arch.hvm_vcpu.hcall_preempted )
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
        unsigned int ebx = regs->_ebx;
        unsigned int ecx = regs->_ecx;
        unsigned int edx = regs->_edx;
        unsigned int esi = regs->_esi;
        unsigned int edi = regs->_edi;
        unsigned int ebp = regs->_ebp;

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

        regs->rax = hvm_hypercall_table[eax].compat(ebx, ecx, edx, esi, edi,
                                                    ebp);

#ifndef NDEBUG
        if ( !curr->arch.hvm_vcpu.hcall_preempted )
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

    HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%lu -> %lx", eax, regs->rax);

    if ( curr->arch.hvm_vcpu.hcall_preempted )
        return HVM_HCALL_preempted;

    if ( unlikely(currd->arch.hvm_domain.qemu_mapcache_invalidate) &&
         test_and_clear_bool(currd->arch.hvm_domain.qemu_mapcache_invalidate) )
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
