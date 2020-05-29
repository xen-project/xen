/******************************************************************************
 * arch/x86/hypercall.c
 *
 * Common x86 hypercall infrastructure.
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
 * Copyright (c) 2015,2016 Citrix Systems Ltd.
 */

#include <xen/hypercall.h>

#define ARGS(x, n)                              \
    [ __HYPERVISOR_ ## x ] = { n, n }
#define COMP(x, n, c)                           \
    [ __HYPERVISOR_ ## x ] = { n, c }

const hypercall_args_t hypercall_args_table[NR_hypercalls] =
{
    ARGS(set_trap_table, 1),
    ARGS(mmu_update, 4),
    ARGS(set_gdt, 2),
    ARGS(stack_switch, 2),
    COMP(set_callbacks, 3, 4),
    ARGS(fpu_taskswitch, 1),
    ARGS(sched_op_compat, 2),
    ARGS(platform_op, 1),
    ARGS(set_debugreg, 2),
    ARGS(get_debugreg, 1),
    COMP(update_descriptor, 2, 4),
    ARGS(memory_op, 2),
    ARGS(multicall, 2),
    COMP(update_va_mapping, 3, 4),
    COMP(set_timer_op, 1, 2),
    ARGS(event_channel_op_compat, 1),
    ARGS(xen_version, 2),
    ARGS(console_io, 3),
    ARGS(physdev_op_compat, 1),
#ifdef CONFIG_GRANT_TABLE
    ARGS(grant_table_op, 3),
#endif
    ARGS(vm_assist, 2),
    COMP(update_va_mapping_otherdomain, 4, 5),
    ARGS(vcpu_op, 3),
    COMP(set_segment_base, 2, 0),
    ARGS(mmuext_op, 4),
    ARGS(xsm_op, 1),
    ARGS(nmi_op, 2),
    ARGS(sched_op, 2),
    ARGS(callback_op, 2),
    ARGS(xenoprof_op, 2),
    ARGS(event_channel_op, 2),
    ARGS(physdev_op, 2),
    ARGS(sysctl, 1),
    ARGS(domctl, 1),
    ARGS(kexec_op, 2),
#ifdef CONFIG_ARGO
    ARGS(argo_op, 5),
#endif
    ARGS(xenpmu_op, 2),
#ifdef CONFIG_HVM
    ARGS(hvm_op, 2),
    ARGS(dm_op, 3),
#endif
#ifdef CONFIG_HYPFS
    ARGS(hypfs_op, 5),
#endif
    ARGS(mca, 1),
    ARGS(arch_1, 1),
};

#undef COMP
#undef ARGS

#define NEXT_ARG(fmt, args)                                                 \
({                                                                          \
    unsigned long __arg;                                                    \
    switch ( *(fmt)++ )                                                     \
    {                                                                       \
    case 'i': __arg = (unsigned long)va_arg(args, unsigned int);  break;    \
    case 'l': __arg = (unsigned long)va_arg(args, unsigned long); break;    \
    case 'h': __arg = (unsigned long)va_arg(args, void *);        break;    \
    default:  goto bad_fmt;                                                 \
    }                                                                       \
    __arg;                                                                  \
})

unsigned long hypercall_create_continuation(
    unsigned int op, const char *format, ...)
{
    struct vcpu *curr = current;
    struct mc_state *mcs = &curr->mc_state;
    const char *p = format;
    unsigned long arg;
    unsigned int i;
    va_list args;

    curr->hcall_preempted = true;

    va_start(args, format);

    if ( mcs->flags & MCSF_in_multicall )
    {
        for ( i = 0; *p != '\0'; i++ )
            mcs->call.args[i] = NEXT_ARG(p, args);
    }
    else
    {
        struct cpu_user_regs *regs = guest_cpu_user_regs();

        regs->rax = op;

        if ( !curr->hcall_compat )
        {
            for ( i = 0; *p != '\0'; i++ )
            {
                arg = NEXT_ARG(p, args);
                switch ( i )
                {
                case 0: regs->rdi = arg; break;
                case 1: regs->rsi = arg; break;
                case 2: regs->rdx = arg; break;
                case 3: regs->r10 = arg; break;
                case 4: regs->r8  = arg; break;
                case 5: regs->r9  = arg; break;
                }
            }
        }
        else
        {
            for ( i = 0; *p != '\0'; i++ )
            {
                arg = NEXT_ARG(p, args);
                switch ( i )
                {
                case 0: regs->rbx = arg; break;
                case 1: regs->rcx = arg; break;
                case 2: regs->rdx = arg; break;
                case 3: regs->rsi = arg; break;
                case 4: regs->rdi = arg; break;
                case 5: regs->rbp = arg; break;
                }
            }
        }
    }

    va_end(args);

    return op;

 bad_fmt:
    va_end(args);
    gprintk(XENLOG_ERR, "Bad hypercall continuation format '%c'\n", *p);
    ASSERT_UNREACHABLE();
    domain_crash(curr->domain);
    return 0;
}

#undef NEXT_ARG

void arch_hypercall_tasklet_result(struct vcpu *v, long res)
{
    struct cpu_user_regs *regs = &v->arch.user_regs;

    regs->rax = res;
}

int hypercall_xlat_continuation(unsigned int *id, unsigned int nr,
                                unsigned int mask, ...)
{
    int rc = 0;
    struct mc_state *mcs = &current->mc_state;
    struct cpu_user_regs *regs;
    unsigned int i, cval = 0;
    unsigned long nval = 0;
    va_list args;

    ASSERT(nr <= ARRAY_SIZE(mcs->call.args));
    ASSERT(!(mask >> nr));
    ASSERT(!id || *id < nr);
    ASSERT(!id || !(mask & (1U << *id)));

    va_start(args, mask);

    if ( mcs->flags & MCSF_in_multicall )
    {
        if ( !current->hcall_preempted )
        {
            va_end(args);
            return 0;
        }

        for ( i = 0; i < nr; ++i, mask >>= 1 )
        {
            if ( mask & 1 )
            {
                nval = va_arg(args, unsigned long);
                cval = va_arg(args, unsigned int);
                if ( cval == nval )
                    mask &= ~1U;
                else
                    BUG_ON(nval == (unsigned int)nval);
            }
            else if ( id && *id == i )
            {
                *id = mcs->call.args[i];
                id = NULL;
            }
            if ( (mask & 1) && mcs->call.args[i] == nval )
            {
                mcs->call.args[i] = cval;
                ++rc;
            }
            else
                BUG_ON(mcs->call.args[i] != (unsigned int)mcs->call.args[i]);
        }
    }
    else
    {
        regs = guest_cpu_user_regs();
        for ( i = 0; i < nr; ++i, mask >>= 1 )
        {
            unsigned long *reg;

            switch ( i )
            {
            case 0: reg = &regs->rbx; break;
            case 1: reg = &regs->rcx; break;
            case 2: reg = &regs->rdx; break;
            case 3: reg = &regs->rsi; break;
            case 4: reg = &regs->rdi; break;
            case 5: reg = &regs->rbp; break;
            default: BUG(); reg = NULL; break;
            }
            if ( (mask & 1) )
            {
                nval = va_arg(args, unsigned long);
                cval = va_arg(args, unsigned int);
                if ( cval == nval )
                    mask &= ~1U;
                else
                    BUG_ON(nval == (unsigned int)nval);
            }
            else if ( id && *id == i )
            {
                *id = *reg;
                id = NULL;
            }
            if ( (mask & 1) && *reg == nval )
            {
                *reg = cval;
                ++rc;
            }
            else
                BUG_ON(*reg != (unsigned int)*reg);
        }
    }

    va_end(args);

    return rc;
}

#ifndef CONFIG_PV
/* Stub for arch_do_multicall_call */
enum mc_disposition arch_do_multicall_call(struct mc_state *mc)
{
    return mc_exit;
}
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

