/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/hypercall.c
 *
 * Common x86 hypercall infrastructure.
 *
 * Copyright (c) 2015,2016 Citrix Systems Ltd.
 */

#include <xen/hypercall.h>
#include <asm/multicall.h>

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
    /* SAF-4-safe allowed variadic function */
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

#ifdef CONFIG_COMPAT
        if ( !curr->hcall_compat )
#else
        if ( true )
#endif
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
    /* SAF-4-safe allowed variadic function */
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
                else if ( nval == (unsigned int)nval )
                    domain_crash(current->domain,
                                 "multicall (op %lu) bogus continuation arg%u (%#lx)\n",
                                 mcs->call.op, i, nval);
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
            else if ( mcs->call.args[i] != (unsigned int)mcs->call.args[i] )
                domain_crash(current->domain,
                             "multicall (op %lu) bad continuation arg%u (%#lx)\n",
                             mcs->call.op, i, mcs->call.args[i]);
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
                else if ( nval == (unsigned int)nval )
                    domain_crash(current->domain,
                                 "hypercall (op %u) bogus continuation arg%u (%#lx)\n",
                                 regs->eax, i, nval);
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
            else if ( *reg != (unsigned int)*reg )
                domain_crash(current->domain,
                             "hypercall (op %u) bad continuation arg%u (%#lx)\n",
                             regs->eax, i, *reg);
        }
    }

    va_end(args);

    return rc;
}

enum mc_disposition arch_do_multicall_call(struct mc_state *mcs)
{
    const struct domain *currd = current->domain;

    if ( is_pv_domain(currd) )
        return pv_do_multicall_call(mcs);

    if ( is_hvm_domain(currd) )
        return hvm_do_multicall_call(mcs);

    return mc_exit;
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

