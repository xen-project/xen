/******************************************************************************
 * sysctl.c
 * 
 * System management operations. For use by node control stack.
 * 
 * Copyright (c) 2002-2006, K Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <public/sysctl.h>

extern long arch_do_sysctl(
    struct xen_sysctl *op, XEN_GUEST_HANDLE(xen_sysctl_t) u_sysctl);

long do_sysctl(XEN_GUEST_HANDLE(xen_sysctl_t) u_sysctl)
{
    long ret = 0;
    struct xen_sysctl curop, *op = &curop;
    static DEFINE_SPINLOCK(sysctl_lock);

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( copy_from_guest(op, u_sysctl, 1) )
        return -EFAULT;

    if ( op->interface_version != XEN_SYSCTL_INTERFACE_VERSION )
        return -EACCES;

    spin_lock(&sysctl_lock);

    switch ( op->cmd )
    {
    case XEN_SYSCTL_readconsole:
    {
        ret = read_console_ring(
            guest_handle_cast(op->u.readconsole.buffer, char),
            &op->u.readconsole.count,
            op->u.readconsole.clear);
        if ( copy_to_guest(u_sysctl, op, 1) )
            ret = -EFAULT;
    }
    break;

    case XEN_SYSCTL_tbuf_op:
    {
        ret = tb_control(&op->u.tbuf_op);
        if ( copy_to_guest(u_sysctl, op, 1) )
            ret = -EFAULT;
    }
    break;
    
    case XEN_SYSCTL_sched_id:
    {
        op->u.sched_id.sched_id = sched_id();
        if ( copy_to_guest(u_sysctl, op, 1) )
            ret = -EFAULT;
        else
            ret = 0;
    }
    break;

    case XEN_SYSCTL_getdomaininfolist:
    { 
        struct domain *d;
        struct xen_domctl_getdomaininfo info;
        u32 num_domains = 0;

        rcu_read_lock(&domlist_read_lock);

        for_each_domain ( d )
        {
            if ( d->domain_id < op->u.getdomaininfolist.first_domain )
                continue;
            if ( num_domains == op->u.getdomaininfolist.max_domains )
                break;

            getdomaininfo(d, &info);

            if ( copy_to_guest_offset(op->u.getdomaininfolist.buffer,
                                      num_domains, &info, 1) )
            {
                ret = -EFAULT;
                break;
            }
            
            num_domains++;
        }
        
        rcu_read_unlock(&domlist_read_lock);
        
        if ( ret != 0 )
            break;
        
        op->u.getdomaininfolist.num_domains = num_domains;

        if ( copy_to_guest(u_sysctl, op, 1) )
            ret = -EFAULT;
    }
    break;

#ifdef PERF_COUNTERS
    case XEN_SYSCTL_perfc_op:
    {
        ret = perfc_control(&op->u.perfc_op);
        if ( copy_to_guest(u_sysctl, op, 1) )
            ret = -EFAULT;
    }
    break;
#endif

    default:
        ret = arch_do_sysctl(op, u_sysctl);
        break;
    }

    spin_unlock(&sysctl_lock);

    return ret;
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
