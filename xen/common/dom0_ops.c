/******************************************************************************
 * dom0_ops.c
 * 
 * Process command requests from domain-0 guest OS.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <public/dom0_ops.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <asm/domain_page.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <asm/shadow.h>
#include <public/sched_ctl.h>

#define TRC_DOM0OP_ENTER_BASE  0x00020000
#define TRC_DOM0OP_LEAVE_BASE  0x00030000

extern unsigned int alloc_new_dom_mem(struct domain *, unsigned int);
extern long arch_do_dom0_op(dom0_op_t *op, dom0_op_t *u_dom0_op);
extern void arch_getdomaininfo_ctxt(
    struct exec_domain *, full_execution_context_t *);

static inline int is_free_domid(domid_t dom)
{
    struct domain *d;

    if ( dom >= DOMID_FIRST_RESERVED )
        return 0;

    if ( (d = find_domain_by_id(dom)) == NULL )
        return 1;

    put_domain(d);
    return 0;
}

/*
 * Allocate a free domain id. We try to reuse domain ids in a fairly low range,
 * only expanding the range when there are no free domain ids. This is to keep 
 * domain ids in a range depending on the number that exist simultaneously,
 * rather than incrementing domain ids in the full 32-bit range.
 */
static int allocate_domid(domid_t *pdom)
{
    static spinlock_t domid_lock = SPIN_LOCK_UNLOCKED;
    static domid_t curdom = 0;
    static domid_t topdom = 101;
    int err = 0;
    domid_t dom;

    spin_lock(&domid_lock);

    /* Try to use a domain id in the range 0..topdom, starting at curdom. */
    for ( dom = curdom + 1; dom != curdom; dom++ )
    {
        if ( dom == topdom )
            dom = 1;
        if ( is_free_domid(dom) )
            goto exit;
    }

    /* Couldn't find a free domain id in 0..topdom, try higher. */
    for ( dom = topdom; dom < DOMID_FIRST_RESERVED; dom++ )
    {
        if ( is_free_domid(dom) )
        {
            topdom = dom + 1;
            goto exit;
        }
    }

    /* No free domain ids. */
    err = -ENOMEM;

  exit:
    if ( err == 0 )
    {
        curdom = dom;
        *pdom = dom;
    }

    spin_unlock(&domid_lock);
    return err;
}

long do_dom0_op(dom0_op_t *u_dom0_op)
{
    long ret = 0;
    dom0_op_t curop, *op = &curop;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( copy_from_user(op, u_dom0_op, sizeof(*op)) )
        return -EFAULT;

    if ( op->interface_version != DOM0_INTERFACE_VERSION )
        return -EACCES;

    TRACE_5D(TRC_DOM0OP_ENTER_BASE + op->cmd, 
             0, op->u.dummy[0], op->u.dummy[1], 
             op->u.dummy[2], op->u.dummy[3] );

    switch ( op->cmd )
    {

    case DOM0_BUILDDOMAIN:
    {
        struct domain *d = find_domain_by_id(op->u.builddomain.domain);
        ret = -EINVAL;
        if ( d != NULL )
        {
            ret = final_setup_guest(d, &op->u.builddomain);
            put_domain(d);
        }
    }
    break;

    case DOM0_PAUSEDOMAIN:
    {
        struct domain *d = find_domain_by_id(op->u.pausedomain.domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = -EINVAL;
            if ( d != current->domain )
            {
                domain_pause_by_systemcontroller(d);
                ret = 0;
            }
            put_domain(d);
        }
    }
    break;

    case DOM0_UNPAUSEDOMAIN:
    {
        struct domain *d = find_domain_by_id(op->u.unpausedomain.domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = -EINVAL;
            if ( test_bit(DF_CONSTRUCTED, &d->d_flags) )
            {
                domain_unpause_by_systemcontroller(d);
                ret = 0;
            }
            put_domain(d);
        }
    }
    break;

    case DOM0_CREATEDOMAIN:
    {
        struct domain *d;
        unsigned int   pro = 0;
        domid_t        dom;

        dom = op->u.createdomain.domain;
        if ( (dom > 0) && (dom < DOMID_FIRST_RESERVED) )
        {
            ret = -EINVAL;
            if ( !is_free_domid(dom) )
                break;
        }
        else if ( (ret = allocate_domid(&dom)) != 0 )
            break;

        if ( op->u.createdomain.cpu == -1 )
        {
            /* Do an initial placement. Pick the least-populated CPU. */
            struct domain *d;
            struct exec_domain *ed;
            unsigned int i, cnt[NR_CPUS] = { 0 };

            read_lock(&domlist_lock);
            for_each_domain ( d ) {
                for_each_exec_domain ( d, ed )
                    cnt[ed->processor]++;
            }
            read_unlock(&domlist_lock);

            for ( i = 0; i < smp_num_cpus; i++ )
                if ( cnt[i] < cnt[pro] )
                    pro = i;
        }
        else
            pro = op->u.createdomain.cpu % smp_num_cpus;

        ret = -ENOMEM;
        if ( (d = do_createdomain(dom, pro)) == NULL )
            break;

        ret = alloc_new_dom_mem(d, op->u.createdomain.memory_kb);
        if ( ret != 0 ) 
        {
            domain_kill(d);
            break;
        }

        ret = 0;
        
        op->u.createdomain.domain = d->id;
        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;

    case DOM0_DESTROYDOMAIN:
    {
        struct domain *d = find_domain_by_id(op->u.destroydomain.domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = -EINVAL;
            if ( d != current->domain )
            {
                domain_kill(d);
                ret = 0;
            }
            put_domain(d);
        }
    }
    break;

    case DOM0_PINCPUDOMAIN:
    {
        domid_t dom = op->u.pincpudomain.domain;
        struct domain *d = find_domain_by_id(dom);
        struct exec_domain *ed;
        int cpu = op->u.pincpudomain.cpu;

        if ( d == NULL )
        {
            ret = -ESRCH;            
            break;
        }
        
        ed = d->exec_domain[op->u.pincpudomain.exec_domain];
        if ( ed == NULL )
        {
            ret = -ESRCH;
            put_domain(d);
            break;
        }

        if ( ed == current )
        {
            ret = -EINVAL;
            put_domain(d);
            break;
        }

        if ( cpu == -1 )
        {
            clear_bit(EDF_CPUPINNED, &ed->ed_flags);
        }
        else
        {
            exec_domain_pause(ed);
            synchronise_pagetables(~0UL);
            if ( ed->processor != (cpu % smp_num_cpus) )
                set_bit(EDF_MIGRATED, &ed->ed_flags);
            set_bit(EDF_CPUPINNED, &ed->ed_flags);
            ed->processor = cpu % smp_num_cpus;
            exec_domain_unpause(ed);
        }

        put_domain(d);
    }
    break;

    case DOM0_SCHEDCTL:
    {
        ret = sched_ctl(&op->u.schedctl);
        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;

    case DOM0_ADJUSTDOM:
    {
        ret = sched_adjdom(&op->u.adjustdom);
        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;

    case DOM0_GETDOMAININFO:
    { 
        full_execution_context_t *c;
        struct domain            *d;
        struct exec_domain       *ed;

        read_lock(&domlist_lock);

        for_each_domain ( d )
        {
            if ( d->id >= op->u.getdomaininfo.domain )
                break;
        }

        if ( (d == NULL) || !get_domain(d) )
        {
            read_unlock(&domlist_lock);
            ret = -ESRCH;
            break;
        }

        read_unlock(&domlist_lock);

        op->u.getdomaininfo.domain = d->id;

        if ( (op->u.getdomaininfo.exec_domain >= MAX_VIRT_CPUS) ||
             !d->exec_domain[op->u.getdomaininfo.exec_domain] )
        {
            ret = -EINVAL;
            break;
        }
        
        ed = d->exec_domain[op->u.getdomaininfo.exec_domain];

        op->u.getdomaininfo.flags =
            (test_bit( DF_DYING,      &d->d_flags)  ? DOMFLAGS_DYING    : 0) |
            (test_bit( DF_CRASHED,    &d->d_flags)  ? DOMFLAGS_CRASHED  : 0) |
            (test_bit( DF_SHUTDOWN,   &d->d_flags)  ? DOMFLAGS_SHUTDOWN : 0) |
            (test_bit(EDF_CTRLPAUSE, &ed->ed_flags) ? DOMFLAGS_PAUSED   : 0) |
            (test_bit(EDF_BLOCKED,   &ed->ed_flags) ? DOMFLAGS_BLOCKED  : 0) |
            (test_bit(EDF_RUNNING,   &ed->ed_flags) ? DOMFLAGS_RUNNING  : 0);

        op->u.getdomaininfo.flags |= ed->processor << DOMFLAGS_CPUSHIFT;
        op->u.getdomaininfo.flags |= 
            d->shutdown_code << DOMFLAGS_SHUTDOWNSHIFT;

        op->u.getdomaininfo.tot_pages   = d->tot_pages;
        op->u.getdomaininfo.max_pages   = d->max_pages;
        op->u.getdomaininfo.cpu_time    = ed->cpu_time;
        op->u.getdomaininfo.shared_info_frame = 
            __pa(d->shared_info) >> PAGE_SHIFT;

        if ( op->u.getdomaininfo.ctxt != NULL )
        {
            if ( (c = xmalloc(full_execution_context_t)) == NULL )
            {
                ret = -ENOMEM;
                put_domain(d);
                break;
            }

            if ( ed != current )
                exec_domain_pause(ed);

            arch_getdomaininfo_ctxt(ed,c);

            if ( ed != current )
                exec_domain_unpause(ed);

            if ( copy_to_user(op->u.getdomaininfo.ctxt, c, sizeof(*c)) )
                ret = -EINVAL;

            if ( c != NULL )
                xfree(c);
        }

        if ( copy_to_user(u_dom0_op, op, sizeof(*op)) )     
            ret = -EINVAL;

        put_domain(d);
    }
    break;

    case DOM0_SETTIME:
    {
        do_settime(op->u.settime.secs, 
                   op->u.settime.usecs, 
                   op->u.settime.system_time);
        ret = 0;
    }
    break;

#ifdef TRACE_BUFFER
    case DOM0_GETTBUFS:
    {
        ret = get_tb_info(&op->u.gettbufs);
        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;
#endif
    
    case DOM0_READCONSOLE:
    {
        ret = read_console_ring(op->u.readconsole.str, 
                                op->u.readconsole.count,
                                op->u.readconsole.cmd); 
    }
    break;

    case DOM0_PCIDEV_ACCESS:
    {
        extern int physdev_pci_access_modify(domid_t, int, int, int, int);
        ret = physdev_pci_access_modify(op->u.pcidev_access.domain, 
                                        op->u.pcidev_access.bus,
                                        op->u.pcidev_access.dev,
                                        op->u.pcidev_access.func,
                                        op->u.pcidev_access.enable);
    }
    break;

    case DOM0_SCHED_ID:
    {
        op->u.sched_id.sched_id = sched_id();
        copy_to_user(u_dom0_op, op, sizeof(*op));
        ret = 0;        
    }
    break;

    case DOM0_SETDOMAININITIALMEM:
    {
        struct domain *d; 
        ret = -ESRCH;
        d = find_domain_by_id(op->u.setdomaininitialmem.domain);
        if ( d != NULL )
        { 
            /* should only be used *before* domain is built. */
            if ( !test_bit(DF_CONSTRUCTED, &d->d_flags) )
                ret = alloc_new_dom_mem( 
                    d, op->u.setdomaininitialmem.initial_memkb );
            else
                ret = -EINVAL;
            put_domain(d);
        }
    }
    break;

    case DOM0_SETDOMAINMAXMEM:
    {
        struct domain *d; 
        ret = -ESRCH;
        d = find_domain_by_id( op->u.setdomainmaxmem.domain );
        if ( d != NULL )
        {
            d->max_pages = 
                (op->u.setdomainmaxmem.max_memkb+PAGE_SIZE-1)>> PAGE_SHIFT;
            put_domain(d);
            ret = 0;
        }
    }
    break;

    case DOM0_SETDOMAINVMASSIST:
    {
        struct domain *d; 
        ret = -ESRCH;
        d = find_domain_by_id( op->u.setdomainvmassist.domain );
        if ( d != NULL )
        {
            vm_assist(d, op->u.setdomainvmassist.cmd,
                      op->u.setdomainvmassist.type);
            put_domain(d);
            ret = 0;
        }
    }
    break;

#ifdef PERF_COUNTERS
    case DOM0_PERFCCONTROL:
    {
        extern int perfc_control(dom0_perfccontrol_t *);
        ret = perfc_control(&op->u.perfccontrol);
        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;
#endif

    default:
        ret = arch_do_dom0_op(op,u_dom0_op);

    }

    TRACE_5D(TRC_DOM0OP_LEAVE_BASE + op->cmd, ret,
             op->u.dummy[0], op->u.dummy[1], op->u.dummy[2], op->u.dummy[3]);


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
