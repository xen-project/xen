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
#include <asm/pdb.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <asm/shadow.h>
#include <public/sched_ctl.h>

#define TRC_DOM0OP_ENTER_BASE  0x00020000
#define TRC_DOM0OP_LEAVE_BASE  0x00030000

extern unsigned int alloc_new_dom_mem(struct domain *, unsigned int);
extern long arch_do_dom0_op(dom0_op_t *op, dom0_op_t *u_dom0_op);
extern void arch_getdomaininfo_ctxt(
    struct domain *, full_execution_context_t *);

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

    if ( !IS_PRIV(current) )
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
            ret = final_setup_guestos(d, &op->u.builddomain);
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
            if ( d != current )
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
            if ( test_bit(DF_CONSTRUCTED, &d->flags) )
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
            unsigned int i, cnt[NR_CPUS] = { 0 };

            read_lock(&domlist_lock);
            for_each_domain ( d )
                cnt[d->processor]++;
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
            if ( d != current )
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
        int cpu = op->u.pincpudomain.cpu;

        if ( d == NULL )
        {
            ret = -ESRCH;            
            break;
        }
        
        if ( d == current )
        {
            ret = -EINVAL;
            put_domain(d);
            break;
        }

        if ( cpu == -1 )
        {
            clear_bit(DF_CPUPINNED, &d->flags);
        }
        else
        {
            domain_pause(d);
            synchronise_pagetables(~0UL);
            if ( d->processor != (cpu % smp_num_cpus) )
                set_bit(DF_MIGRATED, &d->flags);
            set_bit(DF_CPUPINNED, &d->flags);
            d->processor = cpu % smp_num_cpus;
            domain_unpause(d);
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

    case DOM0_GETMEMLIST:
    {
        int i;
        struct domain *d = find_domain_by_id(op->u.getmemlist.domain);
        unsigned long max_pfns = op->u.getmemlist.max_pfns;
        unsigned long pfn;
        unsigned long *buffer = op->u.getmemlist.buffer;
        struct list_head *list_ent;

        ret = -EINVAL;
        if ( d != NULL )
        {
            ret = 0;

            spin_lock(&d->page_alloc_lock);
            list_ent = d->page_list.next;
            for ( i = 0; (i < max_pfns) && (list_ent != &d->page_list); i++ )
            {
                pfn = list_entry(list_ent, struct pfn_info, list) - 
                    frame_table;
                if ( put_user(pfn, buffer) )
                {
                    ret = -EFAULT;
                    break;
                }
                buffer++;
                list_ent = frame_table[pfn].list.next;
            }
            spin_unlock(&d->page_alloc_lock);

            op->u.getmemlist.num_pfns = i;
            copy_to_user(u_dom0_op, op, sizeof(*op));
            
            put_domain(d);
        }
    }
    break;

    case DOM0_GETDOMAININFO:
    { 
        full_execution_context_t *c;
        struct domain            *d;

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
        
        op->u.getdomaininfo.flags =
            (test_bit(DF_DYING,     &d->flags) ? DOMFLAGS_DYING    : 0) |
            (test_bit(DF_CRASHED,   &d->flags) ? DOMFLAGS_CRASHED  : 0) |
            (test_bit(DF_SHUTDOWN,  &d->flags) ? DOMFLAGS_SHUTDOWN : 0) |
            (test_bit(DF_CTRLPAUSE, &d->flags) ? DOMFLAGS_PAUSED   : 0) |
            (test_bit(DF_BLOCKED,   &d->flags) ? DOMFLAGS_BLOCKED  : 0) |
            (test_bit(DF_RUNNING,   &d->flags) ? DOMFLAGS_RUNNING  : 0);

        op->u.getdomaininfo.flags |= d->processor << DOMFLAGS_CPUSHIFT;
        op->u.getdomaininfo.flags |= 
            d->shutdown_code << DOMFLAGS_SHUTDOWNSHIFT;

        op->u.getdomaininfo.tot_pages   = d->tot_pages;
        op->u.getdomaininfo.max_pages   = d->max_pages;
        op->u.getdomaininfo.cpu_time    = d->cpu_time;
        op->u.getdomaininfo.shared_info_frame = 
            __pa(d->shared_info) >> PAGE_SHIFT;

        if ( op->u.getdomaininfo.ctxt != NULL )
        {
            if ( (c = xmalloc(sizeof(*c))) == NULL )
            {
                ret = -ENOMEM;
                put_domain(d);
                break;
            }

            if ( d != current )
                domain_pause(d);

            arch_getdomaininfo_ctxt(d,c);

            if ( d != current )
                domain_unpause(d);

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

    case DOM0_GETPAGEFRAMEINFO:
    {
        struct pfn_info *page;
        unsigned long pfn = op->u.getpageframeinfo.pfn;
        domid_t dom = op->u.getpageframeinfo.domain;
        struct domain *d;

        ret = -EINVAL;

        if ( unlikely(pfn >= max_page) || 
             unlikely((d = find_domain_by_id(dom)) == NULL) )
            break;

        page = &frame_table[pfn];

        if ( likely(get_page(page, d)) )
        {
            ret = 0;

            op->u.getpageframeinfo.type = NOTAB;

            if ( (page->u.inuse.type_info & PGT_count_mask) != 0 )
            {
                switch ( page->u.inuse.type_info & PGT_type_mask )
                {
                case PGT_l1_page_table:
                    op->u.getpageframeinfo.type = L1TAB;
                    break;
                case PGT_l2_page_table:
                    op->u.getpageframeinfo.type = L2TAB;
                    break;
                case PGT_l3_page_table:
                    op->u.getpageframeinfo.type = L3TAB;
                    break;
                case PGT_l4_page_table:
                    op->u.getpageframeinfo.type = L4TAB;
                    break;
                }
            }
            
            put_page(page);
        }

        put_domain(d);

        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;

    case DOM0_IOPL:
    {
        extern long do_iopl(domid_t, unsigned int);
        ret = do_iopl(op->u.iopl.domain, op->u.iopl.iopl);
    }
    break;

#ifdef XEN_DEBUGGER
    case DOM0_DEBUG:
    {
        pdb_do_debug(op);
        copy_to_user(u_dom0_op, op, sizeof(*op));
        ret = 0;
    }
    break;
#endif

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

    case DOM0_PHYSINFO:
    {
        dom0_physinfo_t *pi = &op->u.physinfo;

        pi->ht_per_core = opt_noht ? 1 : ht_per_core;
        pi->cores       = smp_num_cpus / pi->ht_per_core;
        pi->total_pages = max_page;
        pi->free_pages  = avail_domheap_pages();
        pi->cpu_khz     = cpu_khz;

        copy_to_user(u_dom0_op, op, sizeof(*op));
        ret = 0;
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
            if ( !test_bit(DF_CONSTRUCTED, &d->flags) )
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

    case DOM0_GETPAGEFRAMEINFO2:
    {
#define GPF2_BATCH 128
        int n,j;
        int num = op->u.getpageframeinfo2.num;
        domid_t dom = op->u.getpageframeinfo2.domain;
        unsigned long *s_ptr = (unsigned long*) op->u.getpageframeinfo2.array;
        struct domain *d;
        unsigned long l_arr[GPF2_BATCH];
        ret = -ESRCH;

        if ( unlikely((d = find_domain_by_id(dom)) == NULL) )
            break;

        if ( unlikely(num > 1024) )
        {
            ret = -E2BIG;
            break;
        }
 
        ret = 0;
        for( n = 0; n < num; )
        {
            int k = ((num-n)>GPF2_BATCH)?GPF2_BATCH:(num-n);

            if ( copy_from_user(l_arr, &s_ptr[n], k*sizeof(unsigned long)) )
            {
                ret = -EINVAL;
                break;
            }
     
            for( j = 0; j < k; j++ )
            {      
                struct pfn_info *page;
                unsigned long mfn = l_arr[j];

                if ( unlikely(mfn >= max_page) )
                    goto e2_err;

                page = &frame_table[mfn];
  
                if ( likely(get_page(page, d)) )
                {
                    unsigned long type = 0;

                    switch( page->u.inuse.type_info & PGT_type_mask )
                    {
                    case PGT_l1_page_table:
                        type = L1TAB;
                        break;
                    case PGT_l2_page_table:
                        type = L2TAB;
                        break;
                    case PGT_l3_page_table:
                        type = L3TAB;
                        break;
                    case PGT_l4_page_table:
                        type = L4TAB;
                        break;
                    }

                    if ( page->u.inuse.type_info & PGT_pinned )
                        type |= LPINTAB;
                    l_arr[j] |= type;
                    put_page(page);
                }
                else
                {
                e2_err:
                    l_arr[j] |= XTAB;
                }

            }

            if ( copy_to_user(&s_ptr[n], l_arr, k*sizeof(unsigned long)) )
            {
                ret = -EINVAL;
                break;
            }

            n += j;
        }

        put_domain(d);
    }
    break;

    case DOM0_SETDOMAINVMASSIST:
    {
        struct domain *d; 
        ret = -ESRCH;
        d = find_domain_by_id( op->u.setdomainmaxmem.domain );
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
