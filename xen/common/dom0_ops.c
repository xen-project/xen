/******************************************************************************
 * dom0_ops.c
 * 
 * Process command requests from domain-0 guest OS.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <xeno/mm.h>
#include <hypervisor-ifs/dom0_ops.h>
#include <xeno/sched.h>
#include <xeno/event.h>
#include <asm/domain_page.h>
#include <asm/msr.h>

extern unsigned int alloc_new_dom_mem(struct task_struct *, unsigned int);

/* Basically used to protect the domain-id space. */
static spinlock_t create_dom_lock = SPIN_LOCK_UNLOCKED;

static unsigned int get_domnr(void)
{
    static unsigned int domnr = 0;
    struct task_struct *p;
    int tries = 0;

    for ( tries = 0; tries < 1024; tries++ )
    {
        domnr = (domnr+1) & ((1<<20)-1);
        if ( (p = find_domain_by_id(domnr)) == NULL )
            return domnr;
        put_task_struct(p);
    }

    return 0;
}

static void build_page_list(struct task_struct *p)
{
    unsigned long *list;
    unsigned long curr;
    struct list_head *list_ent;

    curr = list_entry(p->pg_head.next, struct pfn_info, list) - frame_table;
    list = (unsigned long *)map_domain_mem(curr << PAGE_SHIFT);

    list_for_each(list_ent, &p->pg_head)
    {
        *list++ = list_entry(list_ent, struct pfn_info, list) - frame_table;

        if( ((unsigned long)list & ~PAGE_MASK) == 0 )
        {
            struct list_head *ent = frame_table[curr].list.next;
            curr = list_entry(ent, struct pfn_info, list) - frame_table;
            unmap_domain_mem(list-1);
            list = (unsigned long *)map_domain_mem(curr << PAGE_SHIFT);
        }
    }

    unmap_domain_mem(list);
}

static int msr_cpu_mask;
static unsigned long msr_addr;
static unsigned long msr_lo;
static unsigned long msr_hi;

static void write_msr_for(void *unused)
{
    if (((1 << current->processor) & msr_cpu_mask))
        wrmsr(msr_addr, msr_lo, msr_hi);
}

static void read_msr_for(void *unused)
{
    if (((1 << current->processor) & msr_cpu_mask))
	rdmsr(msr_addr, msr_lo, msr_hi);
}

    
long do_dom0_op(dom0_op_t *u_dom0_op)
{
    long ret = 0;
    dom0_op_t op;

    if ( !IS_PRIV(current) )
        return -EPERM;

    if ( copy_from_user(&op, u_dom0_op, sizeof(op)) )
        return -EFAULT;

    if ( op.interface_version != DOM0_INTERFACE_VERSION )
        return -EINVAL;

    switch ( op.cmd )
    {

    case DOM0_BUILDDOMAIN:
    {
        struct task_struct * p = find_domain_by_id(op.u.builddomain.domain);
        ret = -EINVAL;
        if ( p != NULL )
        {
            if ( (ret = final_setup_guestos(p, &op.u.builddomain)) == 0 )
                ret = p->domain;
            put_task_struct(p);
        }
    }
    break;

    case DOM0_STARTDOMAIN:
    {
        struct task_struct * p = find_domain_by_id(op.u.startdomain.domain);
        ret = -EINVAL;
        if ( p != NULL )
        {
            if ( (p->flags & PF_CONSTRUCTED) != 0 )
            {
                wake_up(p);
                reschedule(p);
                ret = p->domain;
            }
            put_task_struct(p);
        }
    }
    break;

    case DOM0_STOPDOMAIN:
    {
        ret = stop_other_domain(op.u.stopdomain.domain);
    }
    break;

    case DOM0_CREATEDOMAIN:
    {
        struct task_struct *p;
        static unsigned int pro = 0;
        unsigned int dom;
        ret = -ENOMEM;
        
        spin_lock_irq(&create_dom_lock);
        
        if ( (dom = get_domnr()) == 0 ) 
            goto exit_create;

        pro = (pro+1) % smp_num_cpus;
        p = do_createdomain(dom, pro);
        if ( p == NULL ) 
            goto exit_create;

	if ( op.u.createdomain.name[0] )
        {
            strncpy (p->name, op.u.createdomain.name, MAX_DOMAIN_NAME);
            p->name[MAX_DOMAIN_NAME - 1] = 0;
	}

        ret = alloc_new_dom_mem(p, op.u.createdomain.memory_kb);
        if ( ret != 0 ) 
        {
            __kill_domain(p);
            goto exit_create;
        }

        build_page_list(p);
        
        ret = p->domain;
        
        op.u.createdomain.domain = ret;
        copy_to_user(u_dom0_op, &op, sizeof(op));
 
    exit_create:
        spin_unlock_irq(&create_dom_lock);
    }
    break;

    case DOM0_DESTROYDOMAIN:
    {
        unsigned int dom = op.u.destroydomain.domain;
        int force = op.u.destroydomain.force;
        ret = (dom == IDLE_DOMAIN_ID) ? -EPERM : kill_other_domain(dom, force);
    }
    break;

    case DOM0_BVTCTL:
    {
        unsigned long  ctx_allow = op.u.bvtctl.ctx_allow;
        ret = sched_bvtctl(ctx_allow);
        
    }
    break;

    case DOM0_ADJUSTDOM:
    {
        unsigned int   dom     = op.u.adjustdom.domain;
        unsigned long  mcu_adv = op.u.adjustdom.mcu_adv;
        unsigned long  warp    = op.u.adjustdom.warp;
        unsigned long  warpl   = op.u.adjustdom.warpl;
        unsigned long  warpu   = op.u.adjustdom.warpu;

        ret = -EPERM;
        if ( dom != IDLE_DOMAIN_ID )
            ret = sched_adjdom(dom, mcu_adv, warp, warpl, warpu);
    }
    break;

    case DOM0_GETMEMLIST:
    {
        int i;
        struct task_struct * p = find_domain_by_id(op.u.getmemlist.domain);
        unsigned long max_pfns = op.u.getmemlist.max_pfns;
        unsigned long pfn;
        unsigned long *buffer = op.u.getmemlist.buffer;
        struct list_head *list_ent;

        ret = -EINVAL;
        if ( p != NULL )
        {
            list_ent = p->pg_head.next;
            pfn = list_entry(list_ent, struct pfn_info, list) - frame_table;
            
            for ( i = 0; (i < max_pfns) && (list_ent != &p->pg_head); i++ )
            {
                if ( put_user(pfn, buffer) )
                {
                    ret = -EFAULT;
                    goto out_getmemlist;
                }
                buffer++;
                list_ent = frame_table[pfn].list.next;
                pfn = list_entry(list_ent, struct pfn_info, list) - 
                    frame_table;
            }

            op.u.getmemlist.num_pfns = i;
            copy_to_user(u_dom0_op, &op, sizeof(op));

            ret = 0;

        out_getmemlist:
            put_task_struct(p);
        }
    }
    break;

    case DOM0_GETDOMAININFO:
    { 
        struct task_struct *p = &idle0_task;
        u_long flags;

        read_lock_irqsave (&tasklist_lock, flags);

        while ( (p = p->next_task) != &idle0_task )
            if ( !is_idle_task(p) && (p->domain >= op.u.getdomaininfo.domain) )
                break;

        if ( p == &idle0_task )
        {
            ret = -ESRCH;
        }
        else
        {
            op.u.getdomaininfo.domain      = p->domain;
            strcpy (op.u.getdomaininfo.name, p->name);
            op.u.getdomaininfo.processor   = p->processor;
            op.u.getdomaininfo.has_cpu     = p->has_cpu;
            op.u.getdomaininfo.state       = p->state;
            op.u.getdomaininfo.hyp_events  = p->hyp_events;
            op.u.getdomaininfo.mcu_advance = p->mcu_advance;
            op.u.getdomaininfo.tot_pages   = p->tot_pages;
            op.u.getdomaininfo.cpu_time    = p->cpu_time;
            memcpy(&op.u.getdomaininfo.ctxt, 
                   &p->shared_info->execution_context,
                   sizeof(execution_context_t));
        }

        read_unlock_irqrestore(&tasklist_lock, flags);
        copy_to_user(u_dom0_op, &op, sizeof(op));
    }
    break;

    case DOM0_GETPAGEFRAMEINFO:
    {
        struct pfn_info *page = frame_table + op.u.getpageframeinfo.pfn;
        
        op.u.getpageframeinfo.domain = page->flags & PG_domain_mask;
        op.u.getpageframeinfo.type   = NONE;
        if ( page->type_count & REFCNT_PIN_BIT )
        {
            switch ( page->flags & PG_type_mask )
            {
            case PGT_l1_page_table:
                op.u.getpageframeinfo.type = L1TAB;
                break;
            case PGT_l2_page_table:
                op.u.getpageframeinfo.type = L2TAB;
                break;
            }
        }

        copy_to_user(u_dom0_op, &op, sizeof(op));
    }
    break;

    case DOM0_IOPL:
    {
        extern long do_iopl(unsigned int, unsigned int);
        ret = do_iopl(op.u.iopl.domain, op.u.iopl.iopl);
    }
    break;

    case DOM0_MSR:
    {
        if (op.u.msr.write)
	{
            msr_cpu_mask = op.u.msr.cpu_mask;
            msr_addr = op.u.msr.msr;
            msr_lo = op.u.msr.in1;
            msr_hi = op.u.msr.in2;
            smp_call_function(write_msr_for, NULL, 1, 1);
            write_msr_for(NULL);
	}
        else
	{
            msr_cpu_mask = op.u.msr.cpu_mask;
            msr_addr = op.u.msr.msr;
            smp_call_function(read_msr_for, NULL, 1, 1);
            read_msr_for(NULL);

            op.u.msr.out1 = msr_lo;
            op.u.msr.out2 = msr_hi;
            copy_to_user(u_dom0_op, &op, sizeof(op));
	}
        ret = 0;
    }
    break;

    case DOM0_DEBUG:
    {
        extern void pdb_do_debug(dom0_op_t *);
        pdb_do_debug(&op);
        copy_to_user(u_dom0_op, &op, sizeof(op));
        ret = 0;
    }
    break;

    case DOM0_SETTIME:
    {
        do_settime(op.u.settime.secs, 
                   op.u.settime.usecs, 
                   op.u.settime.system_time);
        ret = 0;
    }
    break;

    default:
        ret = -ENOSYS;

    }

    return ret;
}
