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
#include <asm/pdb.h>

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
    dom0_op_t *op;

    if ( !IS_PRIV(current) )
        return -EPERM;

    if ( (op = kmalloc(sizeof(*op), GFP_KERNEL)) == NULL )
        return -ENOMEM;

    if ( copy_from_user(op, u_dom0_op, sizeof(*op)) )
    {
        ret = -EFAULT;
        goto out;
    }

    if ( op->interface_version != DOM0_INTERFACE_VERSION )
    {
        ret = -EACCES;
        goto out;
    }

    switch ( op->cmd )
    {

    case DOM0_BUILDDOMAIN:
    {
        struct task_struct * p = find_domain_by_id(op->u.builddomain.domain);
        ret = -EINVAL;
        if ( p != NULL )
        {
            ret = final_setup_guestos(p, &op->u.builddomain);
            put_task_struct(p);
        }
    }
    break;

    case DOM0_STARTDOMAIN:
    {
        struct task_struct * p = find_domain_by_id(op->u.startdomain.domain);
        ret = -EINVAL;
        if ( p != NULL )
        {
            if ( (p->flags & PF_CONSTRUCTED) != 0 )
            {
                wake_up(p);
                reschedule(p);
                ret = 0;
            }
            put_task_struct(p);
        }
    }
    break;

    case DOM0_STOPDOMAIN:
    {
        ret = stop_other_domain(op->u.stopdomain.domain);
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

	if ( op->u.createdomain.name[0] )
        {
            strncpy (p->name, op->u.createdomain.name, MAX_DOMAIN_NAME);
            p->name[MAX_DOMAIN_NAME - 1] = 0;
	}

        ret = alloc_new_dom_mem(p, op->u.createdomain.memory_kb);
        if ( ret != 0 ) 
        {
            __kill_domain(p);
            goto exit_create;
        }

        ret = p->domain;
        
        op->u.createdomain.domain = ret;
        copy_to_user(u_dom0_op, op, sizeof(*op));
 
    exit_create:
        spin_unlock_irq(&create_dom_lock);
    }
    break;

    case DOM0_DESTROYDOMAIN:
    {
        unsigned int dom = op->u.destroydomain.domain;
        int force = op->u.destroydomain.force;
        ret = (dom == IDLE_DOMAIN_ID) ? -EPERM : kill_other_domain(dom, force);
    }
    break;

    case DOM0_PINCPUDOMAIN:
    {
        struct task_struct * p = find_domain_by_id(op->u.pincpudomain.domain);
	int cpu = op->u.pincpudomain.cpu;
        ret = -EINVAL;
        if ( p != NULL )
        {
	    if ( cpu == -1 )
            {
                p->cpupinned = 0;
                ret = 0;
	    }
            else
            {
		/* For the moment, we are unable to move running
                   domains between CPUs. (We need a way of synchronously
                   stopping running domains). For now, if we discover the
                   domain is not stopped already then cowardly bail out
                   with ENOSYS */

		if( !(p->state & TASK_STOPPED) ) 
                {
                    ret = -ENOSYS;
		}
                else
                {
		    /* We need a task structure lock here!!! 
		       FIX ME!! */
		    cpu = cpu % smp_num_cpus;
		    p->processor = cpu;
		    p->cpupinned = 1;
                    ret = 0;
                }
            }
            put_task_struct(p);
        }     	
    }
    break;

    case DOM0_BVTCTL:
    {
        unsigned long  ctx_allow = op->u.bvtctl.ctx_allow;
        ret = sched_bvtctl(ctx_allow);        
    }
    break;

    case DOM0_ADJUSTDOM:
    {
        unsigned int   dom     = op->u.adjustdom.domain;
        unsigned long  mcu_adv = op->u.adjustdom.mcu_adv;
        unsigned long  warp    = op->u.adjustdom.warp;
        unsigned long  warpl   = op->u.adjustdom.warpl;
        unsigned long  warpu   = op->u.adjustdom.warpu;

        ret = -EPERM;
        if ( dom != IDLE_DOMAIN_ID )
            ret = sched_adjdom(dom, mcu_adv, warp, warpl, warpu);
    }
    break;

    case DOM0_GETMEMLIST:
    {
        int i;
        struct task_struct *p = find_domain_by_id(op->u.getmemlist.domain);
        unsigned long max_pfns = op->u.getmemlist.max_pfns;
        unsigned long pfn;
        unsigned long *buffer = op->u.getmemlist.buffer;
        struct list_head *list_ent;

        ret = -EINVAL;
        if ( p != NULL )
        {
            ret = 0;

            spin_lock(&p->page_list_lock);
            list_ent = p->page_list.next;
            for ( i = 0; (i < max_pfns) && (list_ent != &p->page_list); i++ )
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
            spin_unlock(&p->page_list_lock);

            op->u.getmemlist.num_pfns = i;
            copy_to_user(u_dom0_op, op, sizeof(*op));
            
            put_task_struct(p);
        }
    }
    break;

    case DOM0_GETDOMAININFO:
    { 
        struct task_struct *p = &idle0_task;
        u_long flags;
        int i;

        read_lock_irqsave (&tasklist_lock, flags);

        while ( (p = p->next_task) != &idle0_task )
            if ( !is_idle_task(p) && 
                 (p->domain >= op->u.getdomaininfo.domain) )
                break;

        if ( p == &idle0_task )
        {
            ret = -ESRCH;
        }
        else
        {
            op->u.getdomaininfo.domain      = p->domain;
            strcpy (op->u.getdomaininfo.name, p->name);
            op->u.getdomaininfo.processor   = p->processor;
            op->u.getdomaininfo.has_cpu     = p->has_cpu;
            op->u.getdomaininfo.state       = DOMSTATE_ACTIVE;
            if ( (p->state == TASK_STOPPED) || (p->state == TASK_DYING) )
                op->u.getdomaininfo.state = DOMSTATE_STOPPED;
            op->u.getdomaininfo.hyp_events  = p->hyp_events;
            op->u.getdomaininfo.mcu_advance = p->mcu_advance;
            op->u.getdomaininfo.tot_pages   = p->tot_pages;
            op->u.getdomaininfo.cpu_time    = p->cpu_time;
            op->u.getdomaininfo.shared_info_frame = 
                __pa(p->shared_info) >> PAGE_SHIFT;
            if ( p->state == TASK_STOPPED )
            {
                rmb(); /* Ensure that we see saved register state. */
                op->u.getdomaininfo.ctxt.flags = 0;
                memcpy(&op->u.getdomaininfo.ctxt.i386_ctxt, 
                       &p->shared_info->execution_context,
                       sizeof(p->shared_info->execution_context));
                if ( p->flags & PF_DONEFPUINIT )
                    op->u.getdomaininfo.ctxt.flags |= ECF_I387_VALID;
                memcpy(&op->u.getdomaininfo.ctxt.i387_ctxt,
                       &p->thread.i387,
                       sizeof(p->thread.i387));
                memcpy(&op->u.getdomaininfo.ctxt.trap_ctxt,
                       p->thread.traps,
                       sizeof(p->thread.traps));
                if ( (p->thread.fast_trap_desc.a == 0) &&
                     (p->thread.fast_trap_desc.b == 0) )
                    op->u.getdomaininfo.ctxt.fast_trap_idx = 0;
                else
                    op->u.getdomaininfo.ctxt.fast_trap_idx = 
                        p->thread.fast_trap_idx;
                op->u.getdomaininfo.ctxt.ldt_base = p->mm.ldt_base;
                op->u.getdomaininfo.ctxt.ldt_ents = p->mm.ldt_ents;
                op->u.getdomaininfo.ctxt.gdt_ents = 0;
                if ( GET_GDT_ADDRESS(p) == GDT_VIRT_START )
                {
                    for ( i = 0; i < 16; i++ )
                        op->u.getdomaininfo.ctxt.gdt_frames[i] = 
                            l1_pgentry_to_pagenr(p->mm.perdomain_pt[i]);
                    op->u.getdomaininfo.ctxt.gdt_ents = 
                        (GET_GDT_ENTRIES(p) + 1) >> 3;
                }
                op->u.getdomaininfo.ctxt.ring1_ss  = p->thread.ss1;
                op->u.getdomaininfo.ctxt.ring1_esp = p->thread.esp1;
                op->u.getdomaininfo.ctxt.pt_base   = 
                    pagetable_val(p->mm.pagetable);
                memcpy(op->u.getdomaininfo.ctxt.debugreg, 
                       p->thread.debugreg, 
                       sizeof(p->thread.debugreg));
                op->u.getdomaininfo.ctxt.event_callback_cs  =
                    p->event_selector;
                op->u.getdomaininfo.ctxt.event_callback_eip =
                    p->event_address;
                op->u.getdomaininfo.ctxt.failsafe_callback_cs  = 
                    p->failsafe_selector;
                op->u.getdomaininfo.ctxt.failsafe_callback_eip = 
                    p->failsafe_address;
            }
        }
        read_unlock_irqrestore(&tasklist_lock, flags);
        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;

    case DOM0_GETPAGEFRAMEINFO:
    {
        struct pfn_info *page;
        unsigned long pfn = op->u.getpageframeinfo.pfn;
        unsigned int dom = op->u.getpageframeinfo.domain;
        struct task_struct *p;

        ret = -EINVAL;

        if ( unlikely(pfn >= max_page) || 
             unlikely((p = find_domain_by_id(dom)) == NULL) )
            break;

        page = &frame_table[pfn];

        if ( likely(get_page(page, p)) )
        {
            ret = 0;

            op->u.getpageframeinfo.type = NONE;

            if ( (page->type_and_flags & PGT_count_mask) != 0 )
            {
                switch ( page->type_and_flags & PGT_type_mask )
                {
                case PGT_l1_page_table:
                    op->u.getpageframeinfo.type = L1TAB;
                    break;
                case PGT_l2_page_table:
                    op->u.getpageframeinfo.type = L2TAB;
                    break;
                }
            }
            
            put_page(page);
        }

        put_task_struct(p);

        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;

    case DOM0_IOPL:
    {
        extern long do_iopl(unsigned int, unsigned int);
        ret = do_iopl(op->u.iopl.domain, op->u.iopl.iopl);
    }
    break;

    case DOM0_MSR:
    {
        if ( op->u.msr.write )
	{
            msr_cpu_mask = op->u.msr.cpu_mask;
            msr_addr = op->u.msr.msr;
            msr_lo = op->u.msr.in1;
            msr_hi = op->u.msr.in2;
            smp_call_function(write_msr_for, NULL, 1, 1);
            write_msr_for(NULL);
	}
        else
	{
            msr_cpu_mask = op->u.msr.cpu_mask;
            msr_addr = op->u.msr.msr;
            smp_call_function(read_msr_for, NULL, 1, 1);
            read_msr_for(NULL);

            op->u.msr.out1 = msr_lo;
            op->u.msr.out2 = msr_hi;
            copy_to_user(u_dom0_op, op, sizeof(*op));
	}
        ret = 0;
    }
    break;

    case DOM0_DEBUG:
    {
        pdb_do_debug(op);
        copy_to_user(u_dom0_op, op, sizeof(*op));
        ret = 0;
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
    
    case DOM0_READCONSOLE:
    {
    	extern long read_console_ring(unsigned long, 
                                      unsigned int, unsigned int);
        ret = read_console_ring(op->u.readconsole.str, 
                         	op->u.readconsole.count,
				op->u.readconsole.cmd); 
    }
    break;    

    default:
        ret = -ENOSYS;

    }

 out:
    kfree(op);
    return ret;
}
