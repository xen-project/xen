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
#include <hypervisor-ifs/dom0_ops.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <asm/domain_page.h>
#include <asm/msr.h>
#include <asm/pdb.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/shadow.h>
#include <hypervisor-ifs/sched_ctl.h>

#define TRC_DOM0OP_ENTER_BASE  0x00020000
#define TRC_DOM0OP_LEAVE_BASE  0x00030000

extern unsigned int alloc_new_dom_mem(struct task_struct *, unsigned int);

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
    dom0_op_t curop,*op=&curop;

    if ( !IS_PRIV(current) )
        return -EPERM;

    if ( copy_from_user(op, u_dom0_op, sizeof(*op)) )
    {
        return -EFAULT;
    }

    if ( op->interface_version != DOM0_INTERFACE_VERSION )
    {
        return -EACCES;
    }

    TRACE_5D(TRC_DOM0OP_ENTER_BASE + op->cmd, 
             0, op->u.dummy[0], op->u.dummy[1], 
             op->u.dummy[2], op->u.dummy[3] );

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
            if ( test_bit(PF_CONSTRUCTED, &p->flags) )
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
 
        /*
         * This is grim, but helps for live migrate. It's also unsafe
         * in the strict sense as we're not explicitly setting a
         * timeout, but dom0 is bound to have other timers going off to
         * wake us back up. 
         * We go to sleep so that the other domain can stop quicker, hence
         * we have less total down time in a migrate.
         */
        if( ret == 0 && op->u.stopdomain.sync == 1 )
        {
            extern long do_block( void );
            do_block(); /* Yuk... */
        }
    }
    break;

    case DOM0_CREATEDOMAIN:
    {
        struct task_struct *p;
        static domid_t    domnr = 0;
        static spinlock_t domnr_lock = SPIN_LOCK_UNLOCKED;
        unsigned int pro;
        domid_t dom;
        ret = -ENOMEM;

        /* Search for an unused domain identifier. */
        for ( ; ; )
        {
            spin_lock(&domnr_lock);
            /* Wrap the roving counter when we reach first special value. */
            if ( (dom = ++domnr) == DOMID_SELF )
                dom = domnr = 1;
            spin_unlock(&domnr_lock);

            if ( (p = find_domain_by_id(dom)) == NULL )
                break;
            put_task_struct(p);
        }

        if (op->u.createdomain.cpu == -1 )
            pro = (unsigned int)dom % smp_num_cpus;
        else
            pro = op->u.createdomain.cpu % smp_num_cpus;

        p = do_createdomain(dom, pro);
        if ( p == NULL ) 
            break;

        if ( op->u.createdomain.name[0] )
        {
            strncpy(p->name, op->u.createdomain.name, MAX_DOMAIN_NAME);
            p->name[MAX_DOMAIN_NAME - 1] = '\0';
        }

        ret = alloc_new_dom_mem(p, op->u.createdomain.memory_kb);
        if ( ret != 0 ) 
        {
            __kill_domain(p);
            break;
        }

        ret = 0;
        
        op->u.createdomain.domain = p->domain;
        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;

    case DOM0_DESTROYDOMAIN:
    {
        domid_t dom = op->u.destroydomain.domain;
        int force = op->u.destroydomain.force;
        ret = kill_other_domain(dom, force);
    }
    break;

    case DOM0_PINCPUDOMAIN:
    {
        domid_t dom = op->u.pincpudomain.domain;
        
        if ( dom == current->domain || dom == IDLE_DOMAIN_ID )
            ret = -EINVAL;
        else
        {
            struct task_struct * p = find_domain_by_id(dom);
            int cpu = op->u.pincpudomain.cpu;
            int we_paused = 0;
            
            ret = -ESRCH;
            
            if ( p != NULL )
            {
                if ( cpu == -1 )
                {
                    p->cpupinned = 0;
                    ret = 0;
                }
                else
                {
                    /* Pause domain if necessary. */
                    if( !(p->state & TASK_STOPPED) && 
                        !(p->state & TASK_PAUSED) )
                    {
                        sched_pause_sync(p);
                        we_paused = 1;
                    }
                    
                    /* We need a task structure lock here!!! 
                       FIX ME!! */
                    cpu = cpu % smp_num_cpus;
                    p->processor = cpu;
                    p->cpupinned = 1;
                    
                    if ( we_paused )
                        wake_up(p);
                    
                    ret = 0;
                }
                put_task_struct(p);
            }      
        }
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
        full_execution_context_t *c;
        struct task_struct       *p;
        unsigned long             flags;
        int                       i;

        read_lock_irqsave(&tasklist_lock, flags);

        for_each_domain ( p )
        {
            if ( p->domain >= op->u.getdomaininfo.domain )
                break;
        }

        if ( (p == NULL) || (p->state == TASK_DYING) )
        {
            ret = -ESRCH;
            goto gdi_out;
        }
        else
        {
            op->u.getdomaininfo.domain      = p->domain;
            strcpy(op->u.getdomaininfo.name, p->name);

            if ( p->state == TASK_RUNNING )
                op->u.getdomaininfo.flags = 
                    p->has_cpu ? DOMSTATE_RUNNING : DOMSTATE_RUNNABLE;
            else if ( (p->state == TASK_INTERRUPTIBLE) || 
                      (p->state == TASK_UNINTERRUPTIBLE) )
                op->u.getdomaininfo.flags = DOMSTATE_BLOCKED;
            else if ( p->state == TASK_PAUSED )
                op->u.getdomaininfo.flags = DOMSTATE_PAUSED;
            else if ( p->state == TASK_CRASHED )
                op->u.getdomaininfo.flags = DOMSTATE_CRASHED;
            else
                op->u.getdomaininfo.flags = DOMSTATE_STOPPED;
            op->u.getdomaininfo.flags |= p->processor << DOMFLAGS_CPUSHIFT;
            op->u.getdomaininfo.flags |= p->stop_code << DOMFLAGS_GUESTSHIFT;

            op->u.getdomaininfo.hyp_events  = p->hyp_events;
            op->u.getdomaininfo.tot_pages   = p->tot_pages;
            op->u.getdomaininfo.max_pages   = p->max_pages;
            op->u.getdomaininfo.cpu_time    = p->cpu_time;
            op->u.getdomaininfo.shared_info_frame = 
                __pa(p->shared_info) >> PAGE_SHIFT;

            if ( (p->state == TASK_STOPPED) &&
                 (op->u.getdomaininfo.ctxt != NULL) )
            {
                if ( (c = kmalloc(sizeof(*c), GFP_KERNEL)) == NULL )
                {
                    ret = -ENOMEM;
                    goto gdi_out;
                }

                rmb(); /* Ensure that we see saved register state. */
                c->flags = 0;
                memcpy(&c->cpu_ctxt, 
                       &p->shared_info->execution_context,
                       sizeof(p->shared_info->execution_context));
                if ( test_bit(PF_DONEFPUINIT, &p->flags) )
                    c->flags |= ECF_I387_VALID;
                memcpy(&c->fpu_ctxt,
                       &p->thread.i387,
                       sizeof(p->thread.i387));
                memcpy(&c->trap_ctxt,
                       p->thread.traps,
                       sizeof(p->thread.traps));
#ifdef ARCH_HAS_FAST_TRAP
                if ( (p->thread.fast_trap_desc.a == 0) &&
                     (p->thread.fast_trap_desc.b == 0) )
                    c->fast_trap_idx = 0;
                else
                    c->fast_trap_idx = 
                        p->thread.fast_trap_idx;
#endif
                c->ldt_base = p->mm.ldt_base;
                c->ldt_ents = p->mm.ldt_ents;
                c->gdt_ents = 0;
                if ( GET_GDT_ADDRESS(p) == GDT_VIRT_START )
                {
                    for ( i = 0; i < 16; i++ )
                        c->gdt_frames[i] = 
                            l1_pgentry_to_pagenr(p->mm.perdomain_pt[i]);
                    c->gdt_ents = 
                        (GET_GDT_ENTRIES(p) + 1) >> 3;
                }
                c->guestos_ss  = p->thread.guestos_ss;
                c->guestos_esp = p->thread.guestos_sp;
                c->pt_base   = 
                    pagetable_val(p->mm.pagetable);
                memcpy(c->debugreg, 
                       p->thread.debugreg, 
                       sizeof(p->thread.debugreg));
                c->event_callback_cs  =
                    p->event_selector;
                c->event_callback_eip =
                    p->event_address;
                c->failsafe_callback_cs  = 
                    p->failsafe_selector;
                c->failsafe_callback_eip = 
                    p->failsafe_address;

                if ( copy_to_user(op->u.getdomaininfo.ctxt, c, sizeof(*c)) )
                    ret = -EINVAL;

                if ( c != NULL )
                    kfree(c);
            }
        }

        if ( copy_to_user(u_dom0_op, op, sizeof(*op)) )     
            ret = -EINVAL;

    gdi_out:
        read_unlock_irqrestore(&tasklist_lock, flags);
    }
    break;

    case DOM0_GETPAGEFRAMEINFO:
    {
        struct pfn_info *page;
        unsigned long pfn = op->u.getpageframeinfo.pfn;
        domid_t dom = op->u.getpageframeinfo.domain;
        struct task_struct *p;

        ret = -EINVAL;

        if ( unlikely(pfn >= max_page) || 
             unlikely((p = find_domain_by_id(dom)) == NULL) )
            break;

        page = &frame_table[pfn];

        if ( likely(get_page(page, p)) )
        {
            ret = 0;

            op->u.getpageframeinfo.type = NOTAB;

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

        put_task_struct(p);

        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;

    case DOM0_IOPL:
    {
        extern long do_iopl(domid_t, unsigned int);
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
        extern int phys_proc_id[];

        dom0_physinfo_t *pi = &op->u.physinfo;

        int old_id = phys_proc_id[0];
        int ht = 0;

        while( ( ht < smp_num_cpus ) && ( phys_proc_id[ht] == old_id ) ) ht++;

        pi->ht_per_core = ht;
        pi->cores       = smp_num_cpus / pi->ht_per_core;
        pi->total_pages = max_page;
        pi->free_pages  = free_pfns;
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

    case DOM0_SHADOW_CONTROL:
    {
        struct task_struct *p; 
        ret = -ESRCH;
        p = find_domain_by_id( op->u.shadow_control.domain );
        if ( p )
        {
            ret = shadow_mode_control(p, &op->u.shadow_control );
            put_task_struct(p);
            copy_to_user(u_dom0_op, op, sizeof(*op));
        } 
    }
    break;

    case DOM0_SCHED_ID:
    {
        op->u.sched_id.sched_id = sched_id();

        copy_to_user(u_dom0_op, op, sizeof(*op));
        ret = 0;        
    }
    break;

    case DOM0_SETDOMAINNAME:
    {
        struct task_struct *p; 
        p = find_domain_by_id( op->u.setdomainname.domain );
        if ( p )
        {
            strncpy(p->name, op->u.setdomainname.name, MAX_DOMAIN_NAME);
            put_task_struct(p);
        }
        else 
            ret = -ESRCH;
    }
    break;

    case DOM0_SETDOMAININITIALMEM:
    {
        struct task_struct *p; 
        ret = -ESRCH;
        p = find_domain_by_id( op->u.setdomaininitialmem.domain );
        if ( p )
        { 
            /* should only be used *before* domain is built. */
            if ( ! test_bit(PF_CONSTRUCTED, &p->flags) )
                ret = alloc_new_dom_mem( 
                    p, op->u.setdomaininitialmem.initial_memkb );
            else
                ret = -EINVAL;
            put_task_struct(p);
        }
    }
    break;

    case DOM0_SETDOMAINMAXMEM:
    {
        struct task_struct *p; 
        p = find_domain_by_id( op->u.setdomainmaxmem.domain );
        if ( p )
        {
            p->max_pages = 
                (op->u.setdomainmaxmem.max_memkb+PAGE_SIZE-1)>> PAGE_SHIFT;
            put_task_struct(p);
        }
        else 
            ret = -ESRCH;
    }
    break;

    case DOM0_GETPAGEFRAMEINFO2:
    {
#define GPF2_BATCH 128
        int n,j;
        int num = op->u.getpageframeinfo2.num;
        domid_t dom = op->u.getpageframeinfo2.domain;
        unsigned long *s_ptr = (unsigned long*) op->u.getpageframeinfo2.array;
        struct task_struct *p;
        unsigned long l_arr[GPF2_BATCH];
        ret = -ESRCH;

        if ( unlikely((p = find_domain_by_id(dom)) == NULL) )
            break;

        if ( unlikely(num>1024) )
        {
            ret = -E2BIG;
            break;
        }
 
        ret = 0;    
        for(n=0;n<num;)
        {
            int k = ((num-n)>GPF2_BATCH)?GPF2_BATCH:(num-n);

            if( copy_from_user( l_arr, &s_ptr[n], k*sizeof(unsigned long) ) )
            {
                ret = -EINVAL;
                break;
            }
     
            for(j=0;j<k;j++)
            {      
                struct pfn_info *page;
                unsigned long mfn = l_arr[j];

                if ( unlikely(mfn >= max_page) )
                    goto e2_err;

                page = &frame_table[mfn];
  
                if ( likely(get_page(page, p)) )
                {
                    unsigned long type = 0;
                    switch( page->type_and_flags & PGT_type_mask )
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
                    l_arr[j] |= type;
                    put_page(page);
                }
                else
                {
                e2_err:
                    l_arr[j] |= XTAB;
                }

            }

            if( copy_to_user( &s_ptr[n], l_arr, k*sizeof(unsigned long) ) )
            {
                ret = -EINVAL;
                break;
            }

            n+=j;     
        }

        put_task_struct(p);

    }
    break;

    default:
        ret = -ENOSYS;

    }

    TRACE_5D(TRC_DOM0OP_LEAVE_BASE + op->cmd, ret,
             op->u.dummy[0], op->u.dummy[1], op->u.dummy[2], op->u.dummy[3]);


    return ret;
}
