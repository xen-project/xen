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
#include <xeno/dom0_ops.h>
#include <xeno/sched.h>
#include <xeno/event.h>
#include <asm/domain_page.h>

extern unsigned int alloc_new_dom_mem(struct task_struct *, unsigned int);

static unsigned int get_domnr(void)
{
    struct task_struct *p = &idle0_task;
    unsigned long dom_mask = 0;
    read_lock_irq(&tasklist_lock);
    do {
        if ( is_idle_task(p) ) continue;
        set_bit(p->domain, &dom_mask); 
    }
    while ( (p = p->next_task) != &idle0_task );   
    read_unlock_irq(&tasklist_lock);
    return (dom_mask == ~0UL) ? 0 : ffz(dom_mask);
}

static void build_page_list(struct task_struct *p)
{
    unsigned long * list;
    unsigned long curr;
    unsigned long page;
    struct list_head *list_ent;

    list = (unsigned long *)map_domain_mem(p->pg_head << PAGE_SHIFT);
    curr = page = p->pg_head;
    do {
        *list++ = page;
        list_ent = frame_table[page].list.next;
        page = list_entry(list_ent, struct pfn_info, list) - frame_table;
        if( !((unsigned long)list & (PAGE_SIZE-1)) )
        {
            list_ent = frame_table[curr].list.next;
            curr = list_entry(list_ent, struct pfn_info, list) - frame_table;
            unmap_domain_mem(list-1);
            list = (unsigned long *)map_domain_mem(curr << PAGE_SHIFT);
        }
    }
    while ( page != p->pg_head );
    unmap_domain_mem(list);
}
    
long do_dom0_op(dom0_op_t *u_dom0_op)
{
    long ret = 0;
    dom0_op_t op;

    if ( current->domain != 0 )
        return -EPERM;

    if ( copy_from_user(&op, u_dom0_op, sizeof(op)) )
        return -EFAULT;

    switch ( op.cmd )
    {

    case DOM0_STARTDOM:
    {
        struct task_struct * p = find_domain_by_id(op.u.meminfo.domain);
        ret = final_setup_guestos(p, &op.u.meminfo);
        if( ret != 0 ){
            p->state = TASK_DYING;
            release_task(p);
            break;
        }
        wake_up(p);
        reschedule(p);
        ret = p->domain;
    }
    break;

    case DOM0_NEWDOMAIN:
    {
        struct task_struct *p;
        static unsigned int pro = 0;
        unsigned int dom = get_domnr();
        ret = -ENOMEM;
        if ( !dom ) break;
        p = do_newdomain();
        if ( !p ) break;
        p->domain = dom;
        pro = (pro+1) % smp_num_cpus;
        p->processor = pro;

        /* if we are not booting dom 0 than only mem 
         * needs to be allocated
         */
        if(dom != 0){

            if(alloc_new_dom_mem(p, op.u.newdomain.memory_kb) != 0){
                ret = -1;
                break;
            }
            build_page_list(p);
            
            ret = p->domain;

            op.u.newdomain.domain = ret;
            op.u.newdomain.pg_head = p->pg_head;
            copy_to_user(u_dom0_op, &op, sizeof(op));

            break;
        }

        /* executed only in case of domain 0 */
        ret = setup_guestos(p, &op.u.newdomain);    /* Load guest OS into @p */
        if ( ret != 0 ) 
        {
            p->state = TASK_DYING;
            release_task(p);
            break;
        }
        wake_up(p);          /* Put @p on runqueue */
        reschedule(p);       /* Force a scheduling decision on @p's CPU */
        ret = p->domain;
    }
    break;

    case DOM0_KILLDOMAIN:
    {
        unsigned int dom = op.u.killdomain.domain;
        if ( dom == IDLE_DOMAIN_ID )
        {
            ret = -EPERM;
        }
        else
        {
            ret = kill_other_domain(dom);
        }
    }
    break;

    case DOM0_GETMEMLIST:
    {
        int i;
        unsigned long pfn = op.u.getmemlist.start_pfn;
        unsigned long *buffer = op.u.getmemlist.buffer;
        struct list_head *list_ent;

        for ( i = 0; i < op.u.getmemlist.num_pfns; i++ )
        {
            /* XXX We trust DOM0 to give us a safe buffer. XXX */
            *buffer++ = pfn;
            list_ent = frame_table[pfn].list.next;
            pfn = list_entry(list_ent, struct pfn_info, list) - frame_table;
        }
    }
    break;

    default:
        ret = -ENOSYS;

    }

    return ret;
}
