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

    default:
        ret = -ENOSYS;

    }

    return ret;
}
