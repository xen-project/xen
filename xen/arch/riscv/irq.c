/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * RISC-V Interrupt support
 *
 * Copyright (c) Vates
 */

#include <xen/bug.h>
#include <xen/cpumask.h>
#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/spinlock.h>
#include <xen/xvmalloc.h>

#include <asm/hardirq.h>
#include <asm/intc.h>

/* Describe an IRQ assigned to a guest */
struct irq_guest
{
    struct domain *d;
    unsigned int virq;
    /*
     * The action of a guest IRQ has the same lifetime as this structure, so
     * embed it here to have both covered by a single allocation. Consequently
     * it must not be freed on its own, which is why free_on_release is left
     * false for it (see irq_release_action()).
     */
    struct irqaction action;
};

static irq_desc_t irq_desc[NR_IRQS];

struct irq_desc *irq_to_desc(unsigned int irq)
{
    ASSERT(irq < ARRAY_SIZE(irq_desc));
    return &irq_desc[irq];
}

static bool irq_validate_new_type(unsigned int curr, unsigned int new)
{
    return curr == IRQ_TYPE_INVALID || curr == new;
}

static int irq_set_type(unsigned int irq, unsigned int type)
{
    unsigned long flags;
    struct irq_desc *desc = irq_to_desc(irq);
    int ret = -EBUSY;

    spin_lock_irqsave(&desc->lock, flags);

    if ( !irq_validate_new_type(desc->arch.type, type) )
        goto err;

    desc->arch.type = type;

    ret = 0;

 err:
    spin_unlock_irqrestore(&desc->lock, flags);

    return ret;
}

int platform_get_irq(const struct dt_device_node *device, int index)
{
    struct dt_irq dt_irq;
    int ret;

    if ( (ret = dt_device_get_irq(device, index, &dt_irq)) != 0 )
        return ret;

    BUILD_BUG_ON(NR_IRQS > INT_MAX);

    if ( dt_irq.irq >= NR_IRQS )
        panic("irq%d is bigger then NR_IRQS(%d)\n", dt_irq.irq, NR_IRQS);

    if ( (ret = irq_set_type(dt_irq.irq, dt_irq.type)) != 0 )
        return ret;

    return dt_irq.irq;
}

static int _setup_irq(struct irq_desc *desc, unsigned int irqflags,
                      struct irqaction *new)
{
    bool shared = irqflags & IRQF_SHARED;

    ASSERT(new != NULL);

    /*
     * Sanity checks:
     *  - if the IRQ is marked as shared
     *  - dev_id is not NULL when IRQF_SHARED is set
     */
    if ( desc->action != NULL && (!(desc->status & IRQF_SHARED) || !shared) )
        return -EINVAL;
    if ( shared && new->dev_id == NULL )
        return -EINVAL;

    if ( shared )
        desc->status |= IRQF_SHARED;

#ifdef CONFIG_IRQ_HAS_MULTIPLE_ACTION
    new->next = desc->action;
#endif

    desc->action = new;
    smp_wmb();

    return 0;
}

int setup_irq(unsigned int irq, unsigned int irqflags, struct irqaction *new)
{
    int rc;
    unsigned long flags;
    struct irq_desc *desc = irq_to_desc(irq);
    bool disabled;

    spin_lock_irqsave(&desc->lock, flags);

    disabled = (desc->action == NULL);

    if ( desc->status & IRQ_GUEST )
    {
        spin_unlock_irqrestore(&desc->lock, flags);
        /*
         * TODO: would be nice to have functionality to print which domain owns
         *       an IRQ.
         */
        printk(XENLOG_ERR "ERROR: IRQ %u is already in use by a domain\n", irq);
        return -EBUSY;
    }

    rc = _setup_irq(desc, irqflags, new);
    if ( rc )
        goto err;

    /* First time the IRQ is setup */
    if ( disabled )
    {
        /* Route interrupt to xen */
        intc_route_irq_to_xen(desc, IRQ_NO_PRIORITY);

        /*
         * We don't care for now which CPU will receive the
         * interrupt.
         *
         * TODO: Handle case where IRQ is setup on different CPU than
         *       the targeted CPU and the priority.
         */
        desc->handler->set_affinity(desc, cpumask_of(smp_processor_id()));

        desc->handler->startup(desc);

        /* Enable irq */
        desc->status &= ~IRQ_DISABLED;
    }

 err:
    spin_unlock_irqrestore(&desc->lock, flags);

    return rc;
}

int arch_init_one_irq_desc(struct irq_desc *desc)
{
    desc->arch.type = IRQ_TYPE_INVALID;

    return 0;
}

static int __init init_irq_data(void)
{
    unsigned int irq;

    for ( irq = 0; irq < NR_IRQS; irq++ )
    {
        struct irq_desc *desc = irq_to_desc(irq);
        int rc;

        desc->irq = irq;

        rc = init_one_irq_desc(desc);
        if ( rc )
            return rc;
    }

    return 0;
}

void __init init_IRQ(void)
{
    if ( init_irq_data() < 0 )
        panic("initialization of IRQ data failed\n");
}

/* Dispatch an interrupt */
void do_IRQ(struct cpu_user_regs *regs, unsigned int irq)
{
    struct irq_desc *desc = irq_to_desc(irq);
    struct irqaction *action;

    irq_enter();

    spin_lock(&desc->lock);

    if ( desc->handler->ack )
        desc->handler->ack(desc);

    if ( desc->status & IRQ_GUEST )
        /*
         * With APLIC + IMSIC, guest interrupts bypass Xen and are delivered
         * directly to the guest. Without IMSIC, interrupts would be trapped
         * by Xen and would need injecting into the guest here.
         */
        panic("unimplemented");

    if ( desc->status & IRQ_DISABLED )
        goto out;

    desc->status |= IRQ_INPROGRESS;

    action = desc->action;

    spin_unlock_irq(&desc->lock);

#ifndef CONFIG_IRQ_HAS_MULTIPLE_ACTION
    action->handler(irq, action->dev_id);
#else
    do {
        action->handler(irq, action->dev_id);
        action = action->next;
    } while ( action );
#endif /* CONFIG_IRQ_HAS_MULTIPLE_ACTION */

    spin_lock_irq(&desc->lock);

    desc->status &= ~IRQ_INPROGRESS;

 out:
    if ( desc->handler->end )
        desc->handler->end(desc);

    spin_unlock(&desc->lock);
    irq_exit();
}

static struct irq_guest *irq_get_guest_info(struct irq_desc *desc)
{
    ASSERT(spin_is_locked(&desc->lock));
    ASSERT(desc->status & IRQ_GUEST);
    ASSERT(desc->action);

    return desc->action->dev_id;
}

/*
 * Detach the action registered with 'dev_id' from 'desc' and, if it was the
 * last one, shut the interrupt down.
 *
 * To be called with desc->lock held, which is still held upon return. The
 * detached action is returned (NULL if 'dev_id' had no action registered) and
 * has to be handed to irq_release_action() once the lock has been dropped.
 */
static struct irqaction *irq_detach_action(struct irq_desc *desc,
                                           const void *dev_id)
{
    struct irqaction *action, **action_ptr = &desc->action;

    ASSERT(spin_is_locked(&desc->lock));

#ifdef CONFIG_IRQ_HAS_MULTIPLE_ACTION
    for ( ;; )
    {
        action = *action_ptr;
        if ( !action || (action->dev_id == dev_id) )
            break;

        action_ptr = &action->next;
    }
#else
    action = *action_ptr;
#endif

    if ( !action )
    {
        printk(XENLOG_WARNING "Trying to free already-free IRQ %u\n",
               desc->irq);
        return NULL;
    }

    /* Found it - remove it from the action list */
#ifdef CONFIG_IRQ_HAS_MULTIPLE_ACTION
    *action_ptr = action->next;
#else
    *action_ptr = NULL;
#endif

    /* If this was the last action, shut down the IRQ */
    if ( !desc->action )
    {
        desc->handler->shutdown(desc);
        desc->status &= ~IRQ_GUEST;
    }

    return action;
}

/*
 * Complete the release of an action detached by irq_detach_action().
 *
 * To be called with desc->lock dropped: the lock cannot be held all the way
 * through, as waiting for a handler still running on another CPU to complete
 * requires do_IRQ() to be able to acquire the very same lock.
 *
 * Once this function has returned, the action (and hence any object embedding
 * it) is no longer referenced by anyone and may be freed.
 */
static void irq_release_action(const struct irq_desc *desc,
                               struct irqaction *action)
{
    /* Wait to make sure it's not being used on another CPU. */
    while ( test_bit(_IRQ_INPROGRESS, &desc->status) )
        cpu_relax();

    /*
     * IRQ_INPROGRESS is cleared in do_IRQ() after re-acquiring desc->lock,
     * and lock acquisition implies a full barrier, so the handler's accesses
     * are ordered before the clearing becomes visible here. The barrier below
     * adds the missing load-load ordering (the loop's exit branch already
     * prevents the store in xvfree() from becoming visible early), so that
     * having observed the bit cleared we also see whatever the handler did on
     * that CPU. Only then is it safe to free the action.
     */
    smp_rmb();

    if ( action->free_on_release )
        xvfree(action);
}

void release_irq(unsigned int irq, const void *dev_id)
{
    struct irq_desc *desc = irq_to_desc(irq);
    struct irqaction *action;
    unsigned long flags;

    spin_lock_irqsave(&desc->lock, flags);
    action = irq_detach_action(desc, dev_id);
    spin_unlock_irqrestore(&desc->lock, flags);

    if ( action )
        irq_release_action(desc, action);
}

int release_guest_irq(const struct domain *d, unsigned int virq)
{
    struct irq_desc *desc = irq_to_desc(virq);
    struct irqaction *action;
    struct irq_guest *info;
    unsigned long flags;
    int ret = -EINVAL;

    spin_lock_irqsave(&desc->lock, flags);

    if ( !(desc->status & IRQ_GUEST) )
        goto unlock_err;

    info = irq_get_guest_info(desc);
    if ( d != info->d )
        goto unlock_err;

    /*
     * Detaching the action happens with desc->lock still held, so that a
     * concurrent release_guest_irq() for the same IRQ will see IRQ_GUEST
     * already cleared and bail out, rather than capturing the same 'info' and
     * double-freeing it below.
     */
    action = irq_detach_action(desc, info);

    spin_unlock_irqrestore(&desc->lock, flags);

    if ( action )
        irq_release_action(desc, action);

    xvfree(info);

    return 0;

 unlock_err:
    spin_unlock_irqrestore(&desc->lock, flags);
    return ret;
}

/* Route an IRQ to a specific guest */
int route_irq_to_guest(struct domain *d, unsigned int virq,
                       unsigned int irq, const char *devname)
{
    struct irq_guest *info;
    struct irq_desc *desc = irq_to_desc(irq);
    unsigned long flags;
    int retval = 0;

    if ( d->is_dying )
        return -EINVAL;

    info = xvzalloc(struct irq_guest);
    if ( !info )
        return -ENOMEM;

    info->d = d;
    info->virq = virq;

    info->action.dev_id = info;
    info->action.name = devname;

    spin_lock_irqsave(&desc->lock, flags);

    /*
     * If the IRQ is already used by someone
     *  - If it's the same domain -> Xen doesn't need to update the IRQ desc.
     *  For safety check if we are not trying to assign the IRQ to a
     *  different vIRQ.
     *  - Otherwise -> For now, don't allow the IRQ to be shared between
     *  Xen and domains.
     */
    if ( desc->action )
    {
        if ( desc->status & IRQ_GUEST )
        {
            struct domain *ad = irq_get_guest_info(desc)->d;

            if ( d != ad )
            {
                printk(XENLOG_G_ERR "%pd: IRQ %u is already used by %pd\n",
                       d, irq, ad);
                retval = -EBUSY;
            }
            else if ( irq_get_guest_info(desc)->virq != virq )
            {
                printk(XENLOG_G_ERR
                       "%pd: IRQ %u is already assigned to vIRQ %u\n",
                       d, irq, irq_get_guest_info(desc)->virq);
                retval = -EBUSY;
            }
        }
        else
        {
            printk(XENLOG_G_ERR "%pd: IRQ %u is already used by Xen\n",
                   d, irq);
            retval = -EBUSY;
        }
        goto out;
    }

    retval = _setup_irq(desc, 0, &info->action);
    if ( retval )
        goto out;

    retval = intc_route_irq_to_guest(desc, IRQ_NO_PRIORITY);
    if ( retval )
    {
        struct irqaction *action = irq_detach_action(desc, info);

        spin_unlock_irqrestore(&desc->lock, flags);

        if ( action )
            irq_release_action(desc, action);

        goto free_info;
    }

    spin_unlock_irqrestore(&desc->lock, flags);

    return 0;

 out:
    spin_unlock_irqrestore(&desc->lock, flags);
 free_info:
    xvfree(info);

    return retval;
}
