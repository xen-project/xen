/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 */

#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/rcupdate.h>
#include <xen/spinlock.h>
#include <xen/virtual_region.h>

static struct virtual_region core = {
    .list = LIST_HEAD_INIT(core.list),
    .start = _stext,
    .end = _etext,
};

/* Becomes irrelevant when __init sections are cleared. */
static struct virtual_region core_init __initdata = {
    .list = LIST_HEAD_INIT(core_init.list),
    .start = _sinittext,
    .end = _einittext,
};

/*
 * RCU locking. Additions are done either at startup (when there is only
 * one CPU) or when all CPUs are running without IRQs.
 *
 * Deletions are bit tricky. We do it when Live Patch (all CPUs running
 * without IRQs) or during bootup (when clearing the init).
 *
 * Hence we use list_del_rcu (which sports an memory fence) and a spinlock
 * on deletion.
 *
 * All readers of virtual_region_list MUST use list_for_each_entry_rcu.
 */
static LIST_HEAD(virtual_region_list);
static DEFINE_SPINLOCK(virtual_region_lock);
static DEFINE_RCU_READ_LOCK(rcu_virtual_region_lock);

const struct virtual_region *find_text_region(unsigned long addr)
{
    const struct virtual_region *region;

    rcu_read_lock(&rcu_virtual_region_lock);
    list_for_each_entry_rcu( region, &virtual_region_list, list )
    {
        if ( (void *)addr >= region->start && (void *)addr < region->end )
        {
            rcu_read_unlock(&rcu_virtual_region_lock);
            return region;
        }
    }
    rcu_read_unlock(&rcu_virtual_region_lock);

    return NULL;
}

void register_virtual_region(struct virtual_region *r)
{
    ASSERT(!local_irq_is_enabled());

    list_add_tail_rcu(&r->list, &virtual_region_list);
}

static void remove_virtual_region(struct virtual_region *r)
{
    unsigned long flags;

    spin_lock_irqsave(&virtual_region_lock, flags);
    list_del_rcu(&r->list);
    spin_unlock_irqrestore(&virtual_region_lock, flags);
    /*
     * We do not need to invoke call_rcu.
     *
     * This is due to the fact that on the deletion we have made sure
     * to use spinlocks (to guard against somebody else calling
     * unregister_virtual_region) and list_deletion spiced with
     * memory barrier.
     *
     * That protects us from corrupting the list as the readers all
     * use list_for_each_entry_rcu which is safe against concurrent
     * deletions.
     */
}

void unregister_virtual_region(struct virtual_region *r)
{
    /* Expected to be called from Live Patch - which has IRQs disabled. */
    ASSERT(!local_irq_is_enabled());

    remove_virtual_region(r);
}

void __init unregister_init_virtual_region(void)
{
    BUG_ON(system_state != SYS_STATE_active);

    remove_virtual_region(&core_init);
}

void __init setup_virtual_regions(const struct exception_table_entry *start,
                                  const struct exception_table_entry *end)
{
    size_t sz;
    unsigned int i;
    static const struct bug_frame *const __initconstrel bug_frames[] = {
        __start_bug_frames,
        __stop_bug_frames_0,
        __stop_bug_frames_1,
        __stop_bug_frames_2,
#ifdef CONFIG_X86
        __stop_bug_frames_3,
#endif
        NULL
    };

    for ( i = 1; bug_frames[i]; i++ )
    {
        const struct bug_frame *s;

        s = bug_frames[i - 1];
        sz = bug_frames[i] - s;

        core.frame[i - 1].n_bugs = sz;
        core.frame[i - 1].bugs = s;

        core_init.frame[i - 1].n_bugs = sz;
        core_init.frame[i - 1].bugs = s;
    }

    core_init.ex = core.ex = start;
    core_init.ex_end = core.ex_end = end;

    register_virtual_region(&core_init);
    register_virtual_region(&core);
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
