/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 */

#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/mm.h>
#include <xen/rcupdate.h>
#include <xen/spinlock.h>
#include <xen/virtual_region.h>

static struct virtual_region core = {
    .list = LIST_HEAD_INIT(core.list),
    .text_start = _stext,
    .text_end = _etext,
    .rodata_start = _srodata,
    .rodata_end = _erodata,
};

/* Becomes irrelevant when __init sections are cleared. */
static struct virtual_region core_init __initdata = {
    .list = LIST_HEAD_INIT(core_init.list),
    .text_start = _sinittext,
    .text_end = _einittext,
};

/*
 * RCU locking. Modifications to the list must be done in exclusive mode, and
 * hence need to hold the spinlock.
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
        if ( (void *)addr >= region->text_start &&
             (void *)addr <  region->text_end )
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
    unsigned long flags;

    spin_lock_irqsave(&virtual_region_lock, flags);
    list_add_tail_rcu(&r->list, &virtual_region_list);
    spin_unlock_irqrestore(&virtual_region_lock, flags);
}

/*
 * Suggest inline so when !CONFIG_LIVEPATCH the function is not left
 * unreachable after init code is removed.
 */
static void inline remove_virtual_region(struct virtual_region *r)
{
    unsigned long flags;

    spin_lock_irqsave(&virtual_region_lock, flags);
    list_del_rcu(&r->list);
    spin_unlock_irqrestore(&virtual_region_lock, flags);
}

#ifdef CONFIG_LIVEPATCH
void unregister_virtual_region(struct virtual_region *r)
{
    remove_virtual_region(r);

    /* Assert that no CPU might be using the removed region. */
    rcu_barrier();
}

#ifdef CONFIG_X86
void relax_virtual_region_perms(void)
{
    const struct virtual_region *region;

    rcu_read_lock(&rcu_virtual_region_lock);
    list_for_each_entry_rcu( region, &virtual_region_list, list )
    {
        modify_xen_mappings_lite((unsigned long)region->text_start,
                                 PAGE_ALIGN((unsigned long)region->text_end),
                                 PAGE_HYPERVISOR_RWX);
        if ( region->rodata_start )
            modify_xen_mappings_lite((unsigned long)region->rodata_start,
                                     PAGE_ALIGN((unsigned long)region->rodata_end),
                                     PAGE_HYPERVISOR_RW);
    }
    rcu_read_unlock(&rcu_virtual_region_lock);
}

void tighten_virtual_region_perms(void)
{
    const struct virtual_region *region;

    rcu_read_lock(&rcu_virtual_region_lock);
    list_for_each_entry_rcu( region, &virtual_region_list, list )
    {
        modify_xen_mappings_lite((unsigned long)region->text_start,
                                 PAGE_ALIGN((unsigned long)region->text_end),
                                 PAGE_HYPERVISOR_RX);
        if ( region->rodata_start )
            modify_xen_mappings_lite((unsigned long)region->rodata_start,
                                     PAGE_ALIGN((unsigned long)region->rodata_end),
                                     PAGE_HYPERVISOR_RO);
    }
    rcu_read_unlock(&rcu_virtual_region_lock);
}
#endif /* CONFIG_X86 */
#endif /* CONFIG_LIVEPATCH */

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
        __stop_bug_frames_3,
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
