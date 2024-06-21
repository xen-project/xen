/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 */

#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/mm.h>
#include <xen/rcupdate.h>
#include <xen/sections.h>
#include <xen/spinlock.h>
#include <xen/virtual_region.h>

extern const struct bug_frame
    __start_bug_frames_0[], __stop_bug_frames_0[],
    __start_bug_frames_1[], __stop_bug_frames_1[],
    __start_bug_frames_2[], __stop_bug_frames_2[],
    __start_bug_frames_3[], __stop_bug_frames_3[];

/*
 * For the built-in regions, the double linked list can be constructed at
 * build time.  Forward-declare the elements and their initialisers.
 */
static struct list_head virtual_region_list;
static struct virtual_region core, core_init;

#define LIST_ENTRY_HEAD() { .next = &core.list,           .prev = &core_init.list }
#define LIST_ENTRY_CORE() { .next = &core_init.list,      .prev = &virtual_region_list }
#define LIST_ENTRY_INIT() { .next = &virtual_region_list, .prev = &core.list }

static struct virtual_region core __read_mostly = {
    .list = LIST_ENTRY_CORE(),
    .text_start = _stext,
    .text_end = _etext,
    .rodata_start = _srodata,
    .rodata_end = _erodata,

    .frame = {
        { __start_bug_frames_0, __stop_bug_frames_0 },
        { __start_bug_frames_1, __stop_bug_frames_1 },
        { __start_bug_frames_2, __stop_bug_frames_2 },
        { __start_bug_frames_3, __stop_bug_frames_3 },
    },

#ifdef CONFIG_HAS_EX_TABLE
    .ex = __start___ex_table,
    .ex_end = __stop___ex_table,
#endif
};

/* Becomes irrelevant when __init sections are cleared. */
static struct virtual_region core_init __initdata = {
    .list = LIST_ENTRY_INIT(),
    .text_start = _sinittext,
    .text_end = _einittext,

    .frame = {
        { __start_bug_frames_0, __stop_bug_frames_0 },
        { __start_bug_frames_1, __stop_bug_frames_1 },
        { __start_bug_frames_2, __stop_bug_frames_2 },
        { __start_bug_frames_3, __stop_bug_frames_3 },
    },

#ifdef CONFIG_HAS_EX_TABLE
    .ex = __start___ex_table,
    .ex_end = __stop___ex_table,
#endif
};

/*
 * RCU locking. Modifications to the list must be done in exclusive mode, and
 * hence need to hold the spinlock.
 *
 * All readers of virtual_region_list MUST use list_for_each_entry_rcu.
 */
static struct list_head virtual_region_list = LIST_ENTRY_HEAD();
static DEFINE_SPINLOCK(virtual_region_lock);
static DEFINE_RCU_READ_LOCK(rcu_virtual_region_lock);

const struct virtual_region *find_text_region(unsigned long addr)
{
    const struct virtual_region *iter, *region = NULL;

    rcu_read_lock(&rcu_virtual_region_lock);
    list_for_each_entry_rcu ( iter, &virtual_region_list, list )
    {
        if ( (void *)addr >= iter->text_start &&
             (void *)addr <  iter->text_end )
        {
            region = iter;
            break;
        }
    }
    rcu_read_unlock(&rcu_virtual_region_lock);

    return region;
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
void register_virtual_region(struct virtual_region *r)
{
    unsigned long flags;

    spin_lock_irqsave(&virtual_region_lock, flags);
    list_add_tail_rcu(&r->list, &virtual_region_list);
    spin_unlock_irqrestore(&virtual_region_lock, flags);
}

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
                                 (unsigned long)region->text_end,
                                 PAGE_HYPERVISOR_RWX);
        if ( region->rodata_start )
            modify_xen_mappings_lite((unsigned long)region->rodata_start,
                                     (unsigned long)region->rodata_end,
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
                                 (unsigned long)region->text_end,
                                 PAGE_HYPERVISOR_RX);
        if ( region->rodata_start )
            modify_xen_mappings_lite((unsigned long)region->rodata_start,
                                     (unsigned long)region->rodata_end,
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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
