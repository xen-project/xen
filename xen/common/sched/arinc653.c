/******************************************************************************
 * sched_arinc653.c
 *
 * An ARINC653-compatible scheduling algorithm for use in Xen.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (c) 2010, DornerWorks, Ltd. <DornerWorks.com>
 */

#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/timer.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <xen/errno.h>
#include <xen/list.h>
#include <xen/guest_access.h>
#include <public/sysctl.h>

#include "private.h"

/**************************************************************************
 * Private Macros                                                         *
 **************************************************************************/

/**
 * Default timeslice for domain 0.
 */
#define DEFAULT_TIMESLICE MILLISECS(10)

/**
 * Retrieve the idle UNIT for a given physical CPU
 */
#define IDLETASK(cpu)  (sched_idle_unit(cpu))

/**
 * Return a pointer to the ARINC 653-specific scheduler data information
 * associated with the given UNIT (unit)
 */
#define AUNIT(unit) ((arinc653_unit_t *)(unit)->priv)

/**
 * Return the global scheduler private data given the scheduler ops pointer
 */
#define SCHED_PRIV(s) ((a653sched_priv_t *)((s)->sched_data))

/**************************************************************************
 * Private Type Definitions                                               *
 **************************************************************************/

/**
 * The arinc653_unit_t structure holds ARINC 653-scheduler-specific
 * information for all non-idle UNITs
 */
typedef struct arinc653_unit_s
{
    /* unit points to Xen's struct sched_unit so we can get to it from an
     * arinc653_unit_t pointer. */
    struct sched_unit * unit;
    /* awake holds whether the UNIT has been woken with vcpu_wake() */
    bool                awake;
    /* list holds the linked list information for the list this UNIT
     * is stored in */
    struct list_head    list;
} arinc653_unit_t;

/**
 * The sched_entry_t structure holds a single entry of the
 * ARINC 653 schedule.
 */
typedef struct sched_entry_s
{
    /* dom_handle holds the handle ("UUID") for the domain that this
     * schedule entry refers to. */
    xen_domain_handle_t dom_handle;
    /* unit_id holds the UNIT number for the UNIT that this schedule
     * entry refers to. */
    int                 unit_id;
    /* runtime holds the number of nanoseconds that the UNIT for this
     * schedule entry should be allowed to run per major frame. */
    s_time_t            runtime;
    /* unit holds a pointer to the Xen sched_unit structure */
    struct sched_unit * unit;
} sched_entry_t;

/**
 * This structure defines data that is global to an instance of the scheduler
 */
typedef struct a653sched_priv_s
{
    /* lock for the whole pluggable scheduler, nests inside cpupool_lock */
    spinlock_t lock;

    /**
     * This array holds the active ARINC 653 schedule.
     *
     * When the system tries to start a new UNIT, this schedule is scanned
     * to look for a matching (handle, UNIT #) pair. If both the handle (UUID)
     * and UNIT number match, then the UNIT is allowed to run. Its run time
     * (per major frame) is given in the third entry of the schedule.
     */
    sched_entry_t schedule[ARINC653_MAX_DOMAINS_PER_SCHEDULE];

    /**
     * This variable holds the number of entries that are valid in
     * the arinc653_schedule table.
     *
     * This is not necessarily the same as the number of domains in the
     * schedule. A domain could be listed multiple times within the schedule,
     * or a domain with multiple UNITs could have a different
     * schedule entry for each UNIT.
     */
    unsigned int num_schedule_entries;

    /**
     * the major frame time for the ARINC 653 schedule.
     */
    s_time_t major_frame;

    /**
     * the time that the next major frame starts
     */
    s_time_t next_major_frame;

    /**
     * pointers to all Xen UNIT structures for iterating through
     */
    struct list_head unit_list;
} a653sched_priv_t;

/**************************************************************************
 * Helper functions                                                       *
 **************************************************************************/

/**
 * This function compares two domain handles.
 *
 * @param h1        Pointer to handle 1
 * @param h2        Pointer to handle 2
 *
 * @return          <ul>
 *                  <li> <0:  handle 1 is less than handle 2
 *                  <li>  0:  handle 1 is equal to handle 2
 *                  <li> >0:  handle 1 is greater than handle 2
 *                  </ul>
 */
static int dom_handle_cmp(const xen_domain_handle_t h1,
                          const xen_domain_handle_t h2)
{
    return memcmp(h1, h2, sizeof(xen_domain_handle_t));
}

/**
 * This function searches the unit list to find a UNIT that matches
 * the domain handle and UNIT ID specified.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param handle    Pointer to handler
 * @param unit_id   UNIT ID
 *
 * @return          <ul>
 *                  <li> Pointer to the matching UNIT if one is found
 *                  <li> NULL otherwise
 *                  </ul>
 */
static struct sched_unit *find_unit(
    const struct scheduler *ops,
    xen_domain_handle_t handle,
    int unit_id)
{
    arinc653_unit_t *aunit;

    /* loop through the unit_list looking for the specified UNIT */
    list_for_each_entry ( aunit, &SCHED_PRIV(ops)->unit_list, list )
        if ( (dom_handle_cmp(aunit->unit->domain->handle, handle) == 0)
             && (unit_id == aunit->unit->unit_id) )
            return aunit->unit;

    return NULL;
}

/**
 * This function updates the pointer to the Xen UNIT structure for each entry
 * in the ARINC 653 schedule.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @return          <None>
 */
static void update_schedule_units(const struct scheduler *ops)
{
    unsigned int i, n_entries = SCHED_PRIV(ops)->num_schedule_entries;

    for ( i = 0; i < n_entries; i++ )
        SCHED_PRIV(ops)->schedule[i].unit =
            find_unit(ops,
                      SCHED_PRIV(ops)->schedule[i].dom_handle,
                      SCHED_PRIV(ops)->schedule[i].unit_id);
}

/**
 * This function is called by the adjust_global scheduler hook to put
 * in place a new ARINC653 schedule.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 *
 * @return          <ul>
 *                  <li> 0 = success
 *                  <li> !0 = error
 *                  </ul>
 */
static int
arinc653_sched_set(
    const struct scheduler *ops,
    struct xen_sysctl_arinc653_schedule *schedule)
{
    a653sched_priv_t *sched_priv = SCHED_PRIV(ops);
    s_time_t total_runtime = 0;
    unsigned int i;
    unsigned long flags;
    int rc = -EINVAL;

    spin_lock_irqsave(&sched_priv->lock, flags);

    /* Check for valid major frame and number of schedule entries. */
    if ( (schedule->major_frame <= 0)
         || (schedule->num_sched_entries < 1)
         || (schedule->num_sched_entries > ARINC653_MAX_DOMAINS_PER_SCHEDULE) )
        goto fail;

    for ( i = 0; i < schedule->num_sched_entries; i++ )
    {
        /* Check for a valid run time. */
        if ( schedule->sched_entries[i].runtime <= 0 )
            goto fail;

        /* Add this entry's run time to total run time. */
        total_runtime += schedule->sched_entries[i].runtime;
    }

    /*
     * Error if the major frame is not large enough to run all entries as
     * indicated by comparing the total run time to the major frame length.
     */
    if ( total_runtime > schedule->major_frame )
        goto fail;

    /* Copy the new schedule into place. */
    sched_priv->num_schedule_entries = schedule->num_sched_entries;
    sched_priv->major_frame = schedule->major_frame;
    for ( i = 0; i < schedule->num_sched_entries; i++ )
    {
        memcpy(sched_priv->schedule[i].dom_handle,
               schedule->sched_entries[i].dom_handle,
               sizeof(sched_priv->schedule[i].dom_handle));
        sched_priv->schedule[i].unit_id =
            schedule->sched_entries[i].vcpu_id;
        sched_priv->schedule[i].runtime =
            schedule->sched_entries[i].runtime;
    }
    update_schedule_units(ops);

    /*
     * The newly-installed schedule takes effect immediately. We do not even
     * wait for the current major frame to expire.
     *
     * Signal a new major frame to begin. The next major frame is set up by
     * the do_schedule callback function when it is next invoked.
     */
    sched_priv->next_major_frame = NOW();

    rc = 0;

 fail:
    spin_unlock_irqrestore(&sched_priv->lock, flags);
    return rc;
}

/**
 * This function is called by the adjust_global scheduler hook to read the
 * current ARINC 653 schedule
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @return          <ul>
 *                  <li> 0 = success
 *                  <li> !0 = error
 *                  </ul>
 */
static int
arinc653_sched_get(
    const struct scheduler *ops,
    struct xen_sysctl_arinc653_schedule *schedule)
{
    a653sched_priv_t *sched_priv = SCHED_PRIV(ops);
    unsigned int i;
    unsigned long flags;

    spin_lock_irqsave(&sched_priv->lock, flags);

    schedule->num_sched_entries = sched_priv->num_schedule_entries;
    schedule->major_frame = sched_priv->major_frame;
    for ( i = 0; i < sched_priv->num_schedule_entries; i++ )
    {
        memcpy(schedule->sched_entries[i].dom_handle,
               sched_priv->schedule[i].dom_handle,
               sizeof(sched_priv->schedule[i].dom_handle));
        schedule->sched_entries[i].vcpu_id = sched_priv->schedule[i].unit_id;
        schedule->sched_entries[i].runtime = sched_priv->schedule[i].runtime;
    }

    spin_unlock_irqrestore(&sched_priv->lock, flags);

    return 0;
}

/**************************************************************************
 * Scheduler callback functions                                           *
 **************************************************************************/

/**
 * This function performs initialization for an instance of the scheduler.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 *
 * @return          <ul>
 *                  <li> 0 = success
 *                  <li> !0 = error
 *                  </ul>
 */
static int
a653sched_init(struct scheduler *ops)
{
    a653sched_priv_t *prv;

    prv = xzalloc(a653sched_priv_t);
    if ( prv == NULL )
        return -ENOMEM;

    ops->sched_data = prv;

    prv->next_major_frame = 0;
    spin_lock_init(&prv->lock);
    INIT_LIST_HEAD(&prv->unit_list);

    return 0;
}

/**
 * This function performs deinitialization for an instance of the scheduler
 *
 * @param ops       Pointer to this instance of the scheduler structure
 */
static void
a653sched_deinit(struct scheduler *ops)
{
    xfree(SCHED_PRIV(ops));
    ops->sched_data = NULL;
}

/**
 * This function allocates scheduler-specific data for a UNIT
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param unit      Pointer to struct sched_unit
 *
 * @return          Pointer to the allocated data
 */
static void *
a653sched_alloc_udata(const struct scheduler *ops, struct sched_unit *unit,
                      void *dd)
{
    a653sched_priv_t *sched_priv = SCHED_PRIV(ops);
    arinc653_unit_t *svc;
    unsigned int entry;
    unsigned long flags;

    /*
     * Allocate memory for the ARINC 653-specific scheduler data information
     * associated with the given UNIT (unit).
     */
    svc = xmalloc(arinc653_unit_t);
    if ( svc == NULL )
        return NULL;

    spin_lock_irqsave(&sched_priv->lock, flags);

    /*
     * Add every one of dom0's units to the schedule, as long as there are
     * slots available.
     */
    if ( unit->domain->domain_id == 0 )
    {
        entry = sched_priv->num_schedule_entries;

        if ( entry < ARINC653_MAX_DOMAINS_PER_SCHEDULE )
        {
            sched_priv->schedule[entry].dom_handle[0] = '\0';
            sched_priv->schedule[entry].unit_id = unit->unit_id;
            sched_priv->schedule[entry].runtime = DEFAULT_TIMESLICE;
            sched_priv->schedule[entry].unit = unit;

            sched_priv->major_frame += DEFAULT_TIMESLICE;
            ++sched_priv->num_schedule_entries;
        }
    }

    /*
     * Initialize our ARINC 653 scheduler-specific information for the UNIT.
     * The UNIT starts "asleep." When Xen is ready for the UNIT to run, it
     * will call the vcpu_wake scheduler callback function and our scheduler
     * will mark the UNIT awake.
     */
    svc->unit = unit;
    svc->awake = false;
    if ( !is_idle_unit(unit) )
        list_add(&svc->list, &SCHED_PRIV(ops)->unit_list);
    update_schedule_units(ops);

    spin_unlock_irqrestore(&sched_priv->lock, flags);

    return svc;
}

/**
 * This function frees scheduler-specific UNIT data
 *
 * @param ops       Pointer to this instance of the scheduler structure
 */
static void
a653sched_free_udata(const struct scheduler *ops, void *priv)
{
    a653sched_priv_t *sched_priv = SCHED_PRIV(ops);
    arinc653_unit_t *av = priv;
    unsigned long flags;

    if (av == NULL)
        return;

    spin_lock_irqsave(&sched_priv->lock, flags);

    if ( !is_idle_unit(av->unit) )
        list_del(&av->list);

    xfree(av);
    update_schedule_units(ops);

    spin_unlock_irqrestore(&sched_priv->lock, flags);
}

/**
 * Xen scheduler callback function to sleep a UNIT
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param unit      Pointer to struct sched_unit
 */
static void
a653sched_unit_sleep(const struct scheduler *ops, struct sched_unit *unit)
{
    if ( AUNIT(unit) != NULL )
        AUNIT(unit)->awake = false;

    /*
     * If the UNIT being put to sleep is the same one that is currently
     * running, raise a softirq to invoke the scheduler to switch domains.
     */
    if ( get_sched_res(sched_unit_master(unit))->curr == unit )
        cpu_raise_softirq(sched_unit_master(unit), SCHEDULE_SOFTIRQ);
}

/**
 * Xen scheduler callback function to wake up a UNIT
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param unit      Pointer to struct sched_unit
 */
static void
a653sched_unit_wake(const struct scheduler *ops, struct sched_unit *unit)
{
    if ( AUNIT(unit) != NULL )
        AUNIT(unit)->awake = true;

    cpu_raise_softirq(sched_unit_master(unit), SCHEDULE_SOFTIRQ);
}

/**
 * Xen scheduler callback function to select a UNIT to run.
 * This is the main scheduler routine.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param now       Current time
 */
static void
a653sched_do_schedule(
    const struct scheduler *ops,
    struct sched_unit *prev,
    s_time_t now,
    bool tasklet_work_scheduled)
{
    struct sched_unit *new_task = NULL;
    static unsigned int sched_index = 0;
    static s_time_t next_switch_time;
    a653sched_priv_t *sched_priv = SCHED_PRIV(ops);
    const unsigned int cpu = sched_get_resource_cpu(smp_processor_id());
    unsigned long flags;

    spin_lock_irqsave(&sched_priv->lock, flags);

    if ( sched_priv->num_schedule_entries < 1 )
        sched_priv->next_major_frame = now + DEFAULT_TIMESLICE;
    else if ( now >= sched_priv->next_major_frame )
    {
        /* time to enter a new major frame
         * the first time this function is called, this will be true */
        /* start with the first domain in the schedule */
        sched_index = 0;
        sched_priv->next_major_frame = now + sched_priv->major_frame;
        next_switch_time = now + sched_priv->schedule[0].runtime;
    }
    else
    {
        while ( (now >= next_switch_time)
                && (sched_index < sched_priv->num_schedule_entries) )
        {
            /* time to switch to the next domain in this major frame */
            sched_index++;
            next_switch_time += sched_priv->schedule[sched_index].runtime;
        }
    }

    /*
     * If we exhausted the domains in the schedule and still have time left
     * in the major frame then switch next at the next major frame.
     */
    if ( sched_index >= sched_priv->num_schedule_entries )
        next_switch_time = sched_priv->next_major_frame;

    /*
     * If there are more domains to run in the current major frame, set
     * new_task equal to the address of next domain's sched_unit structure.
     * Otherwise, set new_task equal to the address of the idle task's
     * sched_unit structure.
     */
    new_task = (sched_index < sched_priv->num_schedule_entries)
        ? sched_priv->schedule[sched_index].unit
        : IDLETASK(cpu);

    /* Check to see if the new task can be run (awake & runnable). */
    if ( !((new_task != NULL)
           && (AUNIT(new_task) != NULL)
           && AUNIT(new_task)->awake
           && unit_runnable_state(new_task)) )
        new_task = IDLETASK(cpu);
    BUG_ON(new_task == NULL);

    /*
     * Check to make sure we did not miss a major frame.
     * This is a good test for robust partitioning.
     */
    BUG_ON(now >= sched_priv->next_major_frame);

    spin_unlock_irqrestore(&sched_priv->lock, flags);

    /* Tasklet work (which runs in idle UNIT context) overrides all else. */
    if ( tasklet_work_scheduled )
        new_task = IDLETASK(cpu);

    /* Running this task would result in a migration */
    if ( !is_idle_unit(new_task)
         && (sched_unit_master(new_task) != cpu) )
        new_task = IDLETASK(cpu);

    /*
     * Return the amount of time the next domain has to run and the address
     * of the selected task's UNIT structure.
     */
    prev->next_time = next_switch_time - now;
    prev->next_task = new_task;
    new_task->migrated = false;

    BUG_ON(prev->next_time <= 0);
}

/**
 * Xen scheduler callback function to select a resource for the UNIT to run on
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param unit      Pointer to struct sched_unit
 *
 * @return          Scheduler resource to run on
 */
static struct sched_resource *
a653sched_pick_resource(const struct scheduler *ops,
                        const struct sched_unit *unit)
{
    const cpumask_t *online;
    unsigned int cpu;

    /*
     * If present, prefer unit's current processor, else
     * just find the first valid unit.
     */
    online = cpupool_domain_master_cpumask(unit->domain);

    cpu = cpumask_first(online);

    if ( cpumask_test_cpu(sched_unit_master(unit), online)
         || (cpu >= nr_cpu_ids) )
        cpu = sched_unit_master(unit);

    return get_sched_res(cpu);
}

/**
 * Xen scheduler callback to change the scheduler of a cpu
 *
 * @param new_ops   Pointer to this instance of the scheduler structure
 * @param cpu       The cpu that is changing scheduler
 * @param pdata     scheduler specific PCPU data (we don't have any)
 * @param vdata     scheduler specific UNIT data of the idle unit
 */
static spinlock_t *
a653_switch_sched(struct scheduler *new_ops, unsigned int cpu,
                  void *pdata, void *vdata)
{
    struct sched_resource *sr = get_sched_res(cpu);
    const arinc653_unit_t *svc = vdata;

    ASSERT(!pdata && svc && is_idle_unit(svc->unit));

    sched_idle_unit(cpu)->priv = vdata;

    return &sr->_lock;
}

/**
 * Xen scheduler callback function to perform a global (not domain-specific)
 * adjustment. It is used by the ARINC 653 scheduler to put in place a new
 * ARINC 653 schedule or to retrieve the schedule currently in place.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param sc        Pointer to the scheduler operation specified by Domain 0
 */
static int
a653sched_adjust_global(const struct scheduler *ops,
                        struct xen_sysctl_scheduler_op *sc)
{
    struct xen_sysctl_arinc653_schedule local_sched;
    int rc = -EINVAL;

    switch ( sc->cmd )
    {
    case XEN_SYSCTL_SCHEDOP_putinfo:
        if ( copy_from_guest(&local_sched, sc->u.sched_arinc653.schedule, 1) )
        {
            rc = -EFAULT;
            break;
        }

        rc = arinc653_sched_set(ops, &local_sched);
        break;
    case XEN_SYSCTL_SCHEDOP_getinfo:
        memset(&local_sched, -1, sizeof(local_sched));
        rc = arinc653_sched_get(ops, &local_sched);
        if ( rc )
            break;

        if ( copy_to_guest(sc->u.sched_arinc653.schedule, &local_sched, 1) )
            rc = -EFAULT;
        break;
    }

    return rc;
}

/**
 * This structure defines our scheduler for Xen.
 * The entries tell Xen where to find our scheduler-specific
 * callback functions.
 * The symbol must be visible to the rest of Xen at link time.
 */
static const struct scheduler sched_arinc653_def = {
    .name           = "ARINC 653 Scheduler",
    .opt_name       = "arinc653",
    .sched_id       = XEN_SCHEDULER_ARINC653,
    .sched_data     = NULL,

    .init           = a653sched_init,
    .deinit         = a653sched_deinit,

    .free_udata     = a653sched_free_udata,
    .alloc_udata    = a653sched_alloc_udata,

    .insert_unit    = NULL,
    .remove_unit    = NULL,

    .sleep          = a653sched_unit_sleep,
    .wake           = a653sched_unit_wake,
    .yield          = NULL,
    .context_saved  = NULL,

    .do_schedule    = a653sched_do_schedule,

    .pick_resource  = a653sched_pick_resource,

    .switch_sched   = a653_switch_sched,

    .adjust         = NULL,
    .adjust_global  = a653sched_adjust_global,

    .dump_settings  = NULL,
    .dump_cpu_state = NULL,
};

REGISTER_SCHEDULER(sched_arinc653_def);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
