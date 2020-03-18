/*
 * Intel CPU Microcode Update Driver for Linux
 *
 * Copyright (C) 2000-2006 Tigran Aivazian <tigran@aivazian.fsnet.co.uk>
 *               2006      Shaohua Li <shaohua.li@intel.com> *
 * This driver allows to upgrade microcode on Intel processors
 * belonging to IA-32 family - PentiumPro, Pentium II,
 * Pentium III, Xeon, Pentium 4, etc.
 *
 * Reference: Section 8.11 of Volume 3a, IA-32 Intel? Architecture
 * Software Developer's Manual
 * Order Number 253668 or free download from:
 *
 * http://developer.intel.com/design/pentium4/manuals/253668.htm
 *
 * For more information, go to http://www.urbanmyth.org/microcode
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <xen/cpu.h>
#include <xen/err.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/lib.h>
#include <xen/notifier.h>
#include <xen/param.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include <xen/spinlock.h>
#include <xen/stop_machine.h>
#include <xen/tasklet.h>
#include <xen/guest_access.h>
#include <xen/earlycpio.h>
#include <xen/watchdog.h>

#include <asm/apic.h>
#include <asm/delay.h>
#include <asm/msr.h>
#include <asm/nmi.h>
#include <asm/processor.h>
#include <asm/setup.h>
#include <asm/microcode.h>

/*
 * Before performing a late microcode update on any thread, we
 * rendezvous all cpus in stop_machine context. The timeout for
 * waiting for cpu rendezvous is 30ms. It is the timeout used by
 * live patching
 */
#define MICROCODE_CALLIN_TIMEOUT_US 30000

/*
 * Timeout for each thread to complete update is set to 1s. It is a
 * conservative choice considering all possible interference.
 */
#define MICROCODE_UPDATE_TIMEOUT_US 1000000

static module_t __initdata ucode_mod;
static signed int __initdata ucode_mod_idx;
static bool_t __initdata ucode_mod_forced;
static unsigned int nr_cores;

/*
 * These states help to coordinate CPUs during loading an update.
 *
 * The semantics of each state is as follow:
 *  - LOADING_PREPARE: initial state of 'loading_state'.
 *  - LOADING_CALLIN: CPUs are allowed to callin.
 *  - LOADING_ENTER: all CPUs have called in. Initiate ucode loading.
 *  - LOADING_EXIT: ucode loading is done or aborted.
 */
static enum {
    LOADING_PREPARE,
    LOADING_CALLIN,
    LOADING_ENTER,
    LOADING_EXIT,
} loading_state;

/*
 * If we scan the initramfs.cpio for the early microcode code
 * and find it, then 'ucode_blob' will contain the pointer
 * and the size of said blob. It is allocated from Xen's heap
 * memory.
 */
struct ucode_mod_blob {
    const void *data;
    size_t size;
};

static struct ucode_mod_blob __initdata ucode_blob;
/*
 * By default we will NOT parse the multiboot modules to see if there is
 * cpio image with the microcode images.
 */
static bool_t __initdata ucode_scan;

/* By default, ucode loading is done in NMI handler */
static bool ucode_in_nmi = true;

/* Protected by microcode_mutex */
static struct microcode_patch *microcode_cache;

void __init microcode_set_module(unsigned int idx)
{
    ucode_mod_idx = idx;
    ucode_mod_forced = 1;
}

/*
 * The format is '[<integer>|scan=<bool>, nmi=<bool>]'. Both options are
 * optional. If the EFI has forced which of the multiboot payloads is to be
 * used, only nmi=<bool> is parsed.
 */
static int __init parse_ucode(const char *s)
{
    const char *ss;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_boolean("nmi", s, ss)) >= 0 )
            ucode_in_nmi = val;
        else if ( !ucode_mod_forced ) /* Not forced by EFI */
        {
            if ( (val = parse_boolean("scan", s, ss)) >= 0 )
                ucode_scan = val;
            else
            {
                const char *q;

                ucode_mod_idx = simple_strtol(s, &q, 0);
                if ( q != ss )
                    rc = -EINVAL;
            }
        }

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("ucode", parse_ucode);

void __init microcode_scan_module(
    unsigned long *module_map,
    const multiboot_info_t *mbi)
{
    module_t *mod = (module_t *)__va(mbi->mods_addr);
    uint64_t *_blob_start;
    unsigned long _blob_size;
    struct cpio_data cd;
    long offset;
    const char *p = NULL;
    int i;

    ucode_blob.size = 0;
    if ( !ucode_scan )
        return;

    if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        p = "kernel/x86/microcode/AuthenticAMD.bin";
    else if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        p = "kernel/x86/microcode/GenuineIntel.bin";
    else
        return;

    /*
     * Try all modules and see whichever could be the microcode blob.
     */
    for ( i = 1 /* Ignore dom0 kernel */; i < mbi->mods_count; i++ )
    {
        if ( !test_bit(i, module_map) )
            continue;

        _blob_start = bootstrap_map(&mod[i]);
        _blob_size = mod[i].mod_end;
        if ( !_blob_start )
        {
            printk("Could not map multiboot module #%d (size: %ld)\n",
                   i, _blob_size);
            continue;
        }
        cd.data = NULL;
        cd.size = 0;
        cd = find_cpio_data(p, _blob_start, _blob_size, &offset /* ignore */);
        if ( cd.data )
        {
            ucode_blob.size = cd.size;
            ucode_blob.data = cd.data;
            break;
        }
        bootstrap_map(NULL);
    }
}
void __init microcode_grab_module(
    unsigned long *module_map,
    const multiboot_info_t *mbi)
{
    module_t *mod = (module_t *)__va(mbi->mods_addr);

    if ( ucode_mod_idx < 0 )
        ucode_mod_idx += mbi->mods_count;
    if ( ucode_mod_idx <= 0 || ucode_mod_idx >= mbi->mods_count ||
         !__test_and_clear_bit(ucode_mod_idx, module_map) )
        goto scan;
    ucode_mod = mod[ucode_mod_idx];
scan:
    if ( ucode_scan )
        microcode_scan_module(module_map, mbi);
}

const struct microcode_ops *microcode_ops;

static DEFINE_SPINLOCK(microcode_mutex);

DEFINE_PER_CPU(struct cpu_signature, cpu_sig);
/* Store error code of the work done in NMI handler */
static DEFINE_PER_CPU(int, loading_err);

/*
 * Count the CPUs that have entered, exited the rendezvous and succeeded in
 * microcode update during late microcode update respectively.
 *
 * Note that a bitmap is used for callin to allow cpu to set a bit multiple
 * times. It is required to do busy-loop in #NMI handling.
 */
static cpumask_t cpu_callin_map;
static atomic_t cpu_out, cpu_updated;
static const struct microcode_patch *nmi_patch = ZERO_BLOCK_PTR;

/*
 * Return a patch that covers current CPU. If there are multiple patches,
 * return the one with the highest revision number. Return error If no
 * patch is found and an error occurs during the parsing process. Otherwise
 * return NULL.
 */
static struct microcode_patch *parse_blob(const char *buf, size_t len)
{
    if ( likely(!microcode_ops->collect_cpu_info(&this_cpu(cpu_sig))) )
        return microcode_ops->cpu_request_microcode(buf, len);

    return NULL;
}

static void microcode_free_patch(struct microcode_patch *microcode_patch)
{
    microcode_ops->free_patch(microcode_patch->mc);
    xfree(microcode_patch);
}

/* Return true if cache gets updated. Otherwise, return false */
static bool microcode_update_cache(struct microcode_patch *patch)
{
    ASSERT(spin_is_locked(&microcode_mutex));

    if ( !microcode_cache )
        microcode_cache = patch;
    else if ( microcode_ops->compare_patch(patch,
                                           microcode_cache) == NEW_UCODE )
    {
        microcode_free_patch(microcode_cache);
        microcode_cache = patch;
    }
    else
    {
        microcode_free_patch(patch);
        return false;
    }

    return true;
}

/* Wait for a condition to be met with a timeout (us). */
static int wait_for_condition(bool (*func)(unsigned int data),
                              unsigned int data, unsigned int timeout)
{
    while ( !func(data) )
    {
        if ( !timeout-- )
        {
            printk("CPU%u: Timeout in %pS\n",
                   smp_processor_id(), __builtin_return_address(0));
            return -EBUSY;
        }
        udelay(1);
    }

    return 0;
}

static bool wait_cpu_callin(unsigned int nr)
{
    return cpumask_weight(&cpu_callin_map) >= nr;
}

static bool wait_cpu_callout(unsigned int nr)
{
    return atomic_read(&cpu_out) >= nr;
}

/*
 * Load a microcode update to current CPU.
 *
 * If no patch is provided, the cached patch will be loaded. Microcode update
 * during APs bringup and CPU resuming falls into this case.
 */
static int microcode_update_cpu(const struct microcode_patch *patch)
{
    int err = microcode_ops->collect_cpu_info(&this_cpu(cpu_sig));

    if ( unlikely(err) )
        return err;

    spin_lock(&microcode_mutex);
    if ( patch )
        err = microcode_ops->apply_microcode(patch);
    else if ( microcode_cache )
    {
        err = microcode_ops->apply_microcode(microcode_cache);
        if ( err == -EIO )
        {
            microcode_free_patch(microcode_cache);
            microcode_cache = NULL;
        }
    }
    else
        /* No patch to update */
        err = -ENOENT;
    spin_unlock(&microcode_mutex);

    return err;
}

static bool wait_for_state(typeof(loading_state) state)
{
    typeof(loading_state) cur_state;

    while ( (cur_state = ACCESS_ONCE(loading_state)) != state )
    {
        if ( cur_state == LOADING_EXIT )
            return false;
        cpu_relax();
    }

    return true;
}

static void set_state(typeof(loading_state) state)
{
    ACCESS_ONCE(loading_state) = state;
}

static int secondary_nmi_work(void)
{
    cpumask_set_cpu(smp_processor_id(), &cpu_callin_map);

    return wait_for_state(LOADING_EXIT) ? 0 : -EBUSY;
}

static int primary_thread_work(const struct microcode_patch *patch)
{
    int ret;

    cpumask_set_cpu(smp_processor_id(), &cpu_callin_map);

    if ( !wait_for_state(LOADING_ENTER) )
        return -EBUSY;

    ret = microcode_ops->apply_microcode(patch);
    if ( !ret )
        atomic_inc(&cpu_updated);
    atomic_inc(&cpu_out);

    return ret;
}

static int microcode_nmi_callback(const struct cpu_user_regs *regs, int cpu)
{
    unsigned int primary = cpumask_first(this_cpu(cpu_sibling_mask));
    int ret;

    /* System-generated NMI, leave to main handler */
    if ( ACCESS_ONCE(loading_state) != LOADING_CALLIN )
        return 0;

    /*
     * Primary threads load ucode in NMI handler on if ucode_in_nmi is true.
     * Secondary threads are expected to stay in NMI handler regardless of
     * ucode_in_nmi.
     */
    if ( cpu == cpumask_first(&cpu_online_map) ||
         (!ucode_in_nmi && cpu == primary) )
        return 0;

    if ( cpu == primary )
        ret = primary_thread_work(nmi_patch);
    else
        ret = secondary_nmi_work();
    this_cpu(loading_err) = ret;

    return 0;
}

static int secondary_thread_fn(void)
{
    if ( !wait_for_state(LOADING_CALLIN) )
        return -EBUSY;

    self_nmi();

    /*
     * Wait for ucode loading is done in case that the NMI does not arrive
     * synchronously, which may lead to a not-yet-updated CPU signature is
     * copied below.
     */
    if ( unlikely(!wait_for_state(LOADING_EXIT)) )
        ASSERT_UNREACHABLE();

    /* Copy update revision from the primary thread. */
    this_cpu(cpu_sig).rev =
        per_cpu(cpu_sig, cpumask_first(this_cpu(cpu_sibling_mask))).rev;

    return this_cpu(loading_err);
}

static int primary_thread_fn(const struct microcode_patch *patch)
{
    if ( !wait_for_state(LOADING_CALLIN) )
        return -EBUSY;

    if ( ucode_in_nmi )
    {
        self_nmi();

        /*
         * Wait for ucode loading is done in case that the NMI does not arrive
         * synchronously, which may lead to a not-yet-updated error is returned
         * below.
         */
        if ( unlikely(!wait_for_state(LOADING_EXIT)) )
            ASSERT_UNREACHABLE();

        return this_cpu(loading_err);
    }

    return primary_thread_work(patch);
}

static int control_thread_fn(const struct microcode_patch *patch)
{
    unsigned int cpu = smp_processor_id(), done;
    unsigned long tick;
    int ret;
    nmi_callback_t *saved_nmi_callback;

    /*
     * We intend to keep interrupt disabled for a long time, which may lead to
     * watchdog timeout.
     */
    watchdog_disable();

    nmi_patch = patch;
    smp_wmb();
    saved_nmi_callback = set_nmi_callback(microcode_nmi_callback);

    /* Allow threads to call in */
    set_state(LOADING_CALLIN);

    cpumask_set_cpu(cpu, &cpu_callin_map);

    /* Waiting for all threads calling in */
    ret = wait_for_condition(wait_cpu_callin, num_online_cpus(),
                             MICROCODE_CALLIN_TIMEOUT_US);
    if ( ret )
    {
        set_state(LOADING_EXIT);
        return ret;
    }

    /* Control thread loads ucode first while others are in NMI handler. */
    ret = microcode_ops->apply_microcode(patch);
    if ( !ret )
        atomic_inc(&cpu_updated);
    atomic_inc(&cpu_out);

    if ( ret == -EIO )
    {
        printk(XENLOG_ERR
               "Late loading aborted: CPU%u failed to update ucode\n", cpu);
        set_state(LOADING_EXIT);
        return ret;
    }

    /* Let primary threads load the given ucode update */
    set_state(LOADING_ENTER);

    tick = rdtsc_ordered();
    /* Wait for primary threads finishing update */
    while ( (done = atomic_read(&cpu_out)) != nr_cores )
    {
        /*
         * During each timeout interval, at least a CPU is expected to
         * finish its update. Otherwise, something goes wrong.
         *
         * Note that RDTSC (in wait_for_condition()) is safe for threads to
         * execute while waiting for completion of loading an update.
         */
        if ( wait_for_condition(wait_cpu_callout, (done + 1),
                                MICROCODE_UPDATE_TIMEOUT_US) )
            panic("Timeout when finished updating microcode (finished %u/%u)",
                  done, nr_cores);

        /* Print warning message once if long time is spent here */
        if ( tick && rdtsc_ordered() - tick >= cpu_khz * 1000 )
        {
            printk(XENLOG_WARNING
                   "WARNING: UPDATING MICROCODE HAS CONSUMED MORE THAN 1 SECOND!\n");
            tick = 0;
        }
    }

    /* Mark loading is done to unblock other threads */
    set_state(LOADING_EXIT);

    set_nmi_callback(saved_nmi_callback);
    smp_wmb();
    nmi_patch = ZERO_BLOCK_PTR;

    watchdog_enable();

    return ret;
}

static int do_microcode_update(void *patch)
{
    unsigned int cpu = smp_processor_id();
    int ret;

    /*
     * The control thread set state to coordinate ucode loading. Primary
     * threads load the given ucode patch. Secondary threads just wait for
     * the completion of the ucode loading process.
     */
    if ( cpu == cpumask_first(&cpu_online_map) )
        ret = control_thread_fn(patch);
    else if ( cpu == cpumask_first(this_cpu(cpu_sibling_mask)) )
        ret = primary_thread_fn(patch);
    else
        ret = secondary_thread_fn();

    if ( microcode_ops->end_update_percpu )
        microcode_ops->end_update_percpu();

    return ret;
}

struct ucode_buf {
    unsigned int len;
    char buffer[];
};

static long microcode_update_helper(void *data)
{
    int ret;
    struct ucode_buf *buffer = data;
    unsigned int cpu, updated;
    struct microcode_patch *patch;

    /* cpu_online_map must not change during update */
    if ( !get_cpu_maps() )
    {
        xfree(buffer);
        return -EBUSY;
    }

    /*
     * CPUs except the first online CPU would send a fake (self) NMI to
     * rendezvous in NMI handler. But a fake NMI to nmi_cpu may trigger
     * unknown_nmi_error(). It ensures nmi_cpu won't receive a fake NMI.
     */
    if ( unlikely(cpumask_first(&cpu_online_map) != nmi_cpu) )
    {
        xfree(buffer);
        printk(XENLOG_WARNING
               "CPU%u is expected to lead ucode loading (but got CPU%u)\n",
               nmi_cpu, cpumask_first(&cpu_online_map));
        return -EPERM;
    }

    patch = parse_blob(buffer->buffer, buffer->len);
    xfree(buffer);
    if ( IS_ERR(patch) )
    {
        ret = PTR_ERR(patch);
        printk(XENLOG_WARNING "Parsing microcode blob error %d\n", ret);
        goto put;
    }

    if ( !patch )
    {
        printk(XENLOG_WARNING "microcode: couldn't find any matching ucode in "
                              "the provided blob!\n");
        ret = -ENOENT;
        goto put;
    }

    /*
     * If microcode_cache exists, all CPUs in the system should have at least
     * that ucode revision.
     */
    spin_lock(&microcode_mutex);
    if ( microcode_cache &&
         microcode_ops->compare_patch(patch, microcode_cache) != NEW_UCODE )
    {
        spin_unlock(&microcode_mutex);
        printk(XENLOG_WARNING "microcode: couldn't find any newer revision "
                              "in the provided blob!\n");
        microcode_free_patch(patch);
        ret = -ENOENT;

        goto put;
    }
    spin_unlock(&microcode_mutex);

    if ( microcode_ops->start_update )
    {
        ret = microcode_ops->start_update();
        if ( ret )
        {
            microcode_free_patch(patch);
            goto put;
        }
    }

    cpumask_clear(&cpu_callin_map);
    atomic_set(&cpu_out, 0);
    atomic_set(&cpu_updated, 0);
    loading_state = LOADING_PREPARE;

    /* Calculate the number of online CPU core */
    nr_cores = 0;
    for_each_online_cpu(cpu)
        if ( cpu == cpumask_first(per_cpu(cpu_sibling_mask, cpu)) )
            nr_cores++;

    printk(XENLOG_INFO "%u cores are to update their microcode\n", nr_cores);

    /*
     * Late loading dance. Why the heavy-handed stop_machine effort?
     *
     * - HT siblings must be idle and not execute other code while the other
     *   sibling is loading microcode in order to avoid any negative
     *   interactions cause by the loading.
     *
     * - In addition, microcode update on the cores must be serialized until
     *   this requirement can be relaxed in the future. Right now, this is
     *   conservative and good.
     */
    ret = stop_machine_run(do_microcode_update, patch, NR_CPUS);

    updated = atomic_read(&cpu_updated);
    if ( updated > 0 )
    {
        spin_lock(&microcode_mutex);
        microcode_update_cache(patch);
        spin_unlock(&microcode_mutex);
    }
    else
        microcode_free_patch(patch);

    if ( updated && updated != nr_cores )
        printk(XENLOG_ERR "ERROR: Updating microcode succeeded on %u cores and failed\n"
               XENLOG_ERR "on other %u cores. A system with differing microcode\n"
               XENLOG_ERR "revisions is considered unstable. Please reboot and do not\n"
               XENLOG_ERR "load the microcode that triggers this warning!\n",
               updated, nr_cores - updated);

 put:
    put_cpu_maps();
    return ret;
}

int microcode_update(XEN_GUEST_HANDLE_PARAM(const_void) buf, unsigned long len)
{
    int ret;
    struct ucode_buf *buffer;

    if ( len != (uint32_t)len )
        return -E2BIG;

    if ( microcode_ops == NULL )
        return -EINVAL;

    buffer = xmalloc_flex_struct(struct ucode_buf, buffer, len);
    if ( !buffer )
        return -ENOMEM;

    ret = copy_from_guest(buffer->buffer, buf, len);
    if ( ret )
    {
        xfree(buffer);
        return -EFAULT;
    }
    buffer->len = len;

    return continue_hypercall_on_cpu(smp_processor_id(),
                                     microcode_update_helper, buffer);
}

static int __init microcode_init(void)
{
    /*
     * At this point, all CPUs should have updated their microcode
     * via the early_microcode_* paths so free the microcode blob.
     */
    if ( ucode_blob.size )
    {
        bootstrap_map(NULL);
        ucode_blob.size = 0;
        ucode_blob.data = NULL;
    }
    else if ( ucode_mod.mod_end )
    {
        bootstrap_map(NULL);
        ucode_mod.mod_end = 0;
    }

    return 0;
}
__initcall(microcode_init);

/* Load a cached update to current cpu */
int microcode_update_one(bool start_update)
{
    int err;

    if ( !microcode_ops )
        return -EOPNOTSUPP;

    microcode_ops->collect_cpu_info(&this_cpu(cpu_sig));

    if ( start_update && microcode_ops->start_update )
    {
        err = microcode_ops->start_update();
        if ( err )
            return err;
    }

    err = microcode_update_cpu(NULL);

    if ( microcode_ops->end_update_percpu )
        microcode_ops->end_update_percpu();

    return err;
}

/* BSP calls this function to parse ucode blob and then apply an update. */
static int __init early_microcode_update_cpu(void)
{
    int rc = 0;
    const void *data = NULL;
    size_t len;
    struct microcode_patch *patch;

    if ( ucode_blob.size )
    {
        len = ucode_blob.size;
        data = ucode_blob.data;
    }
    else if ( ucode_mod.mod_end )
    {
        len = ucode_mod.mod_end;
        data = bootstrap_map(&ucode_mod);
    }

    if ( !data )
        return -ENOMEM;

    patch = parse_blob(data, len);
    if ( IS_ERR(patch) )
    {
        printk(XENLOG_WARNING "Parsing microcode blob error %ld\n",
               PTR_ERR(patch));
        return PTR_ERR(patch);
    }

    if ( !patch )
        return -ENOENT;

    spin_lock(&microcode_mutex);
    rc = microcode_update_cache(patch);
    spin_unlock(&microcode_mutex);
    ASSERT(rc);

    return microcode_update_one(true);
}

int __init early_microcode_init(void)
{
    int rc;

    rc = microcode_init_intel();
    if ( rc )
        return rc;

    rc = microcode_init_amd();
    if ( rc )
        return rc;

    if ( microcode_ops )
    {
        microcode_ops->collect_cpu_info(&this_cpu(cpu_sig));

        if ( ucode_mod.mod_end || ucode_blob.size )
            rc = early_microcode_update_cpu();
    }

    return rc;
}
