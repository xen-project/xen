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

#include <xen/alternative-call.h>
#include <xen/cpu.h>
#include <xen/delay.h>
#include <xen/earlycpio.h>
#include <xen/err.h>
#include <xen/guest_access.h>
#include <xen/init.h>
#include <xen/param.h>
#include <xen/spinlock.h>
#include <xen/stop_machine.h>
#include <xen/watchdog.h>

#include <asm/apic.h>
#include <asm/bootinfo.h>
#include <asm/cpu-policy.h>
#include <asm/nmi.h>
#include <asm/processor.h>
#include <asm/setup.h>

#include <public/platform.h>

#include "private.h"

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

static bool __initdata ucode_mod_forced;
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

struct patch_with_flags {
    unsigned int flags;
    const struct microcode_patch *patch;
};

/* By default, ucode loading is done in NMI handler */
static bool ucode_in_nmi = true;

/* Protected by microcode_mutex */
static struct microcode_patch *microcode_cache;

/*
 * opt_mod_idx and opt_scan have subtle semantics.
 *
 * The cmdline can either identify a module by number (inc -ve back-reference)
 * containing a raw microcode container, or select scan which instructs Xen to
 * search all modules for an uncompressed CPIO archive containing a file with
 * a vendor-dependent name.
 *
 * These options do not make sense when combined, so for the benefit of module
 * location we require that they are not both active together.
 */
static int __initdata opt_mod_idx;
static bool __initdata opt_scan;

/*
 * Used by the EFI path only, when xen.cfg identifies an explicit microcode
 * file.  Overrides ucode=<int>|scan on the regular command line.
 */
void __init microcode_set_module(unsigned int idx)
{
    opt_mod_idx = idx;
    opt_scan = false;
    ucode_mod_forced = 1;
}

/*
 * The format is '[<integer>|scan=<bool>, nmi=<bool>]'. Both options are
 * optional. If the EFI has forced which of the multiboot payloads is to be
 * used, only nmi=<bool> is parsed.
 */
static int __init cf_check parse_ucode(const char *s)
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
            {
                opt_scan = val;
                opt_mod_idx = 0;
            }
            else
            {
                const char *q;

                opt_mod_idx = simple_strtol(s, &q, 0);
                if ( q != ss )
                {
                    opt_mod_idx = 0;
                    rc = -EINVAL;
                }
                else
                    opt_scan = false;
            }
        }

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("ucode", parse_ucode);

static struct microcode_ops __ro_after_init ucode_ops;

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
static struct patch_with_flags nmi_patch =
{
    .patch  = ZERO_BLOCK_PTR,
};

/*
 * Return a patch that covers current CPU. If there are multiple patches,
 * return the one with the highest revision number. Return error If no
 * patch is found and an error occurs during the parsing process. Otherwise
 * return NULL.
 */
static struct microcode_patch *parse_blob(const char *buf, size_t len)
{
    return alternative_call(ucode_ops.cpu_request_microcode, buf, len, true);
}

/* Returns true if ucode should be loaded on a given cpu */
static bool is_cpu_primary(unsigned int cpu)
{
    if ( boot_cpu_data.x86_vendor & (X86_VENDOR_AMD | X86_VENDOR_HYGON) )
        /* Load ucode on every logical thread/core */
        return true;

    /* Intel CPUs should load ucode only on the first core of SMT siblings */
    if ( cpu == cpumask_first(per_cpu(cpu_sibling_mask, cpu)) )
        return true;

    return false;
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

static bool cf_check wait_cpu_callin(unsigned int nr)
{
    return cpumask_weight(&cpu_callin_map) >= nr;
}

static bool cf_check wait_cpu_callout(unsigned int nr)
{
    return atomic_read(&cpu_out) >= nr;
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

static int primary_thread_work(const struct microcode_patch *patch,
                               unsigned int flags)
{
    int ret;

    cpumask_set_cpu(smp_processor_id(), &cpu_callin_map);

    if ( !wait_for_state(LOADING_ENTER) )
        return -EBUSY;

    ret = alternative_call(ucode_ops.apply_microcode, patch, flags);
    if ( !ret )
        atomic_inc(&cpu_updated);
    atomic_inc(&cpu_out);

    return ret;
}

static int cf_check microcode_nmi_callback(
    const struct cpu_user_regs *regs, int cpu)
{
    bool primary_cpu = is_cpu_primary(cpu);
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
         (!ucode_in_nmi && primary_cpu) )
        return 0;

    if ( primary_cpu )
        ret = primary_thread_work(nmi_patch.patch,
                                  nmi_patch.flags);
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

static int primary_thread_fn(const struct microcode_patch *patch,
                             unsigned int flags)
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

    return primary_thread_work(patch, flags);
}

static int control_thread_fn(const struct microcode_patch *patch,
                             unsigned int flags)
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

    nmi_patch.patch = patch;
    nmi_patch.flags = flags;
    smp_wmb();
    saved_nmi_callback = set_nmi_callback(microcode_nmi_callback);

    /* Allow threads to call in */
    set_state(LOADING_CALLIN);

    cpumask_set_cpu(cpu, &cpu_callin_map);

    /* Waiting for all threads calling in */
    ret = wait_for_condition(wait_cpu_callin, num_online_cpus(),
                             MICROCODE_CALLIN_TIMEOUT_US);
    if ( ret )
        goto out;

    /* Control thread loads ucode first while others are in NMI handler. */
    ret = alternative_call(ucode_ops.apply_microcode, patch, flags);
    if ( !ret )
        atomic_inc(&cpu_updated);
    atomic_inc(&cpu_out);

    if ( ret == -EIO )
    {
        printk(XENLOG_ERR
               "Late loading aborted: CPU%u failed to update ucode\n", cpu);
        goto out;
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
            panic("Timeout when finished updating microcode (finished %u/%u)\n",
                  done, nr_cores);

        /* Print warning message once if long time is spent here */
        if ( tick && rdtsc_ordered() - tick >= cpu_khz * 1000 )
        {
            printk(XENLOG_WARNING
                   "WARNING: UPDATING MICROCODE HAS CONSUMED MORE THAN 1 SECOND!\n");
            tick = 0;
        }
    }

 out:
    /* Mark loading is done to unblock other threads */
    set_state(LOADING_EXIT);

    set_nmi_callback(saved_nmi_callback);
    smp_wmb();
    nmi_patch.patch = ZERO_BLOCK_PTR;
    nmi_patch.flags = 0;

    watchdog_enable();

    return ret;
}

static int cf_check do_microcode_update(void *_patch_with_flags)
{
    unsigned int cpu = smp_processor_id();
    int ret;
    struct patch_with_flags *patch_with_flags = _patch_with_flags;

    /*
     * The control thread set state to coordinate ucode loading. Primary
     * threads load the given ucode patch. Secondary threads just wait for
     * the completion of the ucode loading process.
     */
    if ( cpu == cpumask_first(&cpu_online_map) )
        ret = control_thread_fn(patch_with_flags->patch,
                                patch_with_flags->flags);
    else if ( is_cpu_primary(cpu) )
        ret = primary_thread_fn(patch_with_flags->patch,
                                patch_with_flags->flags);
    else
        ret = secondary_thread_fn();

    return ret;
}

struct ucode_buf {
    unsigned int flags;
    unsigned int len;
    char buffer[];
};

static long cf_check microcode_update_helper(void *data)
{
    struct microcode_patch *patch = NULL;
    int ret, result;
    struct ucode_buf *buffer = data;
    unsigned int cpu, updated;
    struct patch_with_flags patch_with_flags;
    bool ucode_force = buffer->flags & XENPF_UCODE_FORCE;

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
        ret = -EPERM;
        goto put;
    }

    patch = parse_blob(buffer->buffer, buffer->len);
    patch_with_flags.flags = buffer->flags;

    xfree(buffer);

    if ( IS_ERR(patch) )
    {
        ret = PTR_ERR(patch);
        patch = NULL;
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
    if ( microcode_cache )
    {
        result = alternative_call(ucode_ops.compare, microcode_cache, patch);

        if ( result != NEW_UCODE &&
             !(ucode_force && (result == OLD_UCODE || result == SAME_UCODE)) )
        {
            spin_unlock(&microcode_mutex);
            printk(XENLOG_WARNING
                   "microcode: couldn't find any newer%s revision in the provided blob!\n",
                   ucode_force ? " (or a valid)" : "");
            ret = -EEXIST;

            goto put;
        }
    }
    else
        result = NEW_UCODE;
    spin_unlock(&microcode_mutex);

    cpumask_clear(&cpu_callin_map);
    atomic_set(&cpu_out, 0);
    atomic_set(&cpu_updated, 0);
    loading_state = LOADING_PREPARE;

    /* Calculate the number of online CPU core */
    nr_cores = 0;
    for_each_online_cpu(cpu)
        if ( is_cpu_primary(cpu) )
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
    patch_with_flags.patch = patch;
    ret = stop_machine_run(do_microcode_update, &patch_with_flags, NR_CPUS);

    updated = atomic_read(&cpu_updated);
    if ( updated > 0 )
    {
        if ( result == NEW_UCODE )
        {
            spin_lock(&microcode_mutex);
            SWAP(patch, microcode_cache);
            spin_unlock(&microcode_mutex);
        }

        /*
         * Refresh the raw CPU policy, in case the features have changed.
         * Disable CPUID masking if in use, to avoid having current's
         * cpu_policy affect the rescan.
         */
        if ( ctxt_switch_masking )
            alternative_vcall(ctxt_switch_masking, NULL);

        calculate_raw_cpu_policy();

        if ( ctxt_switch_masking )
            alternative_vcall(ctxt_switch_masking, current);
    }

    if ( updated && updated != nr_cores )
        printk(XENLOG_ERR "ERROR: Updating microcode succeeded on %u cores and failed\n"
               XENLOG_ERR "on other %u cores. A system with differing microcode\n"
               XENLOG_ERR "revisions is considered unstable. Please reboot and do not\n"
               XENLOG_ERR "load the microcode that triggers this warning!\n",
               updated, nr_cores - updated);

 put:
    put_cpu_maps();

    /* The parsed blob or old cached value, whichever we're not keeping. */
    xfree(patch);

    return ret;
}

int microcode_update(XEN_GUEST_HANDLE(const_void) buf,
                     unsigned long len, unsigned int flags)
{
    int ret;
    struct ucode_buf *buffer;

    if ( flags & ~XENPF_UCODE_FORCE )
        return -EINVAL;

    if ( !ucode_ops.apply_microcode )
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
    buffer->flags = flags;

    /*
     * Always queue microcode_update_helper() on CPU0.  Most of the logic
     * won't care, but the update of the Raw CPU policy wants to (re)run on
     * the BSP.
     */
    return continue_hypercall_on_cpu(0, microcode_update_helper, buffer);
}

/* Load a cached update to current cpu */
int microcode_update_one(void)
{
    int rc;

    /*
     * This path is used for APs and S3 resume.  Read the microcode revision
     * if possible, even if we can't load microcode.
     */
    if ( ucode_ops.collect_cpu_info )
        alternative_vcall(ucode_ops.collect_cpu_info);

    if ( !ucode_ops.apply_microcode )
        return -EOPNOTSUPP;

    spin_lock(&microcode_mutex);
    if ( microcode_cache )
        rc = alternative_call(ucode_ops.apply_microcode, microcode_cache, 0);
    else
        rc = -ENOENT;
    spin_unlock(&microcode_mutex);

    return rc;
}

/*
 * Set by early_microcode_load() to indicate where it found microcode, so
 * microcode_init_cache() can find it again and initalise the cache.  opt_scan
 * tells us whether we're looking for a raw container or CPIO archive.
 */
static int __initdata early_mod_idx = -1;

static int __init cf_check microcode_init_cache(void)
{
    struct boot_info *bi = &xen_boot_info;
    struct microcode_patch *patch;
    void *data;
    size_t size;
    int rc = 0;

    if ( early_mod_idx < 0 )
        /* early_microcode_load() didn't leave us any work to do. */
        return 0;

    size = bi->mods[early_mod_idx].size;
    data = __va(bi->mods[early_mod_idx].start);

    /*
     * If opt_scan is set, we're looking for a CPIO archive rather than a raw
     * microcode container.  Look within it.
     */
    if ( opt_scan )
    {
        struct cpio_data cd = find_cpio_data(ucode_ops.cpio_path, data, size);

        if ( !cd.data )
        {
            printk(XENLOG_WARNING "Microcode: %s not found in CPIO archive\n",
                   strrchr(ucode_ops.cpio_path, '/') + 1);
            return -ENOENT;
        }

        data = cd.data;
        size = cd.size;
    }

    patch = parse_blob(data, size);
    if ( IS_ERR(patch) )
    {
        rc = PTR_ERR(patch);
        printk(XENLOG_WARNING "Microcode: Parse error %d\n", rc);
        return rc;
    }

    if ( !patch )
    {
        printk(XENLOG_WARNING "Microcode: No suitable patch found\n");
        return -ENOENT;
    }

    spin_lock(&microcode_mutex);
    ASSERT(microcode_cache == NULL);
    microcode_cache = patch;
    spin_unlock(&microcode_mutex);

    return rc;
}
presmp_initcall(microcode_init_cache);

/*
 * There are several tasks:
 * - Locate the ucode blob in the boot modules.
 * - Parse and attempt in-place load.
 * - Inform microcode_init_cache() of how to find the blob again.
 */
static int __init early_microcode_load(struct boot_info *bi)
{
    void *data = NULL;
    size_t size;
    struct microcode_patch *patch;
    int idx = opt_mod_idx;
    int rc;

    /*
     * Cmdline parsing ensures this invariant holds, so that we don't end up
     * trying to mix multiple ways of finding the microcode.
     */
    ASSERT(idx == 0 || !opt_scan);

    if ( opt_scan ) /* Scan for a CPIO archive */
    {
        for ( idx = 0; idx < bi->nr_modules; ++idx )
        {
            const struct boot_module *bm = &bi->mods[idx];
            struct cpio_data cd;

            /* Search anything unclaimed or likely to be a CPIO archive. */
            if ( bm->type != BOOTMOD_UNKNOWN &&
                 bm->type != BOOTMOD_RAMDISK )
                continue;

            size = bm->size;
            data = bootstrap_map_bm(bm);
            if ( !data )
            {
                printk(XENLOG_WARNING "Microcode: Could not map module %d, size %zu\n",
                       idx, size);
                continue;
            }

            cd = find_cpio_data(ucode_ops.cpio_path, data, size);
            if ( !cd.data )
            {
                /* CPIO archive, but no cpio_path.  Try the next module */
                bootstrap_unmap();
                continue;
            }

            /*
             * Do not alter this boot module's type.  We're most likely
             * peeking at dom0's initrd.
             */
            data = cd.data;
            size = cd.size;
            goto found;
        }

        printk(XENLOG_WARNING "Microcode: %s not found during CPIO scan\n",
               strrchr(ucode_ops.cpio_path, '/') + 1);
        return -ENODEV;
    }

    if ( idx ) /* Specific module nominated */
    {
        /*
         * Negative indicies can be used to reference from the end of the
         * modules.  e.g. ucode=-1 refers to the last module.
         */
        if ( idx < 0 )
            idx += bi->nr_modules;

        if ( idx <= 0 || idx >= bi->nr_modules )
        {
            printk(XENLOG_WARNING "Microcode: Chosen module %d out of range [1, %u)\n",
                   idx, bi->nr_modules);
            return -ENODEV;
        }

        if ( bi->mods[idx].type != BOOTMOD_UNKNOWN )
        {
            printk(XENLOG_WARNING "Microcode: Chosen module %d already used\n", idx);
            return -ENODEV;
        }
        bi->mods[idx].type = BOOTMOD_MICROCODE;

        size = bi->mods[idx].size;
        data = bootstrap_map_bm(&bi->mods[idx]);
        if ( !data )
        {
            printk(XENLOG_WARNING "Microcode: Could not map module %d, size %zu\n",
                   idx, size);
            return -ENODEV;
        }
        goto found;
    }

    /* No method of finding microcode specified.  Nothing to do. */
    return 0;

 found:
    patch = ucode_ops.cpu_request_microcode(data, size, false);
    if ( IS_ERR(patch) )
    {
        rc = PTR_ERR(patch);
        printk(XENLOG_WARNING "Microcode: Parse error %d\n", rc);
        goto unmap;
    }

    if ( !patch )
    {
        printk(XENLOG_DEBUG "Microcode: No suitable patch found\n");
        rc = -ENOENT;
        goto unmap;
    }

    /*
     * We've found a microcode patch suitable for this CPU.
     *
     * Tell microcode_init_cache() which module we found it in.  We cache it
     * irrespective of whether the BSP successfully loads it; Some platforms
     * are known to update the BSP but leave the APs on older ucode.
     */
    early_mod_idx = idx;

    rc = ucode_ops.apply_microcode(patch, 0);

    if ( rc == 0 )
        /* Rescan CPUID/MSR features, which may have changed after a load. */
        early_cpu_init(false);

 unmap:
    bootstrap_unmap();

    return rc;
}

int __init early_microcode_init(struct boot_info *bi)
{
    const struct cpuinfo_x86 *c = &boot_cpu_data;

    switch ( c->x86_vendor )
    {
    case X86_VENDOR_AMD:
        ucode_probe_amd(&ucode_ops);
        break;

    case X86_VENDOR_INTEL:
        ucode_probe_intel(&ucode_ops);
        break;
    }

    if ( !ucode_ops.collect_cpu_info )
    {
        printk(XENLOG_INFO "Microcode loading not available\n");
        return -ENODEV;
    }

    ucode_ops.collect_cpu_info();

    printk(XENLOG_INFO "BSP microcode revision: 0x%08x\n", this_cpu(cpu_sig).rev);

    /*
     * Some hypervisors deliberately report a microcode revision of -1 to
     * mean that they will not accept microcode updates.
     *
     * It's also possible the hardware might have built-in support to disable
     * updates and someone (e.g: a baremetal cloud provider) disabled them.
     *
     * Take the hint in either case and ignore the microcode interface.
     */
    if ( !ucode_ops.apply_microcode || this_cpu(cpu_sig).rev == ~0 )
    {
        printk(XENLOG_INFO "Microcode loading disabled due to: %s\n",
               ucode_ops.apply_microcode ? "rev = ~0" : "HW toggle");
        ucode_ops.apply_microcode = NULL;
        return -ENODEV;
    }

    return early_microcode_load(bi);
}
