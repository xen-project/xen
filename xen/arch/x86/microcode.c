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
#include <xen/lib.h>
#include <xen/kernel.h>
#include <xen/init.h>
#include <xen/notifier.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include <xen/spinlock.h>
#include <xen/tasklet.h>
#include <xen/guest_access.h>
#include <xen/earlycpio.h>

#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/setup.h>
#include <asm/microcode.h>

static module_t __initdata ucode_mod;
static signed int __initdata ucode_mod_idx;
static bool_t __initdata ucode_mod_forced;

/*
 * If we scan the initramfs.cpio for the early microcode code
 * and find it, then 'ucode_blob' will contain the pointer
 * and the size of said blob. It is allocated from Xen's heap
 * memory.
 */
struct ucode_mod_blob {
    void *data;
    size_t size;
};

static struct ucode_mod_blob __initdata ucode_blob;
/*
 * By default we will NOT parse the multiboot modules to see if there is
 * cpio image with the microcode images.
 */
static bool_t __initdata ucode_scan;

/* Protected by microcode_mutex */
static struct microcode_patch *microcode_cache;

void __init microcode_set_module(unsigned int idx)
{
    ucode_mod_idx = idx;
    ucode_mod_forced = 1;
}

/*
 * The format is '[<integer>|scan]'. Both options are optional.
 * If the EFI has forced which of the multiboot payloads is to be used,
 * no parsing will be attempted.
 */
static int __init parse_ucode(const char *s)
{
    const char *q = NULL;

    if ( ucode_mod_forced ) /* Forced by EFI */
       return 0;

    if ( !strncmp(s, "scan", 4) )
        ucode_scan = 1;
    else
        ucode_mod_idx = simple_strtol(s, &q, 0);

    return (q && *q) ? -EINVAL : 0;
}
custom_param("ucode", parse_ucode);

/*
 * 8MB ought to be enough.
 */
#define MAX_EARLY_CPIO_MICROCODE (8 << 20)

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
                /*
                 * This is an arbitrary check - it would be sad if the blob
                 * consumed most of the memory and did not allow guests
                 * to launch.
                 */
                if ( cd.size > MAX_EARLY_CPIO_MICROCODE )
                {
                    printk("Multiboot %d microcode payload too big! (%ld, we can do %d)\n",
                           i, cd.size, MAX_EARLY_CPIO_MICROCODE);
                    goto err;
                }
                ucode_blob.size = cd.size;
                ucode_blob.data = xmalloc_bytes(cd.size);
                if ( !ucode_blob.data )
                    cd.data = NULL;
                else
                    memcpy(ucode_blob.data, cd.data, cd.size);
        }
        bootstrap_map(NULL);
        if ( cd.data )
            break;
    }
    return;
err:
    bootstrap_map(NULL);
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

int microcode_resume_cpu(void)
{
    int err;
    struct cpu_signature *sig = &this_cpu(cpu_sig);

    if ( !microcode_ops )
        return 0;

    spin_lock(&microcode_mutex);

    err = microcode_ops->collect_cpu_info(sig);
    if ( likely(!err) )
        err = microcode_ops->apply_microcode(microcode_cache);
    spin_unlock(&microcode_mutex);

    return err;
}

void microcode_free_patch(struct microcode_patch *microcode_patch)
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

static long do_microcode_update(void *patch)
{
    unsigned int cpu;
    int ret = microcode_update_cpu(patch);

    /* Store the patch after a successful loading */
    if ( !ret && patch )
    {
        spin_lock(&microcode_mutex);
        microcode_update_cache(patch);
        spin_unlock(&microcode_mutex);
        patch = NULL;
    }

    if ( microcode_ops->end_update_percpu )
        microcode_ops->end_update_percpu();

    /*
     * Each thread tries to load ucode. Only the first thread of a core
     * would succeed while other threads would encounter -EINVAL which
     * indicates current ucode revision is equal to or newer than the
     * given patch. It is actually expected; so ignore this error.
     */
    if ( ret == -EINVAL )
        ret = 0;

    cpu = cpumask_next(smp_processor_id(), &cpu_online_map);
    if ( cpu < nr_cpu_ids )
        return continue_hypercall_on_cpu(cpu, do_microcode_update, patch) ?:
               ret;

    /* Free the patch if no CPU has loaded it successfully. */
    if ( patch )
        microcode_free_patch(patch);

    return ret;
}

int microcode_update(XEN_GUEST_HANDLE_PARAM(const_void) buf, unsigned long len)
{
    int ret;
    void *buffer;
    struct microcode_patch *patch;

    if ( len != (uint32_t)len )
        return -E2BIG;

    if ( microcode_ops == NULL )
        return -EINVAL;

    buffer = xmalloc_bytes(len);
    if ( !buffer )
        return -ENOMEM;

    ret = copy_from_guest(buffer, buf, len);
    if ( ret )
    {
        xfree(buffer);
        return -EFAULT;
    }

    patch = parse_blob(buffer, len);
    xfree(buffer);
    if ( IS_ERR(patch) )
    {
        ret = PTR_ERR(patch);
        printk(XENLOG_WARNING "Parsing microcode blob error %d\n", ret);
        return ret;
    }

    if ( !patch )
        return -ENOENT;

    if ( microcode_ops->start_update )
    {
        ret = microcode_ops->start_update();
        if ( ret != 0 )
        {
            microcode_free_patch(patch);
            return ret;
        }
    }

    return continue_hypercall_on_cpu(cpumask_first(&cpu_online_map),
                                     do_microcode_update, patch);
}

static int __init microcode_init(void)
{
    /*
     * At this point, all CPUs should have updated their microcode
     * via the early_microcode_* paths so free the microcode blob.
     */
    if ( ucode_blob.size )
    {
        xfree(ucode_blob.data);
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

int __init early_microcode_update_cpu(bool start_update)
{
    int rc = 0;
    void *data = NULL;
    size_t len;

    if ( !microcode_ops )
        return -ENOSYS;

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

    microcode_ops->collect_cpu_info(&this_cpu(cpu_sig));

    if ( !data )
        return -ENOMEM;

    if ( start_update )
    {
        struct microcode_patch *patch;

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

        if ( microcode_ops->start_update )
            rc = microcode_ops->start_update();

        if ( rc )
            return rc;
    }

    rc = microcode_update_cpu(NULL);

    if ( microcode_ops->end_update_percpu )
        microcode_ops->end_update_percpu();

    return rc;
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
            rc = early_microcode_update_cpu(true);
    }

    return rc;
}
