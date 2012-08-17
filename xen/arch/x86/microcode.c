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

#include <xen/config.h>
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

#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/setup.h>
#include <asm/microcode.h>

static module_t __initdata ucode_mod;
static void *(*__initdata ucode_mod_map)(const module_t *);
static signed int __initdata ucode_mod_idx;
static bool_t __initdata ucode_mod_forced;
static cpumask_t __initdata init_mask;

void __init microcode_set_module(unsigned int idx)
{
    ucode_mod_idx = idx;
    ucode_mod_forced = 1;
}

static void __init parse_ucode(char *s)
{
    if ( !ucode_mod_forced )
        ucode_mod_idx = simple_strtol(s, NULL, 0);
}
custom_param("ucode", parse_ucode);

void __init microcode_grab_module(
    unsigned long *module_map,
    const multiboot_info_t *mbi,
    void *(*map)(const module_t *))
{
    module_t *mod = (module_t *)__va(mbi->mods_addr);

    if ( ucode_mod_idx < 0 )
        ucode_mod_idx += mbi->mods_count;
    if ( ucode_mod_idx <= 0 || ucode_mod_idx >= mbi->mods_count ||
         !__test_and_clear_bit(ucode_mod_idx, module_map) )
        return;
    ucode_mod = mod[ucode_mod_idx];
    ucode_mod_map = map;
}

const struct microcode_ops *microcode_ops;

static DEFINE_SPINLOCK(microcode_mutex);

DEFINE_PER_CPU(struct ucode_cpu_info, ucode_cpu_info);

struct microcode_info {
    unsigned int cpu;
    uint32_t buffer_size;
    int error;
    char buffer[1];
};

static void __microcode_fini_cpu(int cpu)
{
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);

    xfree(uci->mc.mc_valid);
    memset(uci, 0, sizeof(*uci));
}

static void microcode_fini_cpu(int cpu)
{
    spin_lock(&microcode_mutex);
    __microcode_fini_cpu(cpu);
    spin_unlock(&microcode_mutex);
}

int microcode_resume_cpu(int cpu)
{
    int err;
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);
    struct cpu_signature nsig;
    unsigned int cpu2;

    if ( !microcode_ops )
        return 0;

    spin_lock(&microcode_mutex);

    err = microcode_ops->collect_cpu_info(cpu, &uci->cpu_sig);
    if ( err )
    {
        __microcode_fini_cpu(cpu);
        spin_unlock(&microcode_mutex);
        return err;
    }

    if ( uci->mc.mc_valid )
    {
        err = microcode_ops->microcode_resume_match(cpu, uci->mc.mc_valid);
        if ( err >= 0 )
        {
            if ( err )
                err = microcode_ops->apply_microcode(cpu);
            spin_unlock(&microcode_mutex);
            return err;
        }
    }

    nsig = uci->cpu_sig;
    __microcode_fini_cpu(cpu);
    uci->cpu_sig = nsig;

    err = -EIO;
    for_each_online_cpu ( cpu2 )
    {
        uci = &per_cpu(ucode_cpu_info, cpu2);
        if ( uci->mc.mc_valid &&
             microcode_ops->microcode_resume_match(cpu, uci->mc.mc_valid) > 0 )
        {
            err = microcode_ops->apply_microcode(cpu);
            break;
        }
    }

    __microcode_fini_cpu(cpu);
    spin_unlock(&microcode_mutex);

    return err;
}

static int microcode_update_cpu(const void *buf, size_t size)
{
    int err;
    unsigned int cpu = smp_processor_id();
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);

    spin_lock(&microcode_mutex);

    err = microcode_ops->collect_cpu_info(cpu, &uci->cpu_sig);
    if ( likely(!err) )
        err = microcode_ops->cpu_request_microcode(cpu, buf, size);
    else
        __microcode_fini_cpu(cpu);

    spin_unlock(&microcode_mutex);

    return err;
}

static long do_microcode_update(void *_info)
{
    struct microcode_info *info = _info;
    int error;

    BUG_ON(info->cpu != smp_processor_id());

    error = microcode_update_cpu(info->buffer, info->buffer_size);
    if ( error )
        info->error = error;

    info->cpu = cpumask_next(info->cpu, &cpu_online_map);
    if ( info->cpu < nr_cpu_ids )
        return continue_hypercall_on_cpu(info->cpu, do_microcode_update, info);

    error = info->error;
    xfree(info);
    return error;
}

int microcode_update(XEN_GUEST_HANDLE(const_void) buf, unsigned long len)
{
    int ret;
    struct microcode_info *info;

    if ( len != (uint32_t)len )
        return -E2BIG;

    if ( microcode_ops == NULL )
        return -EINVAL;

    info = xmalloc_bytes(sizeof(*info) + len);
    if ( info == NULL )
        return -ENOMEM;

    ret = copy_from_guest(info->buffer, buf, len);
    if ( ret != 0 )
    {
        xfree(info);
        return ret;
    }

    info->buffer_size = len;
    info->error = 0;
    info->cpu = cpumask_first(&cpu_online_map);

    if ( microcode_ops->start_update )
    {
        ret = microcode_ops->start_update();
        if ( ret != 0 )
        {
            xfree(info);
            return ret;
        }
    }

    return continue_hypercall_on_cpu(info->cpu, do_microcode_update, info);
}

static void __init _do_microcode_update(unsigned long data)
{
    microcode_update_cpu((void *)data, ucode_mod.mod_end);
    cpumask_set_cpu(smp_processor_id(), &init_mask);
}

static int __init microcode_init(void)
{
    void *data;
    static struct tasklet __initdata tasklet;
    unsigned int cpu;

    if ( !microcode_ops || !ucode_mod.mod_end )
        return 0;

    data = ucode_mod_map(&ucode_mod);
    if ( !data )
        return -ENOMEM;

    if ( microcode_ops->start_update && microcode_ops->start_update() != 0 )
    {
        ucode_mod_map(NULL);
        return 0;
    }

    softirq_tasklet_init(&tasklet, _do_microcode_update, (unsigned long)data);

    for_each_online_cpu ( cpu )
    {
        tasklet_schedule_on_cpu(&tasklet, cpu);
        do {
            process_pending_softirqs();
        } while ( !cpumask_test_cpu(cpu, &init_mask) );
    }

    ucode_mod_map(NULL);

    return 0;
}
__initcall(microcode_init);

static int microcode_percpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;

    switch ( action )
    {
    case CPU_DEAD:
        microcode_fini_cpu(cpu);
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block microcode_percpu_nfb = {
    .notifier_call = microcode_percpu_callback,
};

static int __init microcode_presmp_init(void)
{
    if ( microcode_ops )
    {
        if ( ucode_mod.mod_end )
        {
            void *data = ucode_mod_map(&ucode_mod);

            if ( data )
                microcode_update_cpu(data, ucode_mod.mod_end);

            ucode_mod_map(NULL);
        }

        register_cpu_notifier(&microcode_percpu_nfb);
    }

    return 0;
}
presmp_initcall(microcode_presmp_init);
