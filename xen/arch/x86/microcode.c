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
#include <xen/spinlock.h>
#include <xen/guest_access.h>

#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/microcode.h>

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

    return continue_hypercall_on_cpu(info->cpu, do_microcode_update, info);
}

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
        register_cpu_notifier(&microcode_percpu_nfb);
    return 0;
}
presmp_initcall(microcode_presmp_init);
