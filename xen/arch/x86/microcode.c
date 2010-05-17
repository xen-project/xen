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
#include <xen/lib.h>
#include <xen/kernel.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/spinlock.h>
#include <xen/guest_access.h>

#include <asm/current.h>
#include <asm/msr.h>
#include <asm/uaccess.h>
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

    if ( !uci->mc.mc_valid )
        return -EIO;

    /*
     * Let's verify that the 'cached' ucode does belong
     * to this cpu (a bit of paranoia):
     */
    err = microcode_ops->collect_cpu_info(cpu, &nsig);
    if ( err )
    {
        microcode_fini_cpu(cpu);
        return err;
    }

    if ( microcode_ops->microcode_resume_match(cpu, &nsig) )
    {
        return microcode_ops->apply_microcode(cpu);
    }
    else
    {
        microcode_fini_cpu(cpu);
        return -EIO;
    }
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

    info->cpu = next_cpu(info->cpu, cpu_online_map);
    if ( info->cpu < NR_CPUS )
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
    info->cpu = first_cpu(cpu_online_map);

    return continue_hypercall_on_cpu(info->cpu, do_microcode_update, info);
}
