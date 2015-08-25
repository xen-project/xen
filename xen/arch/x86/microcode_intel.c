/*
 * Intel CPU Microcode Update Driver for Linux
 *
 * Copyright (C) 2000-2006 Tigran Aivazian <tigran@aivazian.fsnet.co.uk>
 *               2006 Shaohua Li <shaohua.li@intel.com> *
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

#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/microcode.h>

#define pr_debug(x...) ((void)0)

struct microcode_header_intel {
    unsigned int hdrver;
    unsigned int rev;
    unsigned int date;
    unsigned int sig;
    unsigned int cksum;
    unsigned int ldrver;
    unsigned int pf;
    unsigned int datasize;
    unsigned int totalsize;
    unsigned int reserved[3];
};

struct microcode_intel {
    struct microcode_header_intel hdr;
    unsigned int bits[0];
};

/* microcode format is extended from prescott processors */
struct extended_signature {
    unsigned int sig;
    unsigned int pf;
    unsigned int cksum;
};

struct extended_sigtable {
    unsigned int count;
    unsigned int cksum;
    unsigned int reserved[3];
    struct extended_signature sigs[0];
};

#define DEFAULT_UCODE_DATASIZE  (2000)
#define MC_HEADER_SIZE          (sizeof(struct microcode_header_intel))
#define DEFAULT_UCODE_TOTALSIZE (DEFAULT_UCODE_DATASIZE + MC_HEADER_SIZE)
#define EXT_HEADER_SIZE         (sizeof(struct extended_sigtable))
#define EXT_SIGNATURE_SIZE      (sizeof(struct extended_signature))
#define DWSIZE                  (sizeof(u32))
#define get_totalsize(mc) \
        (((struct microcode_intel *)mc)->hdr.totalsize ? \
         ((struct microcode_intel *)mc)->hdr.totalsize : \
         DEFAULT_UCODE_TOTALSIZE)

#define get_datasize(mc) \
        (((struct microcode_intel *)mc)->hdr.datasize ? \
         ((struct microcode_intel *)mc)->hdr.datasize : DEFAULT_UCODE_DATASIZE)

#define sigmatch(s1, s2, p1, p2) \
        (((s1) == (s2)) && (((p1) & (p2)) || (((p1) == 0) && ((p2) == 0))))

#define exttable_size(et) ((et)->count * EXT_SIGNATURE_SIZE + EXT_HEADER_SIZE)

/* serialize access to the physical write to MSR 0x79 */
static DEFINE_SPINLOCK(microcode_update_lock);

static int collect_cpu_info(unsigned int cpu_num, struct cpu_signature *csig)
{
    struct cpuinfo_x86 *c = &cpu_data[cpu_num];
    uint64_t msr_content;

    BUG_ON(cpu_num != smp_processor_id());

    memset(csig, 0, sizeof(*csig));

    if ( (c->x86_vendor != X86_VENDOR_INTEL) || (c->x86 < 6) ||
         cpu_has(c, X86_FEATURE_IA64) )
    {
        printk(KERN_ERR "microcode: CPU%d not a capable Intel "
               "processor\n", cpu_num);
        return -1;
    }

    csig->sig = cpuid_eax(0x00000001);

    if ( (c->x86_model >= 5) || (c->x86 > 6) )
    {
        /* get processor flags from MSR 0x17 */
        rdmsrl(MSR_IA32_PLATFORM_ID, msr_content);
        csig->pf = 1 << ((msr_content >> 50) & 7);
    }

    wrmsrl(MSR_IA32_UCODE_REV, 0x0ULL);
    /* see notes above for revision 1.07.  Apparent chip bug */
    sync_core();
    /* get the current revision from MSR 0x8B */
    rdmsrl(MSR_IA32_UCODE_REV, msr_content);
    csig->rev = (uint32_t)(msr_content >> 32);
    pr_debug("microcode: collect_cpu_info : sig=%#x, pf=%#x, rev=%#x\n",
             csig->sig, csig->pf, csig->rev);

    return 0;
}

static inline int microcode_update_match(
    unsigned int cpu_num, const struct microcode_header_intel *mc_header,
    int sig, int pf)
{
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu_num);

    return (sigmatch(sig, uci->cpu_sig.sig, pf, uci->cpu_sig.pf) &&
            (mc_header->rev > uci->cpu_sig.rev));
}

static int microcode_sanity_check(void *mc)
{
    struct microcode_header_intel *mc_header = mc;
    struct extended_sigtable *ext_header = NULL;
    struct extended_signature *ext_sig;
    unsigned long total_size, data_size, ext_table_size;
    int sum, orig_sum, ext_sigcount = 0, i;

    total_size = get_totalsize(mc_header);
    data_size = get_datasize(mc_header);
    if ( (data_size + MC_HEADER_SIZE) > total_size )
    {
        printk(KERN_ERR "microcode: error! "
               "Bad data size in microcode data file\n");
        return -EINVAL;
    }

    if ( (mc_header->ldrver != 1) || (mc_header->hdrver != 1) )
    {
        printk(KERN_ERR "microcode: error! "
               "Unknown microcode update format\n");
        return -EINVAL;
    }
    ext_table_size = total_size - (MC_HEADER_SIZE + data_size);
    if ( ext_table_size )
    {
        if ( (ext_table_size < EXT_HEADER_SIZE) ||
             ((ext_table_size - EXT_HEADER_SIZE) % EXT_SIGNATURE_SIZE) )
        {
            printk(KERN_ERR "microcode: error! "
                   "Small exttable size in microcode data file\n");
            return -EINVAL;
        }
        ext_header = mc + MC_HEADER_SIZE + data_size;
        if ( ext_table_size != exttable_size(ext_header) )
        {
            printk(KERN_ERR "microcode: error! "
                   "Bad exttable size in microcode data file\n");
            return -EFAULT;
        }
        ext_sigcount = ext_header->count;
    }

    /* check extended table checksum */
    if ( ext_table_size )
    {
        int ext_table_sum = 0;
        int *ext_tablep = (int *)ext_header;

        i = ext_table_size / DWSIZE;
        while ( i-- )
            ext_table_sum += ext_tablep[i];
        if ( ext_table_sum )
        {
            printk(KERN_WARNING "microcode: aborting, "
                   "bad extended signature table checksum\n");
            return -EINVAL;
        }
    }

    /* calculate the checksum */
    orig_sum = 0;
    i = (MC_HEADER_SIZE + data_size) / DWSIZE;
    while ( i-- )
        orig_sum += ((int *)mc)[i];
    if ( orig_sum )
    {
        printk(KERN_ERR "microcode: aborting, bad checksum\n");
        return -EINVAL;
    }
    if ( !ext_table_size )
        return 0;
    /* check extended signature checksum */
    for ( i = 0; i < ext_sigcount; i++ )
    {
        ext_sig = (void *)ext_header + EXT_HEADER_SIZE +
            EXT_SIGNATURE_SIZE * i;
        sum = orig_sum
            - (mc_header->sig + mc_header->pf + mc_header->cksum)
            + (ext_sig->sig + ext_sig->pf + ext_sig->cksum);
        if ( sum )
        {
            printk(KERN_ERR "microcode: aborting, bad checksum\n");
            return -EINVAL;
        }
    }
    return 0;
}

/*
 * return 0 - no update found
 * return 1 - found update
 * return < 0 - error
 */
static int get_matching_microcode(const void *mc, unsigned int cpu)
{
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);
    const struct microcode_header_intel *mc_header = mc;
    const struct extended_sigtable *ext_header;
    unsigned long total_size = get_totalsize(mc_header);
    int ext_sigcount, i;
    struct extended_signature *ext_sig;
    void *new_mc;

    if ( microcode_update_match(cpu, mc_header,
                                mc_header->sig, mc_header->pf) )
        goto find;

    if ( total_size <= (get_datasize(mc_header) + MC_HEADER_SIZE) )
        return 0;

    ext_header = mc + get_datasize(mc_header) + MC_HEADER_SIZE;
    ext_sigcount = ext_header->count;
    ext_sig = (void *)ext_header + EXT_HEADER_SIZE;
    for ( i = 0; i < ext_sigcount; i++ )
    {
        if ( microcode_update_match(cpu, mc_header,
                                    ext_sig->sig, ext_sig->pf) )
            goto find;
        ext_sig++;
    }
    return 0;
 find:
    pr_debug("microcode: CPU%d found a matching microcode update with"
             " version %#x (current=%#x)\n",
             cpu, mc_header->rev, uci->cpu_sig.rev);
    new_mc = xmalloc_bytes(total_size);
    if ( new_mc == NULL )
    {
        printk(KERN_ERR "microcode: error! Can not allocate memory\n");
        return -ENOMEM;
    }

    memcpy(new_mc, mc, total_size);
    xfree(uci->mc.mc_intel);
    uci->mc.mc_intel = new_mc;
    return 1;
}

static int apply_microcode(unsigned int cpu)
{
    unsigned long flags;
    uint64_t msr_content;
    unsigned int val[2];
    unsigned int cpu_num = raw_smp_processor_id();
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu_num);

    /* We should bind the task to the CPU */
    BUG_ON(cpu_num != cpu);

    if ( uci->mc.mc_intel == NULL )
        return -EINVAL;

    /* serialize access to the physical write to MSR 0x79 */
    spin_lock_irqsave(&microcode_update_lock, flags);

    /* write microcode via MSR 0x79 */
    wrmsrl(MSR_IA32_UCODE_WRITE, (unsigned long)uci->mc.mc_intel->bits);
    wrmsrl(MSR_IA32_UCODE_REV, 0x0ULL);

    /* see notes above for revision 1.07.  Apparent chip bug */
    sync_core();

    /* get the current revision from MSR 0x8B */
    rdmsrl(MSR_IA32_UCODE_REV, msr_content);
    val[1] = (uint32_t)(msr_content >> 32);

    spin_unlock_irqrestore(&microcode_update_lock, flags);
    if ( val[1] != uci->mc.mc_intel->hdr.rev )
    {
        printk(KERN_ERR "microcode: CPU%d update from revision "
               "%#x to %#x failed\n", cpu_num, uci->cpu_sig.rev, val[1]);
        return -EIO;
    }
    printk(KERN_INFO "microcode: CPU%d updated from revision "
           "%#x to %#x, date = %04x-%02x-%02x \n",
           cpu_num, uci->cpu_sig.rev, val[1],
           uci->mc.mc_intel->hdr.date & 0xffff,
           uci->mc.mc_intel->hdr.date >> 24,
           (uci->mc.mc_intel->hdr.date >> 16) & 0xff);
    uci->cpu_sig.rev = val[1];

    return 0;
}

static long get_next_ucode_from_buffer(void **mc, const u8 *buf,
                                       unsigned long size, long offset)
{
    struct microcode_header_intel *mc_header;
    unsigned long total_size;

    /* No more data */
    if ( offset >= size )
        return 0;
    mc_header = (struct microcode_header_intel *)(buf + offset);
    total_size = get_totalsize(mc_header);

    if ( (offset + total_size) > size )
    {
        printk(KERN_ERR "microcode: error! Bad data in microcode data file\n");
        return -EINVAL;
    }

    *mc = xmalloc_bytes(total_size);
    if ( *mc == NULL )
    {
        printk(KERN_ERR "microcode: error! Can not allocate memory\n");
        return -ENOMEM;
    }
    memcpy(*mc, (const void *)(buf + offset), total_size);
    return offset + total_size;
}

static int cpu_request_microcode(unsigned int cpu, const void *buf,
                                 size_t size)
{
    long offset = 0;
    int error = 0;
    void *mc;
    unsigned int matching_count = 0;

    /* We should bind the task to the CPU */
    BUG_ON(cpu != raw_smp_processor_id());

    while ( (offset = get_next_ucode_from_buffer(&mc, buf, size, offset)) > 0 )
    {
        error = microcode_sanity_check(mc);
        if ( error )
            break;
        error = get_matching_microcode(mc, cpu);
        if ( error < 0 )
            break;
        /*
         * It's possible the data file has multiple matching ucode,
         * lets keep searching till the latest version
         */
        if ( error == 1 )
        {
            matching_count++;
            error = 0;
        }
        xfree(mc);
    }
    if ( offset > 0 )
        xfree(mc);
    if ( offset < 0 )
        error = offset;

    if ( !error && matching_count )
        apply_microcode(cpu);

    return error;
}

static int microcode_resume_match(unsigned int cpu, const void *mc)
{
    return get_matching_microcode(mc, cpu);
}

static const struct microcode_ops microcode_intel_ops = {
    .microcode_resume_match           = microcode_resume_match,
    .cpu_request_microcode            = cpu_request_microcode,
    .collect_cpu_info                 = collect_cpu_info,
    .apply_microcode                  = apply_microcode,
};

static __init int microcode_init_intel(void)
{
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        microcode_ops = &microcode_intel_ops;
    return 0;
}
presmp_initcall(microcode_init_intel);
