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

#include <xen/err.h>
#include <xen/init.h>

#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/system.h>

#include "private.h"

#define pr_debug(x...) ((void)0)

struct microcode_header_intel {
    unsigned int hdrver;
    unsigned int rev;
    union {
        struct {
            uint16_t year;
            uint8_t day;
            uint8_t month;
        };
        unsigned int date;
    };
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

static int collect_cpu_info(struct cpu_signature *csig)
{
    unsigned int cpu_num = smp_processor_id();
    struct cpuinfo_x86 *c = &cpu_data[cpu_num];
    uint64_t msr_content;

    memset(csig, 0, sizeof(*csig));

    if ( (c->x86_vendor != X86_VENDOR_INTEL) || (c->x86 < 6) )
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
    /* As documented in the SDM: Do a CPUID 1 here */
    cpuid_eax(1);

    /* get the current revision from MSR 0x8B */
    rdmsrl(MSR_IA32_UCODE_REV, msr_content);
    csig->rev = (uint32_t)(msr_content >> 32);
    pr_debug("microcode: collect_cpu_info : sig=%#x, pf=%#x, rev=%#x\n",
             csig->sig, csig->pf, csig->rev);

    return 0;
}

static int microcode_sanity_check(const void *mc)
{
    const struct microcode_header_intel *mc_header = mc;
    const struct extended_sigtable *ext_header = NULL;
    const struct extended_signature *ext_sig;
    unsigned long total_size, data_size, ext_table_size;
    unsigned int ext_sigcount = 0, i;
    uint32_t sum, orig_sum;

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
        uint32_t ext_table_sum = 0;
        uint32_t *ext_tablep = (uint32_t *)ext_header;

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
        orig_sum += ((uint32_t *)mc)[i];
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

/* Check an update against the CPU signature and current update revision */
static enum microcode_match_result microcode_update_match(
    const struct microcode_header_intel *mc_header)
{
    const struct extended_sigtable *ext_header;
    const struct extended_signature *ext_sig;
    unsigned int i;
    struct cpu_signature *cpu_sig = &this_cpu(cpu_sig);
    unsigned int sig = cpu_sig->sig;
    unsigned int pf = cpu_sig->pf;
    unsigned int rev = cpu_sig->rev;
    unsigned long data_size = get_datasize(mc_header);
    const void *end = (const void *)mc_header + get_totalsize(mc_header);

    ASSERT(!microcode_sanity_check(mc_header));
    if ( sigmatch(sig, mc_header->sig, pf, mc_header->pf) )
        return (mc_header->rev > rev) ? NEW_UCODE : OLD_UCODE;

    ext_header = (const void *)(mc_header + 1) + data_size;
    ext_sig = (const void *)(ext_header + 1);

    /*
     * Make sure there is enough space to hold an extended header and enough
     * array elements.
     */
    if ( end <= (const void *)ext_sig )
        return MIS_UCODE;

    for ( i = 0; i < ext_header->count; i++ )
        if ( sigmatch(sig, ext_sig[i].sig, pf, ext_sig[i].pf) )
            return (mc_header->rev > rev) ? NEW_UCODE : OLD_UCODE;

    return MIS_UCODE;
}

static bool match_cpu(const struct microcode_patch *patch)
{
    if ( !patch )
        return false;

    return microcode_update_match(&patch->mc_intel->hdr) == NEW_UCODE;
}

static void free_patch(void *mc)
{
    xfree(mc);
}

static enum microcode_match_result compare_patch(
    const struct microcode_patch *new, const struct microcode_patch *old)
{
    /*
     * Both patches to compare are supposed to be applicable to local CPU.
     * Just compare the revision number.
     */
    ASSERT(microcode_update_match(&old->mc_intel->hdr) != MIS_UCODE);
    ASSERT(microcode_update_match(&new->mc_intel->hdr) != MIS_UCODE);

    return (new->mc_intel->hdr.rev > old->mc_intel->hdr.rev) ? NEW_UCODE
                                                             : OLD_UCODE;
}

static int apply_microcode(const struct microcode_patch *patch)
{
    uint64_t msr_content;
    unsigned int val[2];
    unsigned int cpu_num = raw_smp_processor_id();
    struct cpu_signature *sig = &this_cpu(cpu_sig);
    const struct microcode_intel *mc_intel;

    if ( !patch )
        return -ENOENT;

    if ( !match_cpu(patch) )
        return -EINVAL;

    mc_intel = patch->mc_intel;

    BUG_ON(local_irq_is_enabled());

    /* write microcode via MSR 0x79 */
    wrmsrl(MSR_IA32_UCODE_WRITE, (unsigned long)mc_intel->bits);
    wrmsrl(MSR_IA32_UCODE_REV, 0x0ULL);

    /* As documented in the SDM: Do a CPUID 1 here */
    cpuid_eax(1);

    /* get the current revision from MSR 0x8B */
    rdmsrl(MSR_IA32_UCODE_REV, msr_content);
    val[1] = (uint32_t)(msr_content >> 32);

    if ( val[1] != mc_intel->hdr.rev )
    {
        printk(KERN_ERR "microcode: CPU%d update from revision "
               "%#x to %#x failed. Resulting revision is %#x.\n", cpu_num,
               sig->rev, mc_intel->hdr.rev, val[1]);
        return -EIO;
    }
    printk(KERN_INFO "microcode: CPU%d updated from revision "
           "%#x to %#x, date = %04x-%02x-%02x\n",
           cpu_num, sig->rev, val[1], mc_intel->hdr.year,
           mc_intel->hdr.month, mc_intel->hdr.day);
    sig->rev = val[1];

    return 0;
}

static long get_next_ucode_from_buffer(struct microcode_intel **mc,
                                       const uint8_t *buf, unsigned long size,
                                       unsigned long offset)
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

static struct microcode_patch *cpu_request_microcode(const void *buf,
                                                     size_t size)
{
    long offset = 0;
    int error = 0;
    struct microcode_intel *mc, *saved = NULL;
    struct microcode_patch *patch = NULL;

    while ( (offset = get_next_ucode_from_buffer(&mc, buf, size, offset)) > 0 )
    {
        error = microcode_sanity_check(mc);
        if ( error )
        {
            xfree(mc);
            break;
        }

        /*
         * If the new update covers current CPU, compare updates and store the
         * one with higher revision.
         */
        if ( (microcode_update_match(&mc->hdr) != MIS_UCODE) &&
             (!saved || (mc->hdr.rev > saved->hdr.rev)) )
        {
            xfree(saved);
            saved = mc;
        }
        else
            xfree(mc);
    }
    if ( offset < 0 )
        error = offset;

    if ( saved )
    {
        patch = xmalloc(struct microcode_patch);
        if ( patch )
            patch->mc_intel = saved;
        else
        {
            xfree(saved);
            error = -ENOMEM;
        }
    }

    if ( error && !patch )
        patch = ERR_PTR(error);

    return patch;
}

static const struct microcode_ops microcode_intel_ops = {
    .cpu_request_microcode            = cpu_request_microcode,
    .collect_cpu_info                 = collect_cpu_info,
    .apply_microcode                  = apply_microcode,
    .free_patch                       = free_patch,
    .compare_patch                    = compare_patch,
    .match_cpu                        = match_cpu,
};

int __init microcode_init_intel(void)
{
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        microcode_ops = &microcode_intel_ops;
    return 0;
}
