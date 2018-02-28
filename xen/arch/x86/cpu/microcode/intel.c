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
#include <asm/system.h>

#include "private.h"

#define pr_debug(x...) ((void)0)

struct microcode_patch {
    unsigned int hdrver;
    unsigned int rev;
    uint16_t year;
    uint8_t  day;
    uint8_t  month;
    unsigned int sig;
    unsigned int cksum;
    unsigned int ldrver;

    /*
     * Microcode for the Pentium Pro and II had all further fields in the
     * header reserved, had a fixed datasize of 2000 and totalsize of 2048,
     * and didn't use platform flags despite the availability of the MSR.
     */
    unsigned int pf;
    unsigned int datasize;
    unsigned int totalsize;
    unsigned int reserved[3];

    /* Microcode payload.  Format is propriety and encrypted. */
    uint8_t data[];
};

/* microcode format is extended from prescott processors */
struct extended_sigtable {
    unsigned int count;
    unsigned int cksum;
    unsigned int reserved[3];
    struct {
        unsigned int sig;
        unsigned int pf;
        unsigned int cksum;
    } sigs[];
};

#define PPRO_UCODE_DATASIZE     2000
#define MC_HEADER_SIZE          offsetof(struct microcode_patch, data)

static uint32_t get_datasize(const struct microcode_patch *patch)
{
    return patch->datasize ?: PPRO_UCODE_DATASIZE;
}

static uint32_t get_totalsize(const struct microcode_patch *patch)
{
    return patch->totalsize ?: PPRO_UCODE_DATASIZE + MC_HEADER_SIZE;
}

/*
 * A piece of microcode has an extended signature table if there is space
 * between the end of data[] and the total size.  (This logic also works
 * appropriately for Pentium Pro/II microcode, which has 0 for both size
 * fields, and no extended signature table.)
 */
static const struct extended_sigtable *get_ext_sigtable(
    const struct microcode_patch *patch)
{
    if ( patch->totalsize > (MC_HEADER_SIZE + patch->datasize) )
        return (const void *)&patch->data[patch->datasize];

    return NULL;
}

/*
 * A piece of microcode is applicable for a CPU if:
 *  1) the signatures (CPUID.1.EAX - Family/Model/Stepping) match, and
 *  2) The Platform Flags bitmap intersect.
 *
 * A CPU will have a single Platform Flag bit, while the microcode may be
 * common to multiple platforms and have multiple bits set.
 *
 * Note: The Pentium Pro/II microcode didn't use platform flags, and should
 * treat 0 as a match.  However, Xen being 64bit means that the CPU signature
 * won't match, allowing us to simplify the logic.
 */
static bool signature_matches(const struct cpu_signature *cpu_sig,
                              unsigned int ucode_sig, unsigned int ucode_pf)
{
    if ( cpu_sig->sig != ucode_sig )
        return false;

    return cpu_sig->pf & ucode_pf;
}

static void collect_cpu_info(void)
{
    struct cpu_signature *csig = &this_cpu(cpu_sig);
    uint64_t msr_content;

    memset(csig, 0, sizeof(*csig));

    rdmsrl(MSR_IA32_PLATFORM_ID, msr_content);
    csig->pf = 1 << ((msr_content >> 50) & 7);

    wrmsrl(MSR_IA32_UCODE_REV, 0x0ULL);
    /* As documented in the SDM: Do a CPUID 1 here */
    csig->sig = cpuid_eax(1);

    /* get the current revision from MSR 0x8B */
    rdmsrl(MSR_IA32_UCODE_REV, msr_content);
    csig->rev = (uint32_t)(msr_content >> 32);
    pr_debug("microcode: collect_cpu_info : sig=%#x, pf=%#x, rev=%#x\n",
             csig->sig, csig->pf, csig->rev);
}

/*
 * Sanity check a blob which is expected to be a microcode patch.  The 48 byte
 * header is of a known format, and together with totalsize are within the
 * bounds of the container.  Everything else is unchecked.
 */
static int microcode_sanity_check(const struct microcode_patch *patch)
{
    const struct extended_sigtable *ext;
    const uint32_t *ptr;
    unsigned int total_size = get_totalsize(patch);
    unsigned int data_size = get_datasize(patch);
    unsigned int i, ext_size;
    uint32_t sum;

    /*
     * Total size must be a multiple of 1024 bytes.  Data size and the header
     * must fit within it.
     */
    if ( (total_size & 1023) ||
         data_size > (total_size - MC_HEADER_SIZE) )
    {
        printk(XENLOG_WARNING "microcode: Bad size\n");
        return -EINVAL;
    }

    /* Checksum the main header and data. */
    for ( sum = 0, ptr = (const uint32_t *)patch;
          ptr < (const uint32_t *)&patch->data[data_size]; ++ptr )
        sum += *ptr;

    if ( sum != 0 )
    {
        printk(XENLOG_WARNING "microcode: Bad checksum\n");
        return -EINVAL;
    }

    /* Look to see if there is an extended signature table. */
    ext_size = total_size - data_size - MC_HEADER_SIZE;

    /* No extended signature table?  All done. */
    if ( ext_size == 0 )
        return 0;

    /*
     * Check the structure of the extended signature table, ensuring that it
     * fits exactly in the remaining space.
     */
    ext = (const void *)&patch->data[data_size];
    if ( ext_size < sizeof(*ext) ||
         (ext_size - sizeof(*ext)) % sizeof(ext->sigs[0]) ||
         (ext_size - sizeof(*ext)) / sizeof(ext->sigs[0]) != ext->count )
    {
        printk(XENLOG_WARNING "microcode: Bad sigtable size\n");
        return -EINVAL;
    }

    /* Checksum the whole extended signature table. */
    for ( sum = 0, ptr = (const uint32_t *)ext;
          ptr < (const uint32_t *)&ext->sigs[ext->count]; ++ptr )
        sum += *ptr;

    if ( sum != 0 )
    {
        printk(XENLOG_WARNING "microcode: Bad sigtable checksum\n");
        return -EINVAL;
    }

    /*
     * Checksum each indiviudal extended signature as if it had been in the
     * main header.
     */
    sum = patch->sig + patch->pf + patch->cksum;
    for ( i = 0; i < ext->count; ++i )
        if ( sum != (ext->sigs[i].sig + ext->sigs[i].pf + ext->sigs[i].cksum) )
        {
            printk(XENLOG_WARNING "microcode: Bad sigtable checksum\n");
            return -EINVAL;
        }

    return 0;
}

/* Check an update against the CPU signature and current update revision */
static enum microcode_match_result microcode_update_match(
    const struct microcode_patch *mc)
{
    const struct extended_sigtable *ext;
    unsigned int i;
    struct cpu_signature *cpu_sig = &this_cpu(cpu_sig);

    ASSERT(!microcode_sanity_check(mc));

    /* Check the main microcode signature. */
    if ( signature_matches(cpu_sig, mc->sig, mc->pf) )
        goto found;

    /* If there is an extended signature table, check each of them. */
    if ( (ext = get_ext_sigtable(mc)) != NULL )
        for ( i = 0; i < ext->count; ++i )
            if ( signature_matches(cpu_sig, ext->sigs[i].sig, ext->sigs[i].pf) )
                goto found;

    return MIS_UCODE;

 found:
    return mc->rev > cpu_sig->rev ? NEW_UCODE : OLD_UCODE;
}

static enum microcode_match_result compare_patch(
    const struct microcode_patch *new, const struct microcode_patch *old)
{
    /*
     * Both patches to compare are supposed to be applicable to local CPU.
     * Just compare the revision number.
     */
    ASSERT(microcode_update_match(old) != MIS_UCODE);
    ASSERT(microcode_update_match(new) != MIS_UCODE);

    return new->rev > old->rev ? NEW_UCODE : OLD_UCODE;
}

static int apply_microcode(const struct microcode_patch *patch)
{
    uint64_t msr_content;
    unsigned int cpu = smp_processor_id();
    struct cpu_signature *sig = &this_cpu(cpu_sig);
    uint32_t rev, old_rev = sig->rev;

    if ( microcode_update_match(patch) != NEW_UCODE )
        return -EINVAL;

    wbinvd();

    /* write microcode via MSR 0x79 */
    wrmsrl(MSR_IA32_UCODE_WRITE, (unsigned long)patch->data);
    wrmsrl(MSR_IA32_UCODE_REV, 0x0ULL);

    /* As documented in the SDM: Do a CPUID 1 here */
    cpuid_eax(1);

    /* get the current revision from MSR 0x8B */
    rdmsrl(MSR_IA32_UCODE_REV, msr_content);
    sig->rev = rev = msr_content >> 32;

    if ( rev != patch->rev )
    {
        printk(XENLOG_ERR
               "microcode: CPU%u update rev %#x to %#x failed, result %#x\n",
               cpu, old_rev, patch->rev, rev);
        return -EIO;
    }

    printk(XENLOG_WARNING
           "microcode: CPU%u updated from revision %#x to %#x, date = %04x-%02x-%02x\n",
           cpu, old_rev, rev, patch->year, patch->month, patch->day);

    return 0;
}

static struct microcode_patch *cpu_request_microcode(const void *buf,
                                                     size_t size)
{
    int error = 0;
    const struct microcode_patch *saved = NULL;
    struct microcode_patch *patch = NULL;

    while ( size )
    {
        const struct microcode_patch *mc;
        unsigned int blob_size;

        if ( size < MC_HEADER_SIZE ||       /* Insufficient space for header? */
             (mc = buf)->hdrver != 1 ||     /* Unrecognised header version?   */
             mc->ldrver != 1 ||             /* Unrecognised loader version?   */
             size < (blob_size =            /* Insufficient space for patch?  */
                     get_totalsize(mc)) )
        {
            error = -EINVAL;
            printk(XENLOG_WARNING "microcode: Bad data in container\n");
            break;
        }

        error = microcode_sanity_check(mc);
        if ( error )
            break;

        /*
         * If the new update covers current CPU, compare updates and store the
         * one with higher revision.
         */
        if ( (microcode_update_match(mc) != MIS_UCODE) &&
             (!saved || (mc->rev > saved->rev)) )
            saved = mc;

        buf  += blob_size;
        size -= blob_size;
    }

    if ( saved )
    {
        patch = xmemdup_bytes(saved, get_totalsize(saved));

        if ( !patch )
            error = -ENOMEM;
    }

    if ( error && !patch )
        patch = ERR_PTR(error);

    return patch;
}

const struct microcode_ops intel_ucode_ops = {
    .cpu_request_microcode            = cpu_request_microcode,
    .collect_cpu_info                 = collect_cpu_info,
    .apply_microcode                  = apply_microcode,
    .compare_patch                    = compare_patch,
};
