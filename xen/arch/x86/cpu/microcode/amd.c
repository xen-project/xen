/*
 *  AMD CPU Microcode Update Driver for Linux
 *  Copyright (C) 2008 Advanced Micro Devices Inc.
 *
 *  Author: Peter Oruba <peter.oruba@amd.com>
 *
 *  Based on work by:
 *  Tigran Aivazian <tigran@aivazian.fsnet.co.uk>
 *
 *  This driver allows to upgrade microcode on AMD
 *  family 0x10 and later.
 *
 *  Licensed unter the terms of the GNU General Public
 *  License version 2. See file COPYING for details.
 */

#include <xen/err.h>
#include <xen/init.h>
#include <xen/mm.h> /* TODO: Fix asm/tlbflush.h breakage */

#include <asm/hvm/svm/svm.h>
#include <asm/msr.h>

#include "private.h"

#define pr_debug(x...) ((void)0)

#define CONT_HDR_SIZE           12
#define SECTION_HDR_SIZE        8
#define PATCH_HDR_SIZE          32

struct __packed equiv_cpu_entry {
    uint32_t installed_cpu;
    uint32_t fixed_errata_mask;
    uint32_t fixed_errata_compare;
    uint16_t equiv_cpu;
    uint16_t reserved;
};

struct microcode_patch {
    uint32_t data_code;
    uint32_t patch_id;
    uint8_t  mc_patch_data_id[2];
    uint8_t  mc_patch_data_len;
    uint8_t  init_flag;
    uint32_t mc_patch_data_checksum;
    uint32_t nb_dev_id;
    uint32_t sb_dev_id;
    uint16_t processor_rev_id;
    uint8_t  nb_rev_id;
    uint8_t  sb_rev_id;
    uint8_t  bios_api_rev;
    uint8_t  reserved1[3];
    uint32_t match_reg[8];
};

#define UCODE_MAGIC                0x00414d44
#define UCODE_EQUIV_CPU_TABLE_TYPE 0x00000000
#define UCODE_UCODE_TYPE           0x00000001

struct mpbhdr {
    uint32_t type;
    uint32_t len;
    uint8_t data[];
};
struct container_microcode {
    uint32_t type; /* UCODE_UCODE_TYPE */
    uint32_t len;
    struct microcode_patch patch[];
};

/*
 * Microcode updates for different CPUs are distinguished by their
 * processor_rev_id in the header.  This denotes the format of the internals
 * of the microcode engine, and is fixed for an individual CPU.
 *
 * There is a mapping from the CPU signature (CPUID.1.EAX -
 * family/model/stepping) to the "equivalent CPU identifier" which is
 * similarly fixed.  In some cases, multiple different CPU signatures map to
 * the same equiv_id for processor lines which share identical microcode
 * facilities.
 *
 * This mapping can't be calculated in the general case, but is provided in
 * the microcode container, so the correct piece of microcode for the CPU can
 * be identified.  We cache it the first time we encounter the correct mapping
 * for this system.
 *
 * Note: for now, we assume a fully homogeneous setup, meaning that there is
 * exactly one equiv_id we need to worry about for microcode blob
 * identification.  This may need revisiting in due course.
 */
static struct {
    uint32_t sig;
    uint16_t id;
} equiv __read_mostly;

/* See comment in start_update() for cases when this routine fails */
static int collect_cpu_info(struct cpu_signature *csig)
{
    memset(csig, 0, sizeof(*csig));

    csig->sig = cpuid_eax(1);
    rdmsrl(MSR_AMD_PATCHLEVEL, csig->rev);

    pr_debug("microcode: CPU%d collect_cpu_info: patch_id=%#x\n",
             smp_processor_id(), csig->rev);

    return 0;
}

static bool_t verify_patch_size(uint32_t patch_size)
{
    uint32_t max_size;

#define F1XH_MPB_MAX_SIZE 2048
#define F14H_MPB_MAX_SIZE 1824
#define F15H_MPB_MAX_SIZE 4096
#define F16H_MPB_MAX_SIZE 3458
#define F17H_MPB_MAX_SIZE 3200

    switch (boot_cpu_data.x86)
    {
    case 0x14:
        max_size = F14H_MPB_MAX_SIZE;
        break;
    case 0x15:
        max_size = F15H_MPB_MAX_SIZE;
        break;
    case 0x16:
        max_size = F16H_MPB_MAX_SIZE;
        break;
    case 0x17:
        max_size = F17H_MPB_MAX_SIZE;
        break;
    default:
        max_size = F1XH_MPB_MAX_SIZE;
        break;
    }

    return (patch_size <= max_size);
}

static bool check_final_patch_levels(const struct cpu_signature *sig)
{
    /*
     * The 'final_levels' of patch ids have been obtained empirically.
     * Refer bug https://bugzilla.suse.com/show_bug.cgi?id=913996
     * for details of the issue. The short version is that people
     * using certain Fam10h systems noticed system hang issues when
     * trying to update microcode levels beyond the patch IDs below.
     * From internal discussions, we gathered that OS/hypervisor
     * cannot reliably perform microcode updates beyond these levels
     * due to hardware issues. Therefore, we need to abort microcode
     * update process if we hit any of these levels.
     */
    static const unsigned int final_levels[] = {
        0x01000098,
        0x0100009f,
        0x010000af,
    };
    unsigned int i;

    if ( boot_cpu_data.x86 != 0x10 )
        return false;

    for ( i = 0; i < ARRAY_SIZE(final_levels); i++ )
        if ( sig->rev == final_levels[i] )
            return true;

    return false;
}

static enum microcode_match_result microcode_fits(
    const struct microcode_patch *patch)
{
    unsigned int cpu = smp_processor_id();
    const struct cpu_signature *sig = &per_cpu(cpu_sig, cpu);

    if ( equiv.sig != sig->sig ||
         equiv.id  != patch->processor_rev_id )
        return MIS_UCODE;

    if ( patch->patch_id <= sig->rev )
    {
        pr_debug("microcode: patch is already at required level or greater.\n");
        return OLD_UCODE;
    }

    pr_debug("microcode: CPU%d found a matching microcode update with version %#x (current=%#x)\n",
             cpu, patch->patch_id, sig->rev);

    return NEW_UCODE;
}

static bool match_cpu(const struct microcode_patch *patch)
{
    return patch && (microcode_fits(patch) == NEW_UCODE);
}

static void free_patch(struct microcode_patch *patch)
{
    xfree(patch);
}

static enum microcode_match_result compare_header(
    const struct microcode_patch *new, const struct microcode_patch *old)
{
    if ( new->processor_rev_id != old->processor_rev_id )
        return MIS_UCODE;

    return new->patch_id > old->patch_id ? NEW_UCODE : OLD_UCODE;
}

static enum microcode_match_result compare_patch(
    const struct microcode_patch *new, const struct microcode_patch *old)
{
    /* Both patches to compare are supposed to be applicable to local CPU. */
    ASSERT(microcode_fits(new) != MIS_UCODE);
    ASSERT(microcode_fits(old) != MIS_UCODE);

    return compare_header(new, old);
}

static int apply_microcode(const struct microcode_patch *patch)
{
    int hw_err;
    unsigned int cpu = smp_processor_id();
    struct cpu_signature *sig = &per_cpu(cpu_sig, cpu);
    uint32_t rev, old_rev = sig->rev;

    if ( !patch )
        return -ENOENT;

    if ( !match_cpu(patch) )
        return -EINVAL;

    if ( check_final_patch_levels(sig) )
    {
        printk(XENLOG_ERR
               "microcode: CPU%u current rev %#x unsafe to update\n",
               cpu, sig->rev);
        return -ENXIO;
    }

    hw_err = wrmsr_safe(MSR_AMD_PATCHLOADER, (unsigned long)patch);

    /* get patch id after patching */
    rdmsrl(MSR_AMD_PATCHLEVEL, rev);
    sig->rev = rev;

    /*
     * Some processors leave the ucode blob mapping as UC after the update.
     * Flush the mapping to regain normal cacheability.
     */
    flush_area_local(patch, FLUSH_TLB_GLOBAL | FLUSH_ORDER(0));

    /* check current patch id and patch's id for match */
    if ( hw_err || (rev != patch->patch_id) )
    {
        printk(XENLOG_ERR
               "microcode: CPU%u update rev %#x to %#x failed, result %#x\n",
               cpu, old_rev, patch->patch_id, rev);
        return -EIO;
    }

    printk(XENLOG_WARNING "microcode: CPU%u updated from revision %#x to %#x\n",
           cpu, old_rev, rev);

    return 0;
}

static int scan_equiv_cpu_table(
    const void *data,
    size_t size_left,
    size_t *offset)
{
    const struct cpu_signature *sig = &this_cpu(cpu_sig);
    const struct mpbhdr *mpbuf;
    const struct equiv_cpu_entry *eq;
    unsigned int i, nr;

    if ( size_left < (sizeof(*mpbuf) + 4) ||
         (mpbuf = data + *offset + 4,
          size_left - sizeof(*mpbuf) - 4 < mpbuf->len) )
    {
        printk(XENLOG_WARNING "microcode: No space for equivalent cpu table\n");
        return -EINVAL;
    }

    *offset += mpbuf->len + CONT_HDR_SIZE;	/* add header length */

    if ( mpbuf->type != UCODE_EQUIV_CPU_TABLE_TYPE )
    {
        printk(KERN_ERR "microcode: Wrong microcode equivalent cpu table type field\n");
        return -EINVAL;
    }

    if ( mpbuf->len == 0 || mpbuf->len % sizeof(*eq) ||
         (eq = (const void *)mpbuf->data,
          nr = mpbuf->len / sizeof(*eq),
          eq[nr - 1].installed_cpu) )
    {
        printk(KERN_ERR "microcode: Wrong microcode equivalent cpu table length\n");
        return -EINVAL;
    }

    /* Search the equiv_cpu_table for the current CPU. */
    for ( i = 0; i < nr && eq[i].installed_cpu; ++i )
    {
        if ( eq[i].installed_cpu != sig->sig )
            continue;

        if ( !equiv.sig ) /* Cache details on first find. */
        {
            equiv.sig = sig->sig;
            equiv.id  = eq[i].equiv_cpu;
            return 0;
        }

        if ( equiv.sig != sig->sig || equiv.id != eq[i].equiv_cpu )
        {
            /*
             * This can only occur if two equiv tables have been seen with
             * different mappings for the same CPU.  The mapping is fixed, so
             * one of the tables is wrong.  As we can't calculate the mapping,
             * we trusted the first table we saw.
             */
            printk(XENLOG_ERR
                   "microcode: Equiv mismatch: cpu %08x, got %04x, cached %04x\n",
                   sig->sig, eq[i].equiv_cpu, equiv.id);
            return -EINVAL;
        }

        return 0;
    }

    /* equiv_cpu_table was fine, but nothing found for the current CPU. */
    return -ESRCH;
}

static int container_fast_forward(const void *data, size_t size_left, size_t *offset)
{
    for ( ; ; )
    {
        size_t size;
        const uint32_t *header;

        if ( size_left < SECTION_HDR_SIZE )
            return -EINVAL;

        header = data + *offset;

        if ( header[0] == UCODE_MAGIC &&
             header[1] == UCODE_EQUIV_CPU_TABLE_TYPE )
            break;

        if ( header[0] != UCODE_UCODE_TYPE )
            return -EINVAL;
        size = header[1] + SECTION_HDR_SIZE;
        if ( size < PATCH_HDR_SIZE || size_left < size )
            return -EINVAL;

        size_left -= size;
        *offset += size;

        if ( !size_left )
            return -ENODATA;
    }

    return 0;
}

static struct microcode_patch *cpu_request_microcode(const void *buf, size_t size)
{
    const struct microcode_patch *saved = NULL;
    struct microcode_patch *patch = NULL;
    size_t offset = 0, saved_size = 0;
    int error = 0;
    unsigned int cpu = smp_processor_id();
    const struct cpu_signature *sig = &per_cpu(cpu_sig, cpu);

    if ( size < 4 || *(const uint32_t *)buf != UCODE_MAGIC )
    {
        printk(KERN_ERR "microcode: Wrong microcode patch file magic\n");
        error = -EINVAL;
        goto out;
    }

    /*
     * Multiple container file support:
     * 1. check if this container file has equiv_cpu_id match
     * 2. If not, fast-fwd to next container file
     */
    while ( offset < size )
    {
        error = scan_equiv_cpu_table(buf, size - offset, &offset);

        if ( !error || error != -ESRCH )
            break;

        error = container_fast_forward(buf, size - offset, &offset);
        if ( error == -ENODATA )
        {
            ASSERT(offset == size);
            break;
        }
        if ( error )
        {
            printk(KERN_ERR "microcode: CPU%d incorrect or corrupt container file\n"
                   "microcode: Failed to update patch level. "
                   "Current lvl:%#x\n", cpu, sig->rev);
            break;
        }
    }

    if ( error )
    {
        /*
         * -ENODATA here means that the blob was parsed fine but no matching
         * ucode was found. Don't return it to the caller.
         */
        if ( error == -ENODATA )
            error = 0;

        goto out;
    }

    /*
     * It's possible the data file has multiple matching ucode,
     * lets keep searching till the latest version
     */
    buf  += offset;
    size -= offset;
    {
        while ( size )
        {
            const struct container_microcode *mc;

            if ( size < sizeof(*mc) ||
                 (mc = buf)->type != UCODE_UCODE_TYPE ||
                 size - sizeof(*mc) < mc->len ||
                 !verify_patch_size(mc->len) )
            {
                printk(XENLOG_ERR "microcode: Bad microcode data\n");
                error = -EINVAL;
                break;
            }

            /*
             * If the new ucode covers current CPU, compare ucodes and store the
             * one with higher revision.
             */
            if ( (microcode_fits(mc->patch) != MIS_UCODE) &&
                 (!saved || (compare_header(mc->patch, saved) == NEW_UCODE)) )
            {
                saved = mc->patch;
                saved_size = mc->len;
            }

            /* Move over the microcode blob. */
            buf  += sizeof(*mc) + mc->len;
            size -= sizeof(*mc) + mc->len;

            /*
             * Peek ahead.  If we see the start of another container, we've
             * exhaused all microcode blobs in this container.  Exit cleanly.
             */
            if ( size >= 4 && *(const uint32_t *)buf == UCODE_MAGIC )
                break;
        }
    }

    if ( saved )
    {
        patch = xmemdup_bytes(saved, saved_size);
        if ( !patch )
            error = -ENOMEM;
    }

  out:
    if ( error && !patch )
        patch = ERR_PTR(error);

    return patch;
}

#ifdef CONFIG_HVM
static int start_update(void)
{
    /*
     * svm_host_osvw_init() will be called on each cpu by calling '.end_update'
     * in common code.
     */
    svm_host_osvw_reset();

    return 0;
}
#endif

const struct microcode_ops amd_ucode_ops = {
    .cpu_request_microcode            = cpu_request_microcode,
    .collect_cpu_info                 = collect_cpu_info,
    .apply_microcode                  = apply_microcode,
#ifdef CONFIG_HVM
    .start_update                     = start_update,
    .end_update_percpu                = svm_host_osvw_init,
#endif
    .free_patch                       = free_patch,
    .compare_patch                    = compare_patch,
    .match_cpu                        = match_cpu,
};
