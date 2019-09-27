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

#include <xen/lib.h>
#include <xen/kernel.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/spinlock.h>

#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/microcode.h>
#include <asm/hvm/svm/svm.h>

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

struct __packed microcode_header_amd {
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

struct microcode_amd {
    void *mpb;
    size_t mpb_size;
    struct equiv_cpu_entry *equiv_cpu_table;
    size_t equiv_cpu_table_size;
};

struct mpbhdr {
    uint32_t type;
    uint32_t len;
    uint8_t data[];
};

/* serialize access to the physical write */
static DEFINE_SPINLOCK(microcode_update_lock);

/* See comment in start_update() for cases when this routine fails */
static int collect_cpu_info(struct cpu_signature *csig)
{
    unsigned int cpu = smp_processor_id();
    struct cpuinfo_x86 *c = &cpu_data[cpu];

    memset(csig, 0, sizeof(*csig));

    if ( (c->x86_vendor != X86_VENDOR_AMD) || (c->x86 < 0x10) )
    {
        printk(KERN_ERR "microcode: CPU%d not a capable AMD processor\n",
               cpu);
        return -EINVAL;
    }

    rdmsrl(MSR_AMD_PATCHLEVEL, csig->rev);

    pr_debug("microcode: CPU%d collect_cpu_info: patch_id=%#x\n",
             cpu, csig->rev);

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

static bool_t find_equiv_cpu_id(const struct equiv_cpu_entry *equiv_cpu_table,
                                unsigned int current_cpu_id,
                                unsigned int *equiv_cpu_id)
{
    unsigned int i;

    if ( !equiv_cpu_table )
        return 0;

    for ( i = 0; equiv_cpu_table[i].installed_cpu != 0; i++ )
    {
        if ( current_cpu_id == equiv_cpu_table[i].installed_cpu )
        {
            *equiv_cpu_id = equiv_cpu_table[i].equiv_cpu & 0xffff;
            return 1;
        }
    }

    return 0;
}

static enum microcode_match_result microcode_fits(
    const struct microcode_amd *mc_amd)
{
    unsigned int cpu = smp_processor_id();
    const struct cpu_signature *sig = &per_cpu(cpu_sig, cpu);
    const struct microcode_header_amd *mc_header = mc_amd->mpb;
    const struct equiv_cpu_entry *equiv_cpu_table = mc_amd->equiv_cpu_table;
    unsigned int current_cpu_id;
    unsigned int equiv_cpu_id;

    current_cpu_id = cpuid_eax(0x00000001);

    if ( !find_equiv_cpu_id(equiv_cpu_table, current_cpu_id, &equiv_cpu_id) )
        return MIS_UCODE;

    if ( (mc_header->processor_rev_id) != equiv_cpu_id )
        return MIS_UCODE;

    if ( !verify_patch_size(mc_amd->mpb_size) )
    {
        pr_debug("microcode: patch size mismatch\n");
        return MIS_UCODE;
    }

    if ( mc_header->patch_id <= sig->rev )
    {
        pr_debug("microcode: patch is already at required level or greater.\n");
        return OLD_UCODE;
    }

    pr_debug("microcode: CPU%d found a matching microcode update with version %#x (current=%#x)\n",
             cpu, mc_header->patch_id, sig->rev);

    return NEW_UCODE;
}

static bool match_cpu(const struct microcode_patch *patch)
{
    return patch && (microcode_fits(patch->mc_amd) == NEW_UCODE);
}

static void free_patch(void *mc)
{
    struct microcode_amd *mc_amd = mc;

    if ( mc_amd )
    {
        xfree(mc_amd->equiv_cpu_table);
        xfree(mc_amd->mpb);
        xfree(mc_amd);
    }
}

static enum microcode_match_result compare_header(
    const struct microcode_header_amd *new_header,
    const struct microcode_header_amd *old_header)
{
    if ( new_header->processor_rev_id == old_header->processor_rev_id )
        return (new_header->patch_id > old_header->patch_id) ? NEW_UCODE
                                                             : OLD_UCODE;

    return MIS_UCODE;
}

static enum microcode_match_result compare_patch(
    const struct microcode_patch *new, const struct microcode_patch *old)
{
    const struct microcode_header_amd *new_header = new->mc_amd->mpb;
    const struct microcode_header_amd *old_header = old->mc_amd->mpb;

    /* Both patches to compare are supposed to be applicable to local CPU. */
    ASSERT(microcode_fits(new->mc_amd) != MIS_UCODE);
    ASSERT(microcode_fits(new->mc_amd) != MIS_UCODE);

    return compare_header(new_header, old_header);
}

static int apply_microcode(const struct microcode_patch *patch)
{
    unsigned long flags;
    uint32_t rev;
    int hw_err;
    unsigned int cpu = smp_processor_id();
    struct cpu_signature *sig = &per_cpu(cpu_sig, cpu);
    const struct microcode_header_amd *hdr;

    if ( !patch )
        return -ENOENT;

    if ( !match_cpu(patch) )
        return -EINVAL;

    hdr = patch->mc_amd->mpb;

    spin_lock_irqsave(&microcode_update_lock, flags);

    hw_err = wrmsr_safe(MSR_AMD_PATCHLOADER, (unsigned long)hdr);

    /* get patch id after patching */
    rdmsrl(MSR_AMD_PATCHLEVEL, rev);

    spin_unlock_irqrestore(&microcode_update_lock, flags);

    /*
     * Some processors leave the ucode blob mapping as UC after the update.
     * Flush the mapping to regain normal cacheability.
     */
    flush_area_local(hdr, FLUSH_TLB_GLOBAL | FLUSH_ORDER(0));

    /* check current patch id and patch's id for match */
    if ( hw_err || (rev != hdr->patch_id) )
    {
        printk(KERN_ERR "microcode: CPU%d update from revision "
               "%#x to %#x failed\n", cpu, rev, hdr->patch_id);
        return -EIO;
    }

    printk(KERN_WARNING "microcode: CPU%d updated from revision %#x to %#x\n",
           cpu, sig->rev, hdr->patch_id);

    sig->rev = rev;

    return 0;
}

static int get_ucode_from_buffer_amd(
    struct microcode_amd *mc_amd,
    const void *buf,
    size_t bufsize,
    size_t *offset)
{
    const struct mpbhdr *mpbuf = buf + *offset;

    /* No more data */
    if ( *offset >= bufsize )
    {
        printk(KERN_ERR "microcode: Microcode buffer overrun\n");
        return -EINVAL;
    }

    if ( mpbuf->type != UCODE_UCODE_TYPE )
    {
        printk(KERN_ERR "microcode: Wrong microcode payload type field\n");
        return -EINVAL;
    }

    if ( (*offset + mpbuf->len) > bufsize )
    {
        printk(KERN_ERR "microcode: Bad data in microcode data file\n");
        return -EINVAL;
    }

    mc_amd->mpb = xmalloc_bytes(mpbuf->len);
    if ( !mc_amd->mpb )
        return -ENOMEM;
    mc_amd->mpb_size = mpbuf->len;
    memcpy(mc_amd->mpb, mpbuf->data, mpbuf->len);

    pr_debug("microcode: CPU%d size %zu, block size %u offset %zu equivID %#x rev %#x\n",
             raw_smp_processor_id(), bufsize, mpbuf->len, *offset,
             ((struct microcode_header_amd *)mc_amd->mpb)->processor_rev_id,
             ((struct microcode_header_amd *)mc_amd->mpb)->patch_id);

    *offset += mpbuf->len + SECTION_HDR_SIZE;

    return 0;
}

static int install_equiv_cpu_table(
    struct microcode_amd *mc_amd,
    const void *data,
    size_t *offset)
{
    const struct mpbhdr *mpbuf = data + *offset + 4;

    *offset += mpbuf->len + CONT_HDR_SIZE;	/* add header length */

    if ( mpbuf->type != UCODE_EQUIV_CPU_TABLE_TYPE )
    {
        printk(KERN_ERR "microcode: Wrong microcode equivalent cpu table type field\n");
        return -EINVAL;
    }

    if ( mpbuf->len == 0 )
    {
        printk(KERN_ERR "microcode: Wrong microcode equivalent cpu table length\n");
        return -EINVAL;
    }

    mc_amd->equiv_cpu_table = xmalloc_bytes(mpbuf->len);
    if ( !mc_amd->equiv_cpu_table )
    {
        printk(KERN_ERR "microcode: Cannot allocate memory for equivalent cpu table\n");
        return -ENOMEM;
    }

    memcpy(mc_amd->equiv_cpu_table, mpbuf->data, mpbuf->len);
    mc_amd->equiv_cpu_table_size = mpbuf->len;

    return 0;
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
    0x010000af
};

static bool_t check_final_patch_levels(unsigned int cpu)
{
    /*
     * Check the current patch levels on the cpu. If they are equal to
     * any of the 'final_levels', then we should not update the microcode
     * patch on the cpu as system will hang otherwise.
     */
    const struct cpu_signature *sig = &per_cpu(cpu_sig, cpu);
    unsigned int i;

    if ( boot_cpu_data.x86 != 0x10 )
        return 0;

    for ( i = 0; i < ARRAY_SIZE(final_levels); i++ )
        if ( sig->rev == final_levels[i] )
            return 1;

    return 0;
}

static struct microcode_patch *cpu_request_microcode(const void *buf,
                                                     size_t bufsize)
{
    struct microcode_amd *mc_amd;
    struct microcode_header_amd *saved = NULL;
    struct microcode_patch *patch = NULL;
    size_t offset = 0, saved_size = 0;
    int error = 0;
    unsigned int current_cpu_id;
    unsigned int equiv_cpu_id;
    unsigned int cpu = smp_processor_id();
    const struct cpu_signature *sig = &per_cpu(cpu_sig, cpu);

    current_cpu_id = cpuid_eax(0x00000001);

    if ( *(const uint32_t *)buf != UCODE_MAGIC )
    {
        printk(KERN_ERR "microcode: Wrong microcode patch file magic\n");
        error = -EINVAL;
        goto out;
    }

    if ( check_final_patch_levels(cpu) )
    {
        printk(XENLOG_INFO
               "microcode: Cannot update microcode patch on the cpu as we hit a final level\n");
        error = -EPERM;
        goto out;
    }

    mc_amd = xzalloc(struct microcode_amd);
    if ( !mc_amd )
    {
        printk(KERN_ERR "microcode: Cannot allocate memory for microcode patch\n");
        error = -ENOMEM;
        goto out;
    }

    /*
     * Multiple container file support:
     * 1. check if this container file has equiv_cpu_id match
     * 2. If not, fast-fwd to next container file
     */
    while ( offset < bufsize )
    {
        error = install_equiv_cpu_table(mc_amd, buf, &offset);
        if ( error )
        {
            printk(KERN_ERR "microcode: installing equivalent cpu table failed\n");
            break;
        }

        /*
         * Could happen as we advance 'offset' early
         * in install_equiv_cpu_table
         */
        if ( offset > bufsize )
        {
            printk(KERN_ERR "microcode: Microcode buffer overrun\n");
            error = -EINVAL;
            break;
        }

        if ( find_equiv_cpu_id(mc_amd->equiv_cpu_table, current_cpu_id,
                               &equiv_cpu_id) )
            break;

        error = container_fast_forward(buf, bufsize - offset, &offset);
        if ( error == -ENODATA )
        {
            ASSERT(offset == bufsize);
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
        xfree(mc_amd->equiv_cpu_table);
        xfree(mc_amd);
        goto out;
    }

    /*
     * It's possible the data file has multiple matching ucode,
     * lets keep searching till the latest version
     */
    while ( (error = get_ucode_from_buffer_amd(mc_amd, buf, bufsize,
                                               &offset)) == 0 )
    {
        /*
         * If the new ucode covers current CPU, compare ucodes and store the
         * one with higher revision.
         */
        if ( (microcode_fits(mc_amd) != MIS_UCODE) &&
             (!saved || (compare_header(mc_amd->mpb, saved) == NEW_UCODE)) )
        {
            xfree(saved);
            saved = mc_amd->mpb;
            saved_size = mc_amd->mpb_size;
        }
        else
        {
            xfree(mc_amd->mpb);
            mc_amd->mpb = NULL;
        }

        if ( offset >= bufsize )
            break;

        /*
         * 1. Given a situation where multiple containers exist and correct
         *    patch lives on a container that is not the last container.
         * 2. We match equivalent ids using find_equiv_cpu_id() from the
         *    earlier while() (On this case, matches on earlier container
         *    file and we break)
         * 3. Proceed to while ( (error = get_ucode_from_buffer_amd(mc_amd,
         *                                  buf, bufsize,&offset)) == 0 )
         * 4. Find correct patch using microcode_fits() and apply the patch
         *    (Assume: apply_microcode() is successful)
         * 5. The while() loop from (3) continues to parse the binary as
         *    there is a subsequent container file, but...
         * 6. ...a correct patch can only be on one container and not on any
         *    subsequent ones. (Refer docs for more info) Therefore, we
         *    don't have to parse a subsequent container. So, we can abort
         *    the process here.
         * 7. This ensures that we retain a success value (= 0) to 'error'
         *    before if ( mpbuf->type != UCODE_UCODE_TYPE ) evaluates to
         *    false and returns -EINVAL.
         */
        if ( offset + SECTION_HDR_SIZE <= bufsize &&
             *(const uint32_t *)(buf + offset) == UCODE_MAGIC )
            break;
    }

    if ( saved )
    {
        mc_amd->mpb = saved;
        mc_amd->mpb_size = saved_size;
        patch = xmalloc(struct microcode_patch);
        if ( patch )
            patch->mc_amd = mc_amd;
        else
        {
            free_patch(mc_amd);
            error = -ENOMEM;
        }
    }
    else
        free_patch(mc_amd);

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

static const struct microcode_ops microcode_amd_ops = {
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

int __init microcode_init_amd(void)
{
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        microcode_ops = &microcode_amd_ops;
    return 0;
}
