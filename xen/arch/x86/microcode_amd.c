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
static int collect_cpu_info(unsigned int cpu, struct cpu_signature *csig)
{
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

static bool_t microcode_fits(const struct microcode_amd *mc_amd,
                             unsigned int cpu)
{
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);
    const struct microcode_header_amd *mc_header = mc_amd->mpb;
    const struct equiv_cpu_entry *equiv_cpu_table = mc_amd->equiv_cpu_table;
    unsigned int current_cpu_id;
    unsigned int equiv_cpu_id;

    /* We should bind the task to the CPU */
    BUG_ON(cpu != raw_smp_processor_id());

    current_cpu_id = cpuid_eax(0x00000001);

    if ( !find_equiv_cpu_id(equiv_cpu_table, current_cpu_id, &equiv_cpu_id) )
        return 0;

    if ( (mc_header->processor_rev_id) != equiv_cpu_id )
        return 0;

    if ( !verify_patch_size(mc_amd->mpb_size) )
    {
        pr_debug("microcode: patch size mismatch\n");
        return 0;
    }

    if ( mc_header->patch_id <= uci->cpu_sig.rev )
    {
        pr_debug("microcode: patch is already at required level or greater.\n");
        return 0;
    }

    pr_debug("microcode: CPU%d found a matching microcode update with version %#x (current=%#x)\n",
             cpu, mc_header->patch_id, uci->cpu_sig.rev);

    return 1;
}

static int apply_microcode(unsigned int cpu)
{
    unsigned long flags;
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);
    uint32_t rev;
    struct microcode_amd *mc_amd = uci->mc.mc_amd;
    struct microcode_header_amd *hdr;
    int hw_err;

    /* We should bind the task to the CPU */
    BUG_ON(raw_smp_processor_id() != cpu);

    if ( mc_amd == NULL )
        return -EINVAL;

    hdr = mc_amd->mpb;
    if ( hdr == NULL )
        return -EINVAL;

    spin_lock_irqsave(&microcode_update_lock, flags);

    hw_err = wrmsr_safe(MSR_AMD_PATCHLOADER, (unsigned long)hdr);

    /* get patch id after patching */
    rdmsrl(MSR_AMD_PATCHLEVEL, rev);

    spin_unlock_irqrestore(&microcode_update_lock, flags);

    /* check current patch id and patch's id for match */
    if ( hw_err || (rev != hdr->patch_id) )
    {
        printk(KERN_ERR "microcode: CPU%d update from revision "
               "%#x to %#x failed\n", cpu, rev, hdr->patch_id);
        return -EIO;
    }

    printk(KERN_WARNING "microcode: CPU%d updated from revision %#x to %#x\n",
           cpu, uci->cpu_sig.rev, hdr->patch_id);

    uci->cpu_sig.rev = rev;

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

    if ( mc_amd->mpb_size < mpbuf->len )
    {
        if ( mc_amd->mpb )
        {
            xfree(mc_amd->mpb);
            mc_amd->mpb_size = 0;
        }
        mc_amd->mpb = xmalloc_bytes(mpbuf->len);
        if ( mc_amd->mpb == NULL )
            return -ENOMEM;
        mc_amd->mpb_size = mpbuf->len;
    }
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
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);
    unsigned int i;

    if ( boot_cpu_data.x86 != 0x10 )
        return 0;

    for ( i = 0; i < ARRAY_SIZE(final_levels); i++ )
        if ( uci->cpu_sig.rev == final_levels[i] )
            return 1;

    return 0;
}

static int cpu_request_microcode(unsigned int cpu, const void *buf,
                                 size_t bufsize)
{
    struct microcode_amd *mc_amd, *mc_old;
    size_t offset = 0;
    size_t last_offset, applied_offset = 0;
    int error = 0, save_error = 1;
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);
    unsigned int current_cpu_id;
    unsigned int equiv_cpu_id;

    /* We should bind the task to the CPU */
    BUG_ON(cpu != raw_smp_processor_id());

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

    mc_amd = xmalloc(struct microcode_amd);
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
                   "Current lvl:%#x\n", cpu, uci->cpu_sig.rev);
            break;
        }
    }

    if ( error )
    {
        xfree(mc_amd);
        goto out;
    }

    mc_old = uci->mc.mc_amd;
    /* implicitely validates uci->mc.mc_valid */
    uci->mc.mc_amd = mc_amd;

    /*
     * It's possible the data file has multiple matching ucode,
     * lets keep searching till the latest version
     */
    mc_amd->mpb = NULL;
    mc_amd->mpb_size = 0;
    last_offset = offset;
    while ( (error = get_ucode_from_buffer_amd(mc_amd, buf, bufsize,
                                               &offset)) == 0 )
    {
        if ( microcode_fits(mc_amd, cpu) )
        {
            error = apply_microcode(cpu);
            if ( error )
                break;
            applied_offset = last_offset;
        }

        last_offset = offset;

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

    /* On success keep the microcode patch for
     * re-apply on resume.
     */
    if ( applied_offset )
    {
        save_error = get_ucode_from_buffer_amd(
            mc_amd, buf, bufsize, &applied_offset);

        if ( save_error )
            error = save_error;
    }

    if ( save_error )
    {
        xfree(mc_amd);
        uci->mc.mc_amd = mc_old;
    }
    else
        xfree(mc_old);

  out:
    svm_host_osvw_init();

    /*
     * In some cases we may return an error even if processor's microcode has
     * been updated. For example, the first patch in a container file is loaded
     * successfully but subsequent container file processing encounters a
     * failure.
     */
    return error;
}

static int microcode_resume_match(unsigned int cpu, const void *mc)
{
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);
    struct microcode_amd *mc_amd = uci->mc.mc_amd;
    const struct microcode_amd *src = mc;

    if ( !microcode_fits(src, cpu) )
        return 0;

    if ( src != mc_amd )
    {
        if ( mc_amd )
        {
            xfree(mc_amd->equiv_cpu_table);
            xfree(mc_amd->mpb);
            xfree(mc_amd);
        }

        mc_amd = xmalloc(struct microcode_amd);
        uci->mc.mc_amd = mc_amd;
        if ( !mc_amd )
            return -ENOMEM;
        mc_amd->equiv_cpu_table = xmalloc_bytes(src->equiv_cpu_table_size);
        if ( !mc_amd->equiv_cpu_table )
            goto err1;
        mc_amd->mpb = xmalloc_bytes(src->mpb_size);
        if ( !mc_amd->mpb )
            goto err2;

        mc_amd->equiv_cpu_table_size = src->equiv_cpu_table_size;
        mc_amd->mpb_size = src->mpb_size;
        memcpy(mc_amd->mpb, src->mpb, src->mpb_size);
        memcpy(mc_amd->equiv_cpu_table, src->equiv_cpu_table,
               src->equiv_cpu_table_size);
    }

    return 1;

err2:
    xfree(mc_amd->equiv_cpu_table);
err1:
    xfree(mc_amd);
    uci->mc.mc_amd = NULL;
    return -ENOMEM;
}

static int start_update(void)
{
    /*
     * We assume here that svm_host_osvw_init() will be called on each cpu (from
     * cpu_request_microcode()).
     *
     * Note that if collect_cpu_info() returns an error then
     * cpu_request_microcode() will not invoked thus leaving OSVW bits not
     * updated. Currently though collect_cpu_info() will not fail on processors
     * supporting OSVW so we will not deal with this possibility.
     */
    svm_host_osvw_reset();

    return 0;
}

static const struct microcode_ops microcode_amd_ops = {
    .microcode_resume_match           = microcode_resume_match,
    .cpu_request_microcode            = cpu_request_microcode,
    .collect_cpu_info                 = collect_cpu_info,
    .apply_microcode                  = apply_microcode,
    .start_update                     = start_update,
};

static __init int microcode_init_amd(void)
{
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        microcode_ops = &microcode_amd_ops;
    return 0;
}
presmp_initcall(microcode_init_amd);
