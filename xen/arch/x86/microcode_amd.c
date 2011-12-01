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
 *  family 0x10 and 0x11 processors.
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

#define pr_debug(x...) ((void)0)

struct equiv_cpu_entry {
    uint32_t installed_cpu;
    uint32_t fixed_errata_mask;
    uint32_t fixed_errata_compare;
    uint16_t equiv_cpu;
    uint16_t reserved;
} __attribute__((packed));

struct microcode_header_amd {
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
} __attribute__((packed));

#define UCODE_MAGIC                0x00414d44
#define UCODE_EQUIV_CPU_TABLE_TYPE 0x00000000
#define UCODE_UCODE_TYPE           0x00000001

#define UCODE_MAX_SIZE          (2048)
#define MC_HEADER_SIZE          (sizeof(struct microcode_header_amd))

struct microcode_amd {
    struct microcode_header_amd hdr;
    unsigned int mpb[(UCODE_MAX_SIZE - MC_HEADER_SIZE) / 4];
    unsigned int equiv_cpu_table_size;
    struct equiv_cpu_entry equiv_cpu_table[];
};

/* serialize access to the physical write */
static DEFINE_SPINLOCK(microcode_update_lock);

static int collect_cpu_info(int cpu, struct cpu_signature *csig)
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

    printk(KERN_DEBUG "microcode: collect_cpu_info: patch_id=0x%x\n",
           csig->rev);

    return 0;
}

static int microcode_fits(const struct microcode_amd *mc_amd, int cpu)
{
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);
    const struct microcode_header_amd *mc_header = &mc_amd->hdr;
    const struct equiv_cpu_entry *equiv_cpu_table = mc_amd->equiv_cpu_table;
    unsigned int current_cpu_id;
    unsigned int equiv_cpu_id = 0x0;
    unsigned int i;

    /* We should bind the task to the CPU */
    BUG_ON(cpu != raw_smp_processor_id());

    current_cpu_id = cpuid_eax(0x00000001);

    for ( i = 0; equiv_cpu_table[i].installed_cpu != 0; i++ )
    {
        if ( current_cpu_id == equiv_cpu_table[i].installed_cpu )
        {
            equiv_cpu_id = equiv_cpu_table[i].equiv_cpu & 0xffff;
            break;
        }
    }

    if ( !equiv_cpu_id )
        return 0;

    if ( (mc_header->processor_rev_id) != equiv_cpu_id )
    {
        printk(KERN_DEBUG "microcode: CPU%d patch does not match "
               "(patch is %x, cpu base id is %x) \n",
               cpu, mc_header->processor_rev_id, equiv_cpu_id);
        return -EINVAL;
    }

    if ( mc_header->patch_id <= uci->cpu_sig.rev )
        return 0;

    printk(KERN_DEBUG "microcode: CPU%d found a matching microcode "
           "update with version 0x%x (current=0x%x)\n",
           cpu, mc_header->patch_id, uci->cpu_sig.rev);

    return 1;
}

static int apply_microcode(int cpu)
{
    unsigned long flags;
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);
    uint32_t rev;
    struct microcode_amd *mc_amd = uci->mc.mc_amd;

    /* We should bind the task to the CPU */
    BUG_ON(raw_smp_processor_id() != cpu);

    if ( mc_amd == NULL )
        return -EINVAL;

    spin_lock_irqsave(&microcode_update_lock, flags);

    wrmsrl(MSR_AMD_PATCHLOADER, (unsigned long)&mc_amd->hdr.data_code);

    /* get patch id after patching */
    rdmsrl(MSR_AMD_PATCHLEVEL, rev);

    spin_unlock_irqrestore(&microcode_update_lock, flags);

    /* check current patch id and patch's id for match */
    if ( rev != mc_amd->hdr.patch_id )
    {
        printk(KERN_ERR "microcode: CPU%d update from revision "
               "0x%x to 0x%x failed\n", cpu,
               mc_amd->hdr.patch_id, rev);
        return -EIO;
    }

    printk(KERN_INFO "microcode: CPU%d updated from revision %#x to %#x\n",
           cpu, uci->cpu_sig.rev, mc_amd->hdr.patch_id);

    uci->cpu_sig.rev = rev;

    return 0;
}

static int get_next_ucode_from_buffer_amd(void *mc, const void *buf,
                                         size_t size, unsigned long *offset)
{
    size_t total_size;
    const uint8_t *bufp = buf;
    unsigned long off;

    off = *offset;

    /* No more data */
    if ( off >= size )
        return 1;

    if ( bufp[off] != UCODE_UCODE_TYPE )
    {
        printk(KERN_ERR "microcode: error! "
               "Wrong microcode payload type field\n");
        return -EINVAL;
    }

    total_size = (unsigned long) (bufp[off+4] + (bufp[off+5] << 8));

    printk(KERN_DEBUG "microcode: size %lu, total_size %lu, offset %ld\n",
           (unsigned long)size, total_size, off);

    if ( (off + total_size) > size )
    {
        printk(KERN_ERR "microcode: error! Bad data in microcode data file\n");
        return -EINVAL;
    }

    memset(mc, 0, UCODE_MAX_SIZE);
    memcpy(mc, (const void *)(&bufp[off + 8]), total_size);

    *offset = off + total_size + 8;

    return 0;
}

static int install_equiv_cpu_table(
    struct microcode_amd *mc_amd,
    const uint32_t *buf_pos,
    unsigned long *offset)
{
    uint32_t size = buf_pos[2];

    /* No more data */
    if ( size + 12 >= *offset )
        return -EINVAL;

    if ( buf_pos[1] != UCODE_EQUIV_CPU_TABLE_TYPE )
    {
        printk(KERN_ERR "microcode: error! "
               "Wrong microcode equivalent cpu table type field\n");
        return -EINVAL;
    }

    if ( size == 0 )
    {
        printk(KERN_ERR "microcode: error! "
               "Wrong microcode equivalnet cpu table length\n");
        return -EINVAL;
    }

    memcpy(mc_amd->equiv_cpu_table, &buf_pos[3], size);
    mc_amd->equiv_cpu_table_size = size;

    *offset = size + 12;	/* add header length */

    return 0;
}

static int cpu_request_microcode(int cpu, const void *buf, size_t size)
{
    const uint32_t *buf_pos;
    struct microcode_amd *mc_amd, *mc_old;
    unsigned long offset = size;
    int error = 0;
    int ret;
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);

    /* We should bind the task to the CPU */
    BUG_ON(cpu != raw_smp_processor_id());

    buf_pos = (const uint32_t *)buf;

    if ( buf_pos[0] != UCODE_MAGIC )
    {
        printk(KERN_ERR "microcode: error! Wrong "
               "microcode patch file magic\n");
        return -EINVAL;
    }

    mc_amd = xmalloc_bytes(sizeof(*mc_amd) + buf_pos[2]);
    if ( !mc_amd )
    {
        printk(KERN_ERR "microcode: error! "
               "Can not allocate memory for microcode patch\n");
        return -ENOMEM;
    }

    error = install_equiv_cpu_table(mc_amd, buf, &offset);
    if ( error )
    {
        xfree(mc_amd);
        printk(KERN_ERR "microcode: installing equivalent cpu table failed\n");
        return -EINVAL;
    }

    mc_old = uci->mc.mc_amd;
    /* implicitely validates uci->mc.mc_valid */
    uci->mc.mc_amd = mc_amd;

    /*
     * It's possible the data file has multiple matching ucode,
     * lets keep searching till the latest version
     */
    while ( (ret = get_next_ucode_from_buffer_amd(&mc_amd->hdr, buf, size,
                                                  &offset)) == 0 )
    {
        error = microcode_fits(mc_amd, cpu);
        if (error <= 0)
            continue;

        error = apply_microcode(cpu);
        if (error == 0)
        {
            error = 1;
            break;
        }
    }

    if ( ret < 0 )
        error = ret;

    /* On success keep the microcode patch for
     * re-apply on resume.
     */
    if (error == 1)
    {
        xfree(mc_old);
        return 0;
    }
    xfree(mc_amd);
    uci->mc.mc_amd = mc_old;

    return error;
}

static int microcode_resume_match(int cpu, const void *mc)
{
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);
    struct microcode_amd *mc_amd = uci->mc.mc_amd;
    const struct microcode_amd *src = mc;
    int res = microcode_fits(src, cpu);

    if ( res <= 0 )
        return res;

    if ( src != mc_amd )
    {
        xfree(mc_amd);
        mc_amd = xmalloc_bytes(sizeof(*src) + src->equiv_cpu_table_size);
        uci->mc.mc_amd = mc_amd;
        if ( !mc_amd )
            return -ENOMEM;
        memcpy(mc_amd, src, UCODE_MAX_SIZE);
        memcpy(mc_amd->equiv_cpu_table, src->equiv_cpu_table,
               src->equiv_cpu_table_size);
    }

    return 1;
}

static const struct microcode_ops microcode_amd_ops = {
    .microcode_resume_match           = microcode_resume_match,
    .cpu_request_microcode            = cpu_request_microcode,
    .collect_cpu_info                 = collect_cpu_info,
    .apply_microcode                  = apply_microcode,
};

static __init int microcode_init_amd(void)
{
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        microcode_ops = &microcode_amd_ops;
    return 0;
}
presmp_initcall(microcode_init_amd);
