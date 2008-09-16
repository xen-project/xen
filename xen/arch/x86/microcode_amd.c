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
#include <asm/uaccess.h>
#include <asm/processor.h>
#include <asm/microcode.h>

#define pr_debug(x...) ((void)0)

#define UCODE_MAGIC                0x00414d44
#define UCODE_EQUIV_CPU_TABLE_TYPE 0x00000000
#define UCODE_UCODE_TYPE           0x00000001

#define UCODE_MAX_SIZE          (2048)
#define DEFAULT_UCODE_DATASIZE  (896)
#define MC_HEADER_SIZE          (sizeof(struct microcode_header_amd))
#define DEFAULT_UCODE_TOTALSIZE (DEFAULT_UCODE_DATASIZE + MC_HEADER_SIZE)
#define DWSIZE                  (sizeof(uint32_t))
/* For now we support a fixed ucode total size only */
#define get_totalsize(mc) \
        ((((struct microcode_amd *)mc)->hdr.mc_patch_data_len * 28) \
         + MC_HEADER_SIZE)

/* serialize access to the physical write */
static DEFINE_SPINLOCK(microcode_update_lock);

struct equiv_cpu_entry *equiv_cpu_table;

static long install_equiv_cpu_table(const void *, uint32_t, long);

static int collect_cpu_info(int cpu, struct cpu_signature *csig)
{
    struct cpuinfo_x86 *c = &cpu_data[cpu];

    memset(csig, 0, sizeof(*csig));

    if ( (c->x86_vendor != X86_VENDOR_AMD) || (c->x86 < 0x10) )
    {
        printk(KERN_ERR "microcode: CPU%d not a capable AMD processor\n",
               cpu);
        return -1;
    }

    asm volatile("movl %1, %%ecx; rdmsr"
                 : "=a" (csig->rev)
                 : "i" (MSR_AMD_PATCHLEVEL) : "ecx");

    printk(KERN_INFO "microcode: collect_cpu_info: patch_id=0x%x\n",
           csig->rev);

    return 0;
}

static int get_matching_microcode(void *mc, int cpu)
{
    struct ucode_cpu_info *uci = ucode_cpu_info + cpu;
    struct microcode_header_amd *mc_header = mc;
    unsigned long total_size = get_totalsize(mc_header);
    void *new_mc;
    unsigned int current_cpu_id;
    unsigned int equiv_cpu_id = 0x00;
    unsigned int i = 0;

    /* We should bind the task to the CPU */
    BUG_ON(cpu != raw_smp_processor_id());

    /* This is a tricky part. We might be called from a write operation
     * to the device file instead of the usual process of firmware
     * loading. This routine needs to be able to distinguish both
     * cases. This is done by checking if there already is a equivalent
     * CPU table installed. If not, we're written through
     * /dev/cpu/microcode.
     * Since we ignore all checks. The error case in which going through
     * firmware loading and that table is not loaded has already been
     * checked earlier.
     */
    if ( equiv_cpu_table == NULL )
    {
        printk(KERN_INFO "microcode: CPU%d microcode update with "
               "version 0x%x (current=0x%x)\n",
               cpu, mc_header->patch_id, uci->cpu_sig.rev);
        goto out;
    }

    current_cpu_id = cpuid_eax(0x00000001);

    while ( equiv_cpu_table[i].installed_cpu != 0 )
    {
        if ( current_cpu_id == equiv_cpu_table[i].installed_cpu )
        {
            equiv_cpu_id = equiv_cpu_table[i].equiv_cpu;
            break;
        }
        i++;
    }

    if ( !equiv_cpu_id )
    {
        printk(KERN_ERR "microcode: CPU%d cpu_id "
               "not found in equivalent cpu table \n", cpu);
        return 0;
    }

    if ( (mc_header->processor_rev_id[0]) != (equiv_cpu_id & 0xff) )
    {
        printk(KERN_INFO
               "microcode: CPU%d patch does not match "
               "(patch is %x, cpu extended is %x) \n",
               cpu, mc_header->processor_rev_id[0],
               (equiv_cpu_id & 0xff));
        return 0;
    }

    if ( (mc_header->processor_rev_id[1]) != ((equiv_cpu_id >> 16) & 0xff) )
    {
        printk(KERN_INFO "microcode: CPU%d patch does not match "
               "(patch is %x, cpu base id is %x) \n",
               cpu, mc_header->processor_rev_id[1],
               ((equiv_cpu_id >> 16) & 0xff));
        return 0;
    }

    if ( mc_header->patch_id <= uci->cpu_sig.rev )
        return 0;

    printk(KERN_INFO "microcode: CPU%d found a matching microcode "
           "update with version 0x%x (current=0x%x)\n",
           cpu, mc_header->patch_id, uci->cpu_sig.rev);

 out:
    new_mc = xmalloc_bytes(UCODE_MAX_SIZE);
    if ( new_mc == NULL )
    {
        printk(KERN_ERR "microcode: error, can't allocate memory\n");
        return -ENOMEM;
    }
    memset(new_mc, 0, UCODE_MAX_SIZE);

    /* free previous update file */
    xfree(uci->mc.mc_amd);

    memcpy(new_mc, mc, total_size);

    uci->mc.mc_amd = new_mc;
    return 1;
}

static int apply_microcode(int cpu)
{
    unsigned long flags;
    uint32_t eax, edx, rev;
    int cpu_num = raw_smp_processor_id();
    struct ucode_cpu_info *uci = ucode_cpu_info + cpu_num;
    uint64_t addr;

    /* We should bind the task to the CPU */
    BUG_ON(cpu_num != cpu);

    if ( uci->mc.mc_amd == NULL )
        return -EINVAL;

    spin_lock_irqsave(&microcode_update_lock, flags);

    addr = (unsigned long)&uci->mc.mc_amd->hdr.data_code;
    edx = (uint32_t)(addr >> 32);
    eax = (uint32_t)addr;

    asm volatile("movl %0, %%ecx; wrmsr" :
                 : "i" (MSR_AMD_PATCHLOADER), "a" (eax), "d" (edx) : "ecx");

    /* get patch id after patching */
    asm volatile("movl %1, %%ecx; rdmsr"
                 : "=a" (rev)
                 : "i" (MSR_AMD_PATCHLEVEL) : "ecx");

    spin_unlock_irqrestore(&microcode_update_lock, flags);

    /* check current patch id and patch's id for match */
    if ( rev != uci->mc.mc_amd->hdr.patch_id )
    {
        printk(KERN_ERR "microcode: CPU%d update from revision "
               "0x%x to 0x%x failed\n", cpu_num,
               uci->mc.mc_amd->hdr.patch_id, rev);
        return -EIO;
    }

    printk("microcode: CPU%d updated from revision "
           "0x%x to 0x%x \n",
           cpu_num, uci->cpu_sig.rev, uci->mc.mc_amd->hdr.patch_id);

    uci->cpu_sig.rev = rev;

    return 0;
}

static long get_next_ucode_from_buffer_amd(void **mc, const void *buf,
                                           unsigned long size, long offset)
{
    struct microcode_header_amd *mc_header;
    unsigned long total_size;
    const uint8_t *buf_pos = buf;

    /* No more data */
    if ( offset >= size )
        return 0;

    if ( buf_pos[offset] != UCODE_UCODE_TYPE )
    {
        printk(KERN_ERR "microcode: error! "
               "Wrong microcode payload type field\n");
        return -EINVAL;
    }

    mc_header = (struct microcode_header_amd *)(&buf_pos[offset+8]);

    total_size = (unsigned long) (buf_pos[offset+4] +
                                  (buf_pos[offset+5] << 8));

    printk(KERN_INFO "microcode: size %lu, total_size %lu, offset %ld\n",
           size, total_size, offset);

    if ( (offset + total_size) > size )
    {
        printk(KERN_ERR "microcode: error! Bad data in microcode data file\n");
        return -EINVAL;
    }

    *mc = xmalloc_bytes(UCODE_MAX_SIZE);
    if ( *mc == NULL )
    {
        printk(KERN_ERR "microcode: error! "
               "Can not allocate memory for microcode patch\n");
        return -ENOMEM;
    }

    memset(*mc, 0, UCODE_MAX_SIZE);
    memcpy(*mc, (const void *)(buf + offset + 8), total_size);

    return offset + total_size + 8;
}

static long install_equiv_cpu_table(const void *buf,
                                    uint32_t size, long offset)
{
    const uint32_t *buf_pos = buf;

    /* No more data */
    if ( offset >= size )
        return 0;

    if ( buf_pos[1] != UCODE_EQUIV_CPU_TABLE_TYPE )
    {
        printk(KERN_ERR "microcode: error! "
               "Wrong microcode equivalnet cpu table type field\n");
        return 0;
    }

    if ( size == 0 )
    {
        printk(KERN_ERR "microcode: error! "
               "Wrong microcode equivalnet cpu table length\n");
        return 0;
    }

    equiv_cpu_table = xmalloc_bytes(size);
    if ( equiv_cpu_table == NULL )
    {
        printk(KERN_ERR "microcode: error, can't allocate "
               "memory for equiv CPU table\n");
        return 0;
    }

    memset(equiv_cpu_table, 0, size);
    memcpy(equiv_cpu_table, (const void *)&buf_pos[3], size);

    return size + 12; /* add header length */
}

static int cpu_request_microcode(int cpu, const void *buf, size_t size)
{
    const uint32_t *buf_pos;
    long offset = 0;
    int error = 0;
    void *mc;

    /* We should bind the task to the CPU */
    BUG_ON(cpu != raw_smp_processor_id());

    buf_pos = (const uint32_t *)buf;

    if ( buf_pos[0] != UCODE_MAGIC )
    {
        printk(KERN_ERR "microcode: error! Wrong "
               "microcode patch file magic\n");
        return -EINVAL;
    }

    offset = install_equiv_cpu_table(buf, (uint32_t)(buf_pos[2]), offset);
    if ( !offset )
    {
        printk(KERN_ERR "microcode: installing equivalent cpu table failed\n");
        return -EINVAL;
    }

    while ( (offset =
             get_next_ucode_from_buffer_amd(&mc, buf, size, offset)) > 0 )
    {
        error = get_matching_microcode(mc, cpu);
        if ( error < 0 )
            break;
        /*
         * It's possible the data file has multiple matching ucode,
         * lets keep searching till the latest version
         */
        if ( error == 1 )
        {
            apply_microcode(cpu);
            error = 0;
        }
        xfree(mc);
    }
    if ( offset > 0 )
    {
        xfree(mc);
        xfree(equiv_cpu_table);
        equiv_cpu_table = NULL;
    }
    if ( offset < 0 )
        error = offset;

    return error;
}

static void microcode_fini_cpu(int cpu)
{
    struct ucode_cpu_info *uci = ucode_cpu_info + cpu;

    xfree(uci->mc.mc_amd);
    uci->mc.mc_amd = NULL;
}

static struct microcode_ops microcode_amd_ops = {
    .get_matching_microcode           = get_matching_microcode,
    .microcode_sanity_check           = NULL,
    .cpu_request_microcode            = cpu_request_microcode,
    .collect_cpu_info                 = collect_cpu_info,
    .apply_microcode                  = apply_microcode,
    .microcode_fini_cpu               = microcode_fini_cpu,
};

static __init int microcode_init_amd(void)
{
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        microcode_ops = &microcode_amd_ops;
    return 0;
}
__initcall(microcode_init_amd);
