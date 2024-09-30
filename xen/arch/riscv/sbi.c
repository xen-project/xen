/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Taken and modified from the xvisor project with the copyright Copyright (c)
 * 2019 Western Digital Corporation or its affiliates and author Anup Patel
 * (anup.patel@wdc.com).
 *
 * Modified by Bobby Eshleman (bobby.eshleman@gmail.com).
 * Modified by Oleksii Kurochko (oleksii.kurochko@gmail.com).
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 * Copyright (c) 2021-2024 Vates SAS.
 */

#include <xen/compiler.h>
#include <xen/const.h>
#include <xen/cpumask.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sections.h>
#include <xen/smp.h>

#include <asm/processor.h>
#include <asm/sbi.h>

static unsigned long __ro_after_init sbi_spec_version = SBI_SPEC_VERSION_DEFAULT;

struct sbiret sbi_ecall(unsigned long ext, unsigned long fid,
                        unsigned long arg0, unsigned long arg1,
                        unsigned long arg2, unsigned long arg3,
                        unsigned long arg4, unsigned long arg5)
{
    struct sbiret ret;

    register unsigned long a0 asm ("a0") = arg0;
    register unsigned long a1 asm ("a1") = arg1;
    register unsigned long a2 asm ("a2") = arg2;
    register unsigned long a3 asm ("a3") = arg3;
    register unsigned long a4 asm ("a4") = arg4;
    register unsigned long a5 asm ("a5") = arg5;
    register unsigned long a6 asm ("a6") = fid;
    register unsigned long a7 asm ("a7") = ext;

    asm volatile (  "ecall"
                    : "+r" (a0), "+r" (a1)
                    : "r" (a2), "r" (a3), "r" (a4), "r" (a5), "r" (a6), "r" (a7)
                    : "memory");
    ret.error = a0;
    ret.value = a1;

    return ret;
}

static int sbi_err_map_xen_errno(int err)
{
    switch ( err )
    {
    case SBI_SUCCESS:
        return 0;
    case SBI_ERR_DENIED:
        return -EACCES;
    case SBI_ERR_INVALID_PARAM:
        return -EINVAL;
    case SBI_ERR_INVALID_ADDRESS:
        return -EFAULT;
    case SBI_ERR_NOT_SUPPORTED:
        return -EOPNOTSUPP;
    case SBI_ERR_FAILURE:
    default:
        return -ENOSYS;
    };
}

void sbi_console_putchar(int ch)
{
    sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, ch, 0, 0, 0, 0, 0);
}

void sbi_shutdown(void)
{
    sbi_ecall(SBI_EXT_0_1_SHUTDOWN, 0, 0, 0, 0, 0, 0, 0);
}

static unsigned int sbi_major_version(void)
{
    return MASK_EXTR(sbi_spec_version, SBI_SPEC_VERSION_MAJOR_MASK);
}

static unsigned int sbi_minor_version(void)
{
    return MASK_EXTR(sbi_spec_version, SBI_SPEC_VERSION_MINOR_MASK);
}

static long sbi_ext_base_func(long fid)
{
    struct sbiret ret;

    ret = sbi_ecall(SBI_EXT_BASE, fid, 0, 0, 0, 0, 0, 0);

    if ( !ret.error )
    {
        /*
         * I wasn't able to find a case in the SBI spec where sbiret.value
         * could be negative.
         *
         * Unfortunately, the spec does not specify the possible values of
         * sbiret.value, but based on the description of the SBI function,
         * ret.value >= 0 when sbiret.error = 0. SPI spec specify only
         * possible value for sbiret.error (<= 0 whwere 0 is SBI_SUCCESS ).
         *
         * Just to be sure that SBI base extension functions one day won't
         * start to return a negative value for sbiret.value when
         * sbiret.error < 0 BUG_ON() is added.
         */
        BUG_ON(ret.value < 0);

        return ret.value;
    }
    else
        return ret.error;
}

static int sbi_rfence_v02_real(unsigned long fid,
                               unsigned long hmask, unsigned long hbase,
                               vaddr_t start, size_t size,
                               unsigned long arg4)
{
    struct sbiret ret = {0};
    int result = 0;

    switch ( fid )
    {
    case SBI_EXT_RFENCE_REMOTE_FENCE_I:
        ret = sbi_ecall(SBI_EXT_RFENCE, fid, hmask, hbase,
                        0, 0, 0, 0);
        break;

    case SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA:
    case SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA:
    case SBI_EXT_RFENCE_REMOTE_SFENCE_VMA:
        ret = sbi_ecall(SBI_EXT_RFENCE, fid, hmask, hbase,
                        start, size, 0, 0);
        break;

    case SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID:
    case SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA_VMID:
    case SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA_ASID:
        ret = sbi_ecall(SBI_EXT_RFENCE, fid, hmask, hbase,
                        start, size, arg4, 0);
        break;

    default:
        printk("%s: unknown function ID [%#lx]\n",
               __func__, fid);
        result = -EINVAL;
        break;
    };

    if ( ret.error )
    {
        result = sbi_err_map_xen_errno(ret.error);
        printk("%s: hbase=%lu hmask=%#lx failed (error %ld)\n",
               __func__, hbase, hmask, ret.error);
    }

    return result;
}

static int cf_check sbi_rfence_v02(unsigned long fid,
                                   const cpumask_t *cpu_mask,
                                   vaddr_t start, size_t size,
                                   unsigned long arg4, unsigned long arg5)
{
    unsigned long hartid, cpuid, hmask = 0, hbase = 0, htop = 0;
    int result = -EINVAL;

    /*
     * hart_mask_base can be set to -1 to indicate that hart_mask can be
     * ignored and all available harts must be considered.
     */
    if ( !cpu_mask )
        return sbi_rfence_v02_real(fid, 0UL, -1UL, start, size, arg4);

    for_each_cpu ( cpuid, cpu_mask )
    {
        /*
         * Hart IDs might not necessarily be numbered contiguously in
         * a multiprocessor system.
         *
         * This means that it is possible for the hart ID mapping to look like:
         *  0, 1, 3, 65, 66, 69
         * In such cases, more than one call to sbi_rfence_v02_real() will be
         * needed, as a single hmask can only cover sizeof(unsigned long) CPUs:
         *  1. sbi_rfence_v02_real(hmask=0b1011, hbase=0)
         *  2. sbi_rfence_v02_real(hmask=0b1011, hbase=65)
         *
         * The algorithm below tries to batch as many harts as possible before
         * making an SBI call. However, batching may not always be possible.
         * For example, consider the hart ID mapping:
         *   0, 64, 1, 65, 2, 66 (1)
         *
         * Generally, batching is also possible for (1):
         *    First (0,1,2), then (64,65,66).
         * It just requires a different approach and updates to the current
         * algorithm.
         */
        hartid = cpuid_to_hartid(cpuid);
        if ( hmask )
        {
            if ( hartid + BITS_PER_LONG <= htop ||
                 hbase + BITS_PER_LONG <= hartid )
            {
                result = sbi_rfence_v02_real(fid, hmask, hbase,
                                             start, size, arg4);
                hmask = 0;
                if ( result )
                    break;
            }
            else if ( hartid < hbase )
            {
                /* shift the mask to fit lower hartid */
                hmask <<= hbase - hartid;
                hbase = hartid;
            }
        }

        if ( !hmask )
        {
            hbase = hartid;
            htop = hartid;
        }
        else if ( hartid > htop )
            htop = hartid;

        hmask |= BIT(hartid - hbase, UL);
    }

    if ( hmask )
        result = sbi_rfence_v02_real(fid, hmask, hbase,
                                     start, size, arg4);

    return result;
}

static int (* __ro_after_init sbi_rfence)(unsigned long fid,
                                          const cpumask_t *cpu_mask,
                                          vaddr_t start,
                                          size_t size,
                                          unsigned long arg4,
                                          unsigned long arg5);

int sbi_remote_sfence_vma(const cpumask_t *cpu_mask, vaddr_t start,
                          size_t size)
{
    ASSERT(sbi_rfence);

    return sbi_rfence(SBI_EXT_RFENCE_REMOTE_SFENCE_VMA,
                      cpu_mask, start, size, 0, 0);
}

/* This function must always succeed. */
#define sbi_get_spec_version()  \
    sbi_ext_base_func(SBI_EXT_BASE_GET_SPEC_VERSION)

#define sbi_get_firmware_id()   \
    sbi_ext_base_func(SBI_EXT_BASE_GET_IMP_ID)

#define sbi_get_firmware_version()  \
    sbi_ext_base_func(SBI_EXT_BASE_GET_IMP_VERSION)

int sbi_probe_extension(long extid)
{
    struct sbiret ret;

    ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, extid,
                    0, 0, 0, 0, 0);
    if ( !ret.error && ret.value )
        return ret.value;

    return sbi_err_map_xen_errno(ret.error);
}

static bool sbi_spec_is_0_1(void)
{
    return (sbi_spec_version == SBI_SPEC_VERSION_DEFAULT);
}

bool sbi_has_rfence(void)
{
    return (sbi_rfence != NULL);
}

int __init sbi_init(void)
{
    sbi_spec_version = sbi_get_spec_version();

    printk("SBI specification v%u.%u detected\n",
            sbi_major_version(), sbi_minor_version());

    if ( !sbi_spec_is_0_1() )
    {
        long sbi_fw_id = sbi_get_firmware_id();
        long sbi_fw_version = sbi_get_firmware_version();

        BUG_ON((sbi_fw_id < 0) || (sbi_fw_version < 0));

        printk("SBI implementation ID=%#lx Version=%#lx\n",
            sbi_fw_id, sbi_fw_version);

        if ( sbi_probe_extension(SBI_EXT_RFENCE) > 0 )
        {
            sbi_rfence = sbi_rfence_v02;
            printk("SBI v0.2 RFENCE extension detected\n");
        }
    }
    else
        panic("Ooops. SBI spec version 0.1 detected. Need to add support");

    return 0;
}
