/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * amd-cppc.c - AMD Processor CPPC Frequency Driver
 *
 * Copyright (C) 2025 Advanced Micro Devices, Inc. All Rights Reserved.
 *
 * Author: Penny Zheng <penny.zheng@amd.com>
 *
 * AMD CPPC cpufreq driver introduces a new CPU performance scaling design
 * for AMD processors using the ACPI Collaborative Performance and Power
 * Control (CPPC) feature which provides finer grained frequency control range.
 */

#include <xen/domain.h>
#include <xen/init.h>
#include <xen/param.h>
#include <acpi/cpufreq/cpufreq.h>

static bool __init amd_cppc_handle_option(const char *s, const char *end)
{
    int ret;

    ret = parse_boolean("verbose", s, end);
    if ( ret >= 0 )
    {
        cpufreq_verbose = ret;
        return true;
    }

    return false;
}

int __init amd_cppc_cmdline_parse(const char *s, const char *e)
{
    do {
        const char *end = strpbrk(s, ",;");

        if ( !amd_cppc_handle_option(s, end) )
        {
            printk(XENLOG_WARNING
                   "cpufreq/amd-cppc: option '%.*s' not recognized\n",
                   (int)((end ?: e) - s), s);

            return -EINVAL;
        }

        s = end ? end + 1 : NULL;
    } while ( s && s < e );

    return 0;
}

int __init amd_cppc_register_driver(void)
{
    if ( !cpu_has_cppc )
        return -ENODEV;

    return -EOPNOTSUPP;
}
