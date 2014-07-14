/*
 * xen/arch/arm/psci.c
 *
 * PSCI host support
 *
 * Andre Przywara <andre.przywara@linaro.org>
 * Copyright (c) 2013 Linaro Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */


#include <xen/types.h>
#include <xen/mm.h>
#include <xen/smp.h>
#include <asm/psci.h>

bool_t psci_available;

#ifdef CONFIG_ARM_32
#define REG_PREFIX "r"
#else
#define REG_PREFIX "x"
#endif

static noinline int __invoke_psci_fn_smc(register_t function_id,
                                         register_t arg0,
                                         register_t arg1,
                                         register_t arg2)
{
    asm volatile(
        __asmeq("%0", REG_PREFIX"0")
        __asmeq("%1", REG_PREFIX"1")
        __asmeq("%2", REG_PREFIX"2")
        __asmeq("%3", REG_PREFIX"3")
        "smc #0"
        : "+r" (function_id)
        : "r" (arg0), "r" (arg1), "r" (arg2));

    return function_id;
}

#undef REG_PREFIX

static uint32_t psci_cpu_on_nr;

int call_psci_cpu_on(int cpu)
{
    return __invoke_psci_fn_smc(psci_cpu_on_nr,
                                cpu_logical_map(cpu), __pa(init_secondary), 0);
}

int __init psci_init(void)
{
    const struct dt_device_node *psci;
    int ret;
    const char *prop_str;

    psci = dt_find_compatible_node(NULL, NULL, "arm,psci");
    if ( !psci )
        return -ENODEV;

    ret = dt_property_read_string(psci, "method", &prop_str);
    if ( ret )
    {
        printk("/psci node does not provide a method (%d)\n", ret);
        return -EINVAL;
    }

    /* Since Xen runs in HYP all of the time, it does not make sense to
     * let it call into HYP for PSCI handling, since the handler just
     * won't be there. So bail out with an error if "smc" is not used.
     */
    if ( strcmp(prop_str, "smc") )
    {
        printk("/psci method must be smc, but is: \"%s\"\n", prop_str);
        return -EINVAL;
    }

    if ( !dt_property_read_u32(psci, "cpu_on", &psci_cpu_on_nr) )
    {
        printk("/psci node is missing the \"cpu_on\" property\n");
        return -ENOENT;
    }

    psci_available = 1;

    printk(XENLOG_INFO "Using PSCI for SMP bringup\n");

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
