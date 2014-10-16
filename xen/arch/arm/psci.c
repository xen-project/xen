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

uint32_t psci_ver;

static uint32_t psci_cpu_on_nr;

int call_psci_cpu_on(int cpu)
{
    return call_smc(psci_cpu_on_nr, cpu_logical_map(cpu), __pa(init_secondary), 0);
}

void call_psci_system_off(void)
{
    if ( psci_ver > XEN_PSCI_V_0_1 )
        call_smc(PSCI_0_2_FN_SYSTEM_OFF, 0, 0, 0);
}

void call_psci_system_reset(void)
{
    if ( psci_ver > XEN_PSCI_V_0_1 )
        call_smc(PSCI_0_2_FN_SYSTEM_RESET, 0, 0, 0);
}

int __init psci_is_smc_method(const struct dt_device_node *psci)
{
    int ret;
    const char *prop_str;

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

    return 0;
}

int __init psci_init_0_1(void)
{
    int ret;
    const struct dt_device_node *psci;

    psci = dt_find_compatible_node(NULL, NULL, "arm,psci");
    if ( !psci )
        return -EOPNOTSUPP;

    ret = psci_is_smc_method(psci);
    if ( ret )
        return -EINVAL;

    if ( !dt_property_read_u32(psci, "cpu_on", &psci_cpu_on_nr) )
    {
        printk("/psci node is missing the \"cpu_on\" property\n");
        return -ENOENT;
    }

    psci_ver = XEN_PSCI_V_0_1;

    printk(XENLOG_INFO "Using PSCI-0.1 for SMP bringup\n");

    return 0;
}

int __init psci_init_0_2(void)
{
    int ret;
    const struct dt_device_node *psci;

    psci = dt_find_compatible_node(NULL, NULL, "arm,psci-0.2");
    if ( !psci )
	return -EOPNOTSUPP;

    ret = psci_is_smc_method(psci);
    if ( ret )
        return -EINVAL;

    psci_ver = call_smc(PSCI_0_2_FN_PSCI_VERSION, 0, 0, 0);

    if ( psci_ver != XEN_PSCI_V_0_2 )
    {
        printk("Error: PSCI version %#x is not supported.\n", psci_ver);
        return -EOPNOTSUPP;
    }

    psci_cpu_on_nr = PSCI_0_2_FN_CPU_ON;

    printk(XENLOG_INFO "Using PSCI-0.2 for SMP bringup\n");

    return 0;
}

int __init psci_init(void)
{
    int ret;

    ret = psci_init_0_2();
    if ( ret )
        ret = psci_init_0_1();

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
