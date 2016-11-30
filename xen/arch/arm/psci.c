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
#include <asm/acpi.h>

/*
 * While a 64-bit OS can make calls with SMC32 calling conventions, for
 * some calls it is necessary to use SMC64 to pass or return 64-bit values.
 * For such calls PSCI_0_2_FN_NATIVE(x) will choose the appropriate
 * (native-width) function ID.
 */
#ifdef CONFIG_ARM_64
#define PSCI_0_2_FN_NATIVE(name)	PSCI_0_2_FN64_##name
#else
#define PSCI_0_2_FN_NATIVE(name)	PSCI_0_2_FN_##name
#endif

uint32_t psci_ver;

static uint32_t psci_cpu_on_nr;

int call_psci_cpu_on(int cpu)
{
    return call_smc(psci_cpu_on_nr, cpu_logical_map(cpu), __pa(init_secondary), 0);
}

void call_psci_system_off(void)
{
    if ( psci_ver > PSCI_VERSION(0, 1) )
        call_smc(PSCI_0_2_FN_SYSTEM_OFF, 0, 0, 0);
}

void call_psci_system_reset(void)
{
    if ( psci_ver > PSCI_VERSION(0, 1) )
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

    if ( !acpi_disabled )
    {
        printk("PSCI 0.1 is not supported when using ACPI\n");
        return -EINVAL;
    }

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

    psci_ver = PSCI_VERSION(0, 1);

    printk(XENLOG_INFO "Using PSCI-0.1 for SMP bringup\n");

    return 0;
}

int __init psci_init_0_2(void)
{
    static const struct dt_device_match psci_ids[] __initconst =
    {
        DT_MATCH_COMPATIBLE("arm,psci-0.2"),
        DT_MATCH_COMPATIBLE("arm,psci-1.0"),
        { /* sentinel */ },
    };
    int ret;

    if ( acpi_disabled )
    {
        const struct dt_device_node *psci;

        psci = dt_find_matching_node(NULL, psci_ids);
        if ( !psci )
            return -EOPNOTSUPP;

        ret = psci_is_smc_method(psci);
        if ( ret )
            return -EINVAL;
    }
    else
    {
        if ( acpi_psci_hvc_present() ) {
            printk("PSCI conduit must be SMC, but is HVC\n");
            return -EINVAL;
        }
    }

    psci_ver = call_smc(PSCI_0_2_FN_PSCI_VERSION, 0, 0, 0);

    /* For the moment, we only support PSCI 0.2 and PSCI 1.x */
    if ( psci_ver != PSCI_VERSION(0, 2) && PSCI_VERSION_MAJOR(psci_ver) != 1 )
    {
        printk("Error: Unrecognized PSCI version %u.%u\n",
               PSCI_VERSION_MAJOR(psci_ver), PSCI_VERSION_MINOR(psci_ver));
        return -EOPNOTSUPP;
    }

    psci_cpu_on_nr = PSCI_0_2_FN_NATIVE(CPU_ON);

    printk(XENLOG_INFO "Using PSCI-%u.%u for SMP bringup\n",
           PSCI_VERSION_MAJOR(psci_ver), PSCI_VERSION_MINOR(psci_ver));

    return 0;
}

int __init psci_init(void)
{
    int ret;

    if ( !acpi_disabled && !acpi_psci_present() )
        return -EOPNOTSUPP;

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
