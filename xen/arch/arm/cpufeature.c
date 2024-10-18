/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Contains CPU feature definitions
 *
 * Copyright (C) 2015 ARM Ltd.
 */

#include <xen/bug.h>
#include <xen/types.h>
#include <xen/init.h>
#include <xen/smp.h>
#include <xen/stop_machine.h>
#include <asm/arm64/sve.h>
#include <asm/cpufeature.h>

DECLARE_BITMAP(cpu_hwcaps, ARM_NCAPS);

struct cpuinfo_arm __read_mostly domain_cpuinfo;

#ifdef CONFIG_ARM_64
static bool has_sb_instruction(const struct arm_cpu_capabilities *entry)
{
    return system_cpuinfo.isa64.sb;
}
#endif

static const struct arm_cpu_capabilities arm_features[] = {
#ifdef CONFIG_ARM_64
    {
        .desc = "Speculation barrier instruction (SB)",
        .capability = ARM_HAS_SB,
        .matches = has_sb_instruction,
    },
#endif
    {},
};

void update_cpu_capabilities(const struct arm_cpu_capabilities *caps,
                             const char *info)
{
    int i;

    for ( i = 0; caps[i].matches; i++ )
    {
        if ( !caps[i].matches(&caps[i]) )
            continue;

        if ( !cpus_have_cap(caps[i].capability) && caps[i].desc )
            printk(XENLOG_INFO "%s: %s\n", info, caps[i].desc);
        cpus_set_cap(caps[i].capability);
    }
}

/*
 * Run through the enabled capabilities and enable() it on all active
 * CPUs.
 */
void __init enable_cpu_capabilities(const struct arm_cpu_capabilities *caps)
{
    for ( ; caps->matches; caps++ )
    {
        if ( !cpus_have_cap(caps->capability) )
            continue;

        if ( caps->enable )
        {
            int ret;

            /*
             * Use stop_machine_run() as it schedules the work allowing
             * us to modify PSTATE, instead of on_each_cpu() which uses
             * an IPI, giving us a PSTATE that disappears when we
             * return.
             */
            ret = stop_machine_run(caps->enable, (void *)caps, NR_CPUS);
            /* stop_machine_run should never fail at this stage of the boot. */
            BUG_ON(ret);
        }
    }
}

void check_local_cpu_features(void)
{
    update_cpu_capabilities(arm_features, "enabled support for");
}

void __init enable_cpu_features(void)
{
    enable_cpu_capabilities(arm_features);
}

/*
 * Run through the enabled capabilities and enable() them on the calling CPU.
 * If enabling of any capability fails the error is returned. After enabling a
 * capability fails the error will be remembered into 'rc' and the remaining
 * capabilities will be enabled. If enabling multiple capabilities fail the
 * error returned by this function represents the error code of the last
 * failure.
 */
int enable_nonboot_cpu_caps(const struct arm_cpu_capabilities *caps)
{
    int rc = 0;

    for ( ; caps->matches; caps++ )
    {
        if ( !cpus_have_cap(caps->capability) )
            continue;

        if ( caps->enable )
        {
            int ret = caps->enable((void *)caps);

            if ( ret )
                rc = ret;
        }
    }

    return rc;
}

void identify_cpu(struct cpuinfo_arm *c)
{
    bool aarch32_el0 = true;

    c->midr.bits = READ_SYSREG(MIDR_EL1);
    c->mpidr.bits = READ_SYSREG(MPIDR_EL1);

#ifdef CONFIG_ARM_64
    c->pfr64.bits[0] = READ_SYSREG(ID_AA64PFR0_EL1);
    c->pfr64.bits[1] = READ_SYSREG(ID_AA64PFR1_EL1);

    c->dbg64.bits[0] = READ_SYSREG(ID_AA64DFR0_EL1);
    c->dbg64.bits[1] = READ_SYSREG(ID_AA64DFR1_EL1);

    c->aux64.bits[0] = READ_SYSREG(ID_AA64AFR0_EL1);
    c->aux64.bits[1] = READ_SYSREG(ID_AA64AFR1_EL1);

    c->mm64.bits[0]  = READ_SYSREG(ID_AA64MMFR0_EL1);
    c->mm64.bits[1]  = READ_SYSREG(ID_AA64MMFR1_EL1);
    c->mm64.bits[2]  = READ_SYSREG(ID_AA64MMFR2_EL1);

    c->isa64.bits[0] = READ_SYSREG(ID_AA64ISAR0_EL1);
    c->isa64.bits[1] = READ_SYSREG(ID_AA64ISAR1_EL1);
    c->isa64.bits[2] = READ_SYSREG(ID_AA64ISAR2_EL1);

    c->zfr64.bits[0] = READ_SYSREG(ID_AA64ZFR0_EL1);

    if ( cpu_has_sve )
        c->zcr64.bits[0] = compute_max_zcr();

    c->dczid.bits[0] = READ_SYSREG(DCZID_EL0);

    c->ctr.bits[0] = READ_SYSREG(CTR_EL0);

    aarch32_el0 = cpu_feature64_has_el0_32(c);
#endif

    if ( aarch32_el0 )
    {
        c->pfr32.bits[0] = READ_SYSREG(ID_PFR0_EL1);
        c->pfr32.bits[1] = READ_SYSREG(ID_PFR1_EL1);
        c->pfr32.bits[2] = READ_SYSREG(ID_PFR2_EL1);

        c->dbg32.bits[0] = READ_SYSREG(ID_DFR0_EL1);
        c->dbg32.bits[1] = READ_SYSREG(ID_DFR1_EL1);

        c->aux32.bits[0] = READ_SYSREG(ID_AFR0_EL1);

        c->mm32.bits[0]  = READ_SYSREG(ID_MMFR0_EL1);
        c->mm32.bits[1]  = READ_SYSREG(ID_MMFR1_EL1);
        c->mm32.bits[2]  = READ_SYSREG(ID_MMFR2_EL1);
        c->mm32.bits[3]  = READ_SYSREG(ID_MMFR3_EL1);
        c->mm32.bits[4]  = READ_SYSREG(ID_MMFR4_EL1);
        c->mm32.bits[5]  = READ_SYSREG(ID_MMFR5_EL1);

        c->isa32.bits[0] = READ_SYSREG(ID_ISAR0_EL1);
        c->isa32.bits[1] = READ_SYSREG(ID_ISAR1_EL1);
        c->isa32.bits[2] = READ_SYSREG(ID_ISAR2_EL1);
        c->isa32.bits[3] = READ_SYSREG(ID_ISAR3_EL1);
        c->isa32.bits[4] = READ_SYSREG(ID_ISAR4_EL1);
        c->isa32.bits[5] = READ_SYSREG(ID_ISAR5_EL1);
        c->isa32.bits[6] = READ_SYSREG(ID_ISAR6_EL1);

        c->mvfr.bits[0] = READ_SYSREG(MVFR0_EL1);
        c->mvfr.bits[1] = READ_SYSREG(MVFR1_EL1);
#ifndef MVFR2_MAYBE_UNDEFINED
        c->mvfr.bits[2] = READ_SYSREG(MVFR2_EL1);
#endif
    }
}

/*
 * This function is creating a cpuinfo structure with values modified to mask
 * all cpu features that should not be published to domains.
 * The created structure is then used to provide ID registers values to domains.
 */
static int __init create_domain_cpuinfo(void)
{
    /* Use the sanitized cpuinfo as initial domain cpuinfo */
    domain_cpuinfo = system_cpuinfo;

#ifdef CONFIG_ARM_64
    /* Hide MPAM support as xen does not support it */
    domain_cpuinfo.pfr64.mpam = 0;
    domain_cpuinfo.pfr64.mpam_frac = 0;

    /* Hide SVE by default */
    domain_cpuinfo.pfr64.sve = 0;
    domain_cpuinfo.zfr64.bits[0] = 0;

    /* Hide SMT support as Xen does not support it */
    domain_cpuinfo.pfr64.sme = 0;

    /* Hide MTE support as Xen does not support it */
    domain_cpuinfo.pfr64.mte = 0;

    /* Hide PAC support as Xen does not support it */
    domain_cpuinfo.isa64.apa = 0;
    domain_cpuinfo.isa64.api = 0;
    domain_cpuinfo.isa64.gpa = 0;
    domain_cpuinfo.isa64.gpi = 0;
#endif

    /* Hide AMU support */
#ifdef CONFIG_ARM_64
    domain_cpuinfo.pfr64.amu = 0;
#endif
    domain_cpuinfo.pfr32.amu = 0;

    /* Hide RAS support as Xen does not support it */
#ifdef CONFIG_ARM_64
    domain_cpuinfo.pfr64.ras = 0;
    domain_cpuinfo.pfr64.ras_frac = 0;
#endif
    domain_cpuinfo.pfr32.ras = 0;
    domain_cpuinfo.pfr32.ras_frac = 0;

    return 0;
}
/*
 * This function needs to be run after all smp are started to have
 * cpuinfo structures for all cores.
 */
__initcall(create_domain_cpuinfo);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
