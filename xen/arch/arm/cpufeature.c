/*
 * Contains CPU feature definitions
 *
 * Copyright (C) 2015 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/types.h>
#include <xen/init.h>
#include <xen/smp.h>
#include <xen/stop_machine.h>
#include <asm/cpufeature.h>

DECLARE_BITMAP(cpu_hwcaps, ARM_NCAPS);

struct cpuinfo_arm __read_mostly guest_cpuinfo;

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

    c->zfr64.bits[0] = READ_SYSREG(ID_AA64ZFR0_EL1);

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
 * all cpu features that should not be published to guest.
 * The created structure is then used to provide ID registers values to guests.
 */
static int __init create_guest_cpuinfo(void)
{
    /*
     * TODO: The code is currently using only the features detected on the boot
     * core. In the long term we should try to compute values containing only
     * features supported by all cores.
     */
    guest_cpuinfo = boot_cpu_data;

#ifdef CONFIG_ARM_64
    /* Hide MPAM support as xen does not support it */
    guest_cpuinfo.pfr64.mpam = 0;
    guest_cpuinfo.pfr64.mpam_frac = 0;

    /* Hide SVE as Xen does not support it */
    guest_cpuinfo.pfr64.sve = 0;
    guest_cpuinfo.zfr64.bits[0] = 0;

    /* Hide MTE support as Xen does not support it */
    guest_cpuinfo.pfr64.mte = 0;

    /* Hide PAC support as Xen does not support it */
    guest_cpuinfo.isa64.apa = 0;
    guest_cpuinfo.isa64.api = 0;
    guest_cpuinfo.isa64.gpa = 0;
    guest_cpuinfo.isa64.gpi = 0;
#endif

    /* Hide AMU support */
#ifdef CONFIG_ARM_64
    guest_cpuinfo.pfr64.amu = 0;
#endif
    guest_cpuinfo.pfr32.amu = 0;

    /* Hide RAS support as Xen does not support it */
#ifdef CONFIG_ARM_64
    guest_cpuinfo.pfr64.ras = 0;
    guest_cpuinfo.pfr64.ras_frac = 0;
#endif
    guest_cpuinfo.pfr32.ras = 0;
    guest_cpuinfo.pfr32.ras_frac = 0;

    return 0;
}
/*
 * This function needs to be run after all smp are started to have
 * cpuinfo structures for all cores.
 */
__initcall(create_guest_cpuinfo);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
