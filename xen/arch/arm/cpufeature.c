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
        c->midr.bits = READ_SYSREG32(MIDR_EL1);
        c->mpidr.bits = READ_SYSREG(MPIDR_EL1);

#ifdef CONFIG_ARM_64
        c->pfr64.bits[0] = READ_SYSREG64(ID_AA64PFR0_EL1);
        c->pfr64.bits[1] = READ_SYSREG64(ID_AA64PFR1_EL1);

        c->dbg64.bits[0] = READ_SYSREG64(ID_AA64DFR0_EL1);
        c->dbg64.bits[1] = READ_SYSREG64(ID_AA64DFR1_EL1);

        c->aux64.bits[0] = READ_SYSREG64(ID_AA64AFR0_EL1);
        c->aux64.bits[1] = READ_SYSREG64(ID_AA64AFR1_EL1);

        c->mm64.bits[0]  = READ_SYSREG64(ID_AA64MMFR0_EL1);
        c->mm64.bits[1]  = READ_SYSREG64(ID_AA64MMFR1_EL1);

        c->isa64.bits[0] = READ_SYSREG64(ID_AA64ISAR0_EL1);
        c->isa64.bits[1] = READ_SYSREG64(ID_AA64ISAR1_EL1);
#endif

        c->pfr32.bits[0] = READ_SYSREG32(ID_PFR0_EL1);
        c->pfr32.bits[1] = READ_SYSREG32(ID_PFR1_EL1);

        c->dbg32.bits[0] = READ_SYSREG32(ID_DFR0_EL1);

        c->aux32.bits[0] = READ_SYSREG32(ID_AFR0_EL1);

        c->mm32.bits[0]  = READ_SYSREG32(ID_MMFR0_EL1);
        c->mm32.bits[1]  = READ_SYSREG32(ID_MMFR1_EL1);
        c->mm32.bits[2]  = READ_SYSREG32(ID_MMFR2_EL1);
        c->mm32.bits[3]  = READ_SYSREG32(ID_MMFR3_EL1);

        c->isa32.bits[0] = READ_SYSREG32(ID_ISAR0_EL1);
        c->isa32.bits[1] = READ_SYSREG32(ID_ISAR1_EL1);
        c->isa32.bits[2] = READ_SYSREG32(ID_ISAR2_EL1);
        c->isa32.bits[3] = READ_SYSREG32(ID_ISAR3_EL1);
        c->isa32.bits[4] = READ_SYSREG32(ID_ISAR4_EL1);
        c->isa32.bits[5] = READ_SYSREG32(ID_ISAR5_EL1);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
