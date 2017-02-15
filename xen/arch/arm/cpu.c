/*
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

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>

#include <asm/processor.h>

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
