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
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
