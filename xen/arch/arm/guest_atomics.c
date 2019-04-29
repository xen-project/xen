/*
 * arch/arm/guest_atomics.c
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */
#include <xen/cpu.h>

#include <asm/guest_atomics.h>

DEFINE_PER_CPU_READ_MOSTLY(unsigned int, guest_safe_atomic_max);

/*
 * Heuristic to find a safe upper-limit for load-store exclusive
 * operations on memory shared with guest.
 *
 * At the moment, we calculate the number of iterations of a simple
 * load-store atomic loop in 1uS.
 */
static void calibrate_safe_atomic(void)
{
    s_time_t deadline = NOW() + MICROSECS(1);
    unsigned int counter = 0;
    unsigned long mem = 0;

    do
    {
        unsigned long res, tmp;

#ifdef CONFIG_ARM_32
        asm volatile (" ldrex   %2, %1\n"
                      " add     %2, %2, #1\n"
                      " strex   %0, %2, %1\n"
                      : "=&r" (res), "+Q" (mem), "=&r" (tmp));
#else
        asm volatile (" ldxr    %w2, %1\n"
                      " add     %w2, %w2, #1\n"
                      " stxr    %w0, %w2, %1\n"
                      : "=&r" (res), "+Q" (mem), "=&r" (tmp));
#endif
        counter++;
    } while (NOW() < deadline);

    this_cpu(guest_safe_atomic_max) = counter;

    printk(XENLOG_DEBUG
           "CPU%u: Guest atomics will try %u times before pausing the domain\n",
           smp_processor_id(), counter);
}

static int cpu_guest_safe_atomic_callback(struct notifier_block *nfb,
                                          unsigned long action,
                                          void *hcpu)
{
    if ( action == CPU_STARTING )
        calibrate_safe_atomic();

    return NOTIFY_DONE;
}

static struct notifier_block cpu_guest_safe_atomic_nfb = {
    .notifier_call = cpu_guest_safe_atomic_callback,
};

static int __init guest_safe_atomic_init(void)
{
    register_cpu_notifier(&cpu_guest_safe_atomic_nfb);

    calibrate_safe_atomic();

    return 0;
}
presmp_initcall(guest_safe_atomic_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
