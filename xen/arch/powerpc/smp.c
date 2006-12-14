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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005,2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 * Authors: Amos Waterland <apw@us.ibm.com>
 */

#include <xen/cpumask.h>
#include <xen/smp.h>
#include <asm/flushtlb.h>
#include <asm/debugger.h>
#include <asm/mpic.h>
#include <asm/mach-default/irq_vectors.h>

int smp_num_siblings = 1;
int smp_num_cpus = 1;
int ht_per_core = 1;

void __flush_tlb_mask(cpumask_t mask, unsigned long addr)
{
    if (cpu_isset(smp_processor_id(), mask)) {
        cpu_clear(smp_processor_id(), mask);
        if (cpus_empty(mask)) {
            /* only local */
            if (addr == FLUSH_ALL_ADDRS)
                local_flush_tlb();
            else
                local_flush_tlb_one(addr);
            return;
        }
    }
    /* if we are still here and the mask is non-empty, then we need to
     * flush other TLBs so we flush em all */
    if (!cpus_empty(mask))
        unimplemented();
}

void smp_send_event_check_mask(cpumask_t mask)
{
    cpu_clear(smp_processor_id(), mask);
    if (!cpus_empty(mask))
        send_IPI_mask(mask, EVENT_CHECK_VECTOR);
}


int smp_call_function(void (*func) (void *info), void *info, int retry,
                      int wait)
{
    cpumask_t allbutself = cpu_online_map;
    cpu_clear(smp_processor_id(), allbutself);

    return on_selected_cpus(allbutself, func, info, retry, wait);
}

void smp_send_stop(void)
{
    BUG();
}

struct call_data_struct {
    void (*func) (void *info);
    void *info;
    int wait;
    atomic_t started;
    atomic_t finished;
    cpumask_t selected;
};

static DEFINE_SPINLOCK(call_lock);
static struct call_data_struct call_data;

int on_selected_cpus(
    cpumask_t selected,
    void (*func) (void *info),
    void *info,
    int retry,
    int wait)
{
    int retval = 0, nr_cpus = cpus_weight(selected);
    unsigned long start, stall = SECONDS(1);

    spin_lock(&call_lock);

    call_data.func = func;
    call_data.info = info;
    call_data.wait = wait;
    atomic_set(&call_data.started, 0);
    atomic_set(&call_data.finished, 0);
    mb();

    send_IPI_mask(selected, CALL_FUNCTION_VECTOR);

    /* We always wait for an initiation ACK from remote CPU.  */
    for (start = NOW(); atomic_read(&call_data.started) != nr_cpus; ) {
        if (NOW() > start + stall) {
            printk("IPI start stall: %d ACKS to %d SYNS\n", 
                   atomic_read(&call_data.started), nr_cpus);
            start = NOW();
        }
    }

    /* If told to, we wait for a completion ACK from remote CPU.  */
    if (wait) {
        for (start = NOW(); atomic_read(&call_data.finished) != nr_cpus; ) {
            if (NOW() > start + stall) {
                printk("IPI finish stall: %d ACKS to %d SYNS\n", 
                       atomic_read(&call_data.finished), nr_cpus);
                start = NOW();
            }
        }
    }

    spin_unlock(&call_lock);

    return retval;
}

void smp_call_function_interrupt(struct cpu_user_regs *regs)
{

    void (*func)(void *info) = call_data.func;
    void *info = call_data.info;
    int wait = call_data.wait;

    atomic_inc(&call_data.started);
    mb();
    (*func)(info);
    mb();

    if (wait)
        atomic_inc(&call_data.finished);

    return;
}

void smp_event_check_interrupt(void)
{
    /* We are knocked out of NAP state at least.  */
    return;
}

void smp_message_recv(int msg, struct cpu_user_regs *regs)
{
    switch(msg) {
    case CALL_FUNCTION_VECTOR:
        smp_call_function_interrupt(regs);
        break;
    case EVENT_CHECK_VECTOR:
        smp_event_check_interrupt();
        break;
    default:
        BUG();
        break;
    }
}

#ifdef DEBUG_IPI
static void debug_ipi_ack(void *info)
{
    if (info) {
        unsigned long start, stall = SECONDS(5);
        for (start = NOW(); NOW() < start + stall; );
        printk("IPI recv on cpu #%d: %s\n", smp_processor_id(), (char *)info);
    }
    return;
}

void ipi_torture_test(void)
{
    int cpu;
    unsigned long before, after, delta;
    unsigned long min = ~0, max = 0, mean = 0, sum = 0, trials = 0;
    cpumask_t mask;

    cpus_clear(mask);

    while (trials < 1000000) {
        for_each_online_cpu(cpu) {
            cpu_set(cpu, mask);
            before = mftb();
            on_selected_cpus(mask, debug_ipi_ack, NULL, 1, 1);
            after = mftb();
            cpus_clear(mask);

            delta = after - before;
            if (delta > max) max = delta;
            if (delta < min) min = delta;
            sum += delta;
            trials++;
        }
    }

    mean = tb_to_ns(sum / trials);

    printk("IPI latency: min = %ld ticks, max = %ld ticks, mean = %ldns\n",
           min, max, mean);

    smp_call_function(debug_ipi_ack, "Hi", 0, 1);
}
#endif
