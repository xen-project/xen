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
 * Copyright IBM Corp. 2007
 *
 * Authors: Christian Ehrhardt <ehrhardt@linux.vnet.ibm.com>
 */
#undef DEBUG

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/init.h>
#include <xen/domain.h>
#include <public/xen.h>
#include <asm/current.h>
#include <asm/msr.h>
#include <asm/papr.h>
#include <asm/hcalls.h>
#include <asm/xenoprof.h>

#define H_PERFMON_ENABLE (1UL << 63)
#define H_PERFMON_THRESHOLDGRANULARITY (1UL << 62)

#ifdef DEBUG
#define DBG(fmt...) printk(fmt)
#else
#define DBG(fmt...)
#endif

/* FIXME workaround - these are just the default values, need the values set to
 * linux via sysfs up-to-date. */
int pmc_reset_val[NUM_PMCS] = { (0x8000000-0x0),
                                (0x8000000-0x100000),
                                (0x8000000-0x0),
                                (0x8000000-0x0),
                                (0x8000000-0x0),
                                (0x8000000-0x0),
                                (0x8000000-0x0),
                                (0x8000000-0x0)};
int perf_count_active_vcpu;
perf_sprs_t perf_clear_sprs;
static DEFINE_SPINLOCK(perf_pmu_lock);

static inline int has_pmu(void) { return 1; }

void do_perfmon(struct cpu_user_regs *regs)
{
    ulong mmcra = mfmmcra();
    ulong mmcr0 = mfmmcr0();
    int pmc,i;
    
    if ((mmcra & MMCRA_SAMPHV) && !(mmcra & MMCRA_SAMPPR)) {
        /* TODO Hypervisor sample - support to sample xen, 
         * pass the sample to the primary sampling domain via an event channel.
         */
        printk("do_perfmon - called with sample of xen space\n");
        print_perf_status();
        BUG();
    } 

    /* Dom sample postponed into xen space
     * Currently just ignored (decreases accuracy) 
     * TODO pass the Dom samples to the appropriate domain via an event channel
     * TODO get access to the real pmc_reset_val currently used by the domain
     * to reset counter safe and valid
     */

    for (i = 0; i < NUM_PMCS; ++i) {
        pmc = ctr_read(i);
        if (pmc < 0) {
            DBG("postponed perfmon exception - PMC%d < 0 - reset to default "
                "'0x%0x'\n", i, pmc_reset_val[i]);
            ctr_write(i,pmc_reset_val[i]);
        }
    }

    mmcr0 |= MMCR0_PMAE;
    mmcr0 &= ~MMCR0_FC;
    mtmmcr0(mmcr0);
}

static void h_perfmon(struct cpu_user_regs *regs)
{
    ulong mode_set   = regs->gprs[4];
    ulong mode_reset = regs->gprs[5];
    struct vcpu *v = get_current();
    struct domain *d = v->domain;

    if (!has_pmu()) {
        regs->gprs[3] = H_Function;
        return;
    }

    /* only bits 0&1 are supported by H_PERFMON */
    if (((mode_set | mode_reset) & ~(H_PERFMON_ENABLE |
            H_PERFMON_THRESHOLDGRANULARITY)) != 0) {
        regs->gprs[3] = H_Parameter;
        return;
    }
    /* enable or disable it, not both */
    if ((mode_set & mode_reset) != 0) {
        regs->gprs[3] = H_Resource;
        return;
    }

    spin_lock(&perf_pmu_lock);
    if (mode_set & H_PERFMON_ENABLE) {
        if (v->arch.pmu_enabled) {
            DBG("H_PERFMON call on already enabled PMU for domain '%d' on "
                "vcpu '%d'\n", d->domain_id, v->vcpu_id);
            goto success;
        }

        if (!perf_count_active_vcpu) {
           save_pmc_sprs(&perf_clear_sprs);
#ifdef DEBUG
           DBG("H_PERFMON Saved initial clear performance special purpose "
               "registers\n");
           print_perf_status();
#endif
        }
        v->arch.pmu_enabled = 1;
        perf_count_active_vcpu++;
        printk("H_PERFMON call enabled PMU for domain '%d' on vcpu '%d'\n",
                d->domain_id, v->vcpu_id);
    } else if (mode_reset & H_PERFMON_ENABLE) {
        if (!v->arch.pmu_enabled) {
            DBG("H_PERFMON call on already disabled PMU for domain '%d' on "
                "vcpu '%d'\n", d->domain_id, v->vcpu_id);
            goto success;
        }
        v->arch.pmu_enabled = 0;
        perf_count_active_vcpu--;
        printk("H_PERFMON call disabled PMU for domain '%d' on vcpu '%d'\n",
                d->domain_id, v->vcpu_id);
    } else {
        regs->gprs[3] = H_Parameter;
    }

success:
    regs->gprs[3] = H_Success;
    spin_unlock(&perf_pmu_lock);
}

__init_papr_hcall(H_PERFMON, h_perfmon);
