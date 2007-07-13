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
 * Copyright IBM Corp. 2005, 2007
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 *          Christian Ehrhardt <ehrhardt@linux.vnet.ibm.com>
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/domain.h>
#include <asm/current.h>

void save_pmc_sprs(perf_sprs_t *p_sprs)
{
    p_sprs->mmcr0 = mfmmcr0();
    p_sprs->mmcr1 = mfmmcr1();
    p_sprs->mmcra = mfmmcra();
    p_sprs->pmc[0] = mfpmc1();
    p_sprs->pmc[1] = mfpmc2();
    p_sprs->pmc[2] = mfpmc3();
    p_sprs->pmc[3] = mfpmc4();
    p_sprs->pmc[4] = mfpmc5();
    p_sprs->pmc[5] = mfpmc6();
    p_sprs->pmc[6] = mfpmc7();
    p_sprs->pmc[7] = mfpmc8();
}

void load_pmc_sprs(perf_sprs_t *p_sprs)
{
    mtpmc1(p_sprs->pmc[0]);
    mtpmc2(p_sprs->pmc[1]);
    mtpmc3(p_sprs->pmc[2]);
    mtpmc4(p_sprs->pmc[3]);
    mtpmc5(p_sprs->pmc[4]);
    mtpmc6(p_sprs->pmc[5]);
    mtpmc7(p_sprs->pmc[6]);
    mtpmc8(p_sprs->pmc[7]);
    mtmmcra(p_sprs->mmcra);
    mtmmcr1(p_sprs->mmcr1);
    mtmmcr0(p_sprs->mmcr0);
}

void save_sprs(struct vcpu *v)
{
    v->arch.timebase = mftb();

    v->arch.sprg[0] = mfsprg0();
    v->arch.sprg[1] = mfsprg1();
    v->arch.sprg[2] = mfsprg2();
    v->arch.sprg[3] = mfsprg3();

    v->arch.dar = mfdar();
    v->arch.dsisr = mfdsisr();

    if (v->arch.pmu_enabled) {
        save_pmc_sprs(&(v->arch.perf_sprs));
        v->arch.perf_sprs_stored = 1;
    }

    save_cpu_sprs(v);
}

void load_sprs(struct vcpu *v)
{
    ulong timebase_delta;

    mtsprg0(v->arch.sprg[0]);
    mtsprg1(v->arch.sprg[1]);
    mtsprg2(v->arch.sprg[2]);
    mtsprg3(v->arch.sprg[3]);
    mtdar(v->arch.dar);
    mtdsisr(v->arch.dsisr);

    if (v->arch.pmu_enabled) {
        if (v->arch.perf_sprs_stored)
            load_pmc_sprs(&(v->arch.perf_sprs));
        else
            load_pmc_sprs(&perf_clear_sprs);
    }

    load_cpu_sprs(v);

    /* adjust the DEC value to account for cycles while not
     * running this OS */
    timebase_delta = mftb() - v->arch.timebase;
    if (timebase_delta > v->arch.dec)
        v->arch.dec = 0;
    else
        v->arch.dec -= timebase_delta;
}

/* XXX evaluate all isyncs in segment code */

void flush_segments(void)
{
    struct slb_entry slb0;
    ulong zero = 0;

    __asm__ __volatile__(
        "slbmfev %0,%2\n"
        "slbmfee %1,%2\n"
        :"=&r"(slb0.slb_vsid), "=&r"(slb0.slb_esid)
        :"r"(zero)
        :"memory");

    /* we manually have to invalidate SLB[0] since slbia doesn't. */
    /* XXX name magic constants! */
    if (slb0.slb_esid & SLB_ESID_VALID) {
        ulong rb;
        ulong class;

        class = !!(slb0.slb_vsid & SLB_ESID_CLASS);
        rb = slb0.slb_esid & SLB_ESID_MASK;
        rb |= class << SLBIE_CLASS_LOG;

        slbie(rb);
    }
    slbia();
}

void save_segments(struct vcpu *v)
{
    struct slb_entry *slb_entry = v->arch.slb_entries;
    int i;

    /* save all extra SLBs */
    for (i = 0; i < NUM_SLB_ENTRIES; i++) {
        ulong vsid;
        ulong esid;

        __asm__ __volatile__(
                "slbmfev %0,%2\n"
                "slbmfee %1,%2\n"
                :"=&r"(vsid), "=&r"(esid)
                :"r"(i)
                :"memory");

        /* FIXME: should we bother to save invalid entries? */
        slb_entry[i].slb_vsid = vsid;
        slb_entry[i].slb_esid = esid;
#ifdef SLB_DEBUG
        if (vsid != 0) {
            printk("%s: DOM[0x%x]: S%02d: 0x%016lx 0x%016lx\n",
                    __func__, v->domain->domain_id, i, vsid, esid);
        }
#endif
    }

    flush_segments();
}

void load_segments(struct vcpu *v)
{
    struct slb_entry *slb_entry = v->arch.slb_entries;
    int i;

    /* restore all extra SLBs */
    for (i = 0; i < NUM_SLB_ENTRIES; i++) {
        ulong vsid = slb_entry[i].slb_vsid;
        ulong esid = slb_entry[i].slb_esid;

        /* FIXME: should we bother to restore invalid entries */
        /* stuff in the index here */
        esid &= ~SLBMTE_ENTRY_MASK;
        esid |= i;

        __asm__ __volatile__(
                "isync\n"
                "slbmte %0,%1\n"
                "isync\n"
                :
                :"r" (vsid), "r"(esid)
                :"memory");

#ifdef SLB_DEBUG
        if (vsid != 0) {
            printk("%s: DOM[0x%x]: R%02d: 0x%016lx 0x%016lx\n",
                    __func__, v->domain->domain_id, i, vsid, esid);
        }
#endif
    }
}

void dump_segments(int valid)
{
    int i;

    printk("Dump %s SLB entries:\n", valid ? "VALID" : "ALL");

    /* save all extra SLBs */
    for (i = 0; i < NUM_SLB_ENTRIES; i++) {
        ulong vsid;
        ulong esid;

        __asm__ __volatile__(
                "slbmfev %0,%2\n"
                "slbmfee %1,%2\n"
                :"=&r"(vsid), "=&r"(esid)
                :"r"(i)
                :"memory");

        if (valid && !(esid & SLB_ESID_VALID))
            continue;
        printk("S%02d: 0x%016lx 0x%016lx\n", i, vsid, esid);
    }
}
