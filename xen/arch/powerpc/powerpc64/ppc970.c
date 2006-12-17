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
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 *          Jimi Xenidis <jimix@watson.ibm.com>
 *          Amos Waterland  <apw@us.ibm.com>
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <asm/time.h>
#include <asm/current.h>
#include <asm/powerpc64/procarea.h>
#include <asm/powerpc64/processor.h>
#include <asm/powerpc64/ppc970-hid.h>
#include "scom.h"

#undef DEBUG
#undef SERIALIZE

struct cpu_caches cpu_caches = {
    .dline_size = 0x80,
    .log_dline_size = 7,
    .dlines_per_page = PAGE_SIZE >> 7,
    .isize = (64 << 10),        /* 64 KiB */
    .iline_size = 0x80,
    .log_iline_size = 7,
    .ilines_per_page = PAGE_SIZE >> 7,
};


void cpu_flush_icache(void)
{
    union hid1 hid1;
    ulong flags;
    ulong ea;

    local_irq_save(flags);

    /* uses special processor mode that forces a real address match on
     * the whole line */
    hid1.word = mfhid1();
    hid1.bits.en_icbi = 1;
    mthid1(hid1.word);

    for (ea = 0; ea < cpu_caches.isize; ea += cpu_caches.iline_size)
        icbi(ea);

    sync();

    hid1.bits.en_icbi = 0;
    mthid1(hid1.word);

    local_irq_restore(flags);
}


struct rma_settings {
    int log;
    int rmlr_0;
    int rmlr_1_2;
};

static struct rma_settings rma_logs[] = {
    { .log = 26, .rmlr_0 = 0, .rmlr_1_2 = 3, }, /*  64 MB */
    { .log = 27, .rmlr_0 = 1, .rmlr_1_2 = 3, }, /* 128 MB */
    { .log = 28, .rmlr_0 = 1, .rmlr_1_2 = 0, }, /* 256 MB */
    { .log = 30, .rmlr_0 = 0, .rmlr_1_2 = 2, }, /*   1 GB */
    { .log = 34, .rmlr_0 = 0, .rmlr_1_2 = 1, }, /*  16 GB */
    { .log = 38, .rmlr_0 = 0, .rmlr_1_2 = 0, }, /* 256 GB */
};

static uint log_large_page_sizes[] = {
    4 + 20, /* (1 << 4) == 16M */
};

static struct rma_settings *cpu_find_rma(unsigned int log)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(rma_logs); i++) {
        if (rma_logs[i].log == log)
            return &rma_logs[i];
    }
    return NULL;
}

unsigned int cpu_default_rma_order_pages(void)
{
    return rma_logs[0].log - PAGE_SHIFT;
}

int cpu_rma_valid(unsigned int order)
{
    return cpu_find_rma(order + PAGE_SHIFT) != NULL;
}

unsigned int cpu_large_page_orders(uint *sizes, uint max)
{
    uint i = 0;

    while (i < max && i < ARRAY_SIZE(log_large_page_sizes)) {
        sizes[i] = log_large_page_sizes[i] - PAGE_SHIFT;
        ++i;
    }

    return i;
}

unsigned int cpu_extent_order(void)
{
    return log_large_page_sizes[0] - PAGE_SHIFT;
}

/* This is more a platform thing than a CPU thing, but we only have
 * one platform now */
int cpu_io_mfn(ulong mfn)
{
    /* totally cheating */
    if (mfn >= (2UL << (30 - PAGE_SHIFT)) && /* 2GiB */
        mfn < (4UL << (30 - PAGE_SHIFT)))    /* 4GiB */
        return 1;

    return 0;
}

int cpu_threads(int cpuid)
{
    return 1;
}


static u64 cpu0_hids[6];
static u64 cpu0_hior;

void cpu_initialize(int cpuid)
{
    union hid0 hid0;
    union hid1 hid1;
    union hid4 hid4;
    union hid5 hid5;

    if (cpuid == 0) {
        /* we can assume that these are sane to start with.  We
         * _do_not_ store the results in case we want to mess with them
         * on a per-cpu basis later. */
        cpu0_hids[0] = mfhid0();
        cpu0_hids[1] = mfhid1();
        cpu0_hids[4] = mfhid4();
        cpu0_hids[5] = mfhid5();
        cpu0_hior = 0;
    }

    hid0.word = cpu0_hids[0];
    hid1.word = cpu0_hids[1];
    hid4.word = cpu0_hids[4];
    hid5.word = cpu0_hids[5];

    /* This is SMP safe because the compiler must use r13 for it.  */
    parea = global_cpu_table[cpuid];
    ASSERT(parea != NULL);

    mthsprg0((ulong)parea); /* now ready for exceptions */

    printk("CPU[PIR:%u IPI:%u Logical:%u] Hello World!\n",
           mfpir(), hard_smp_processor_id(), smp_processor_id());

#ifdef DEBUG
    {
        ulong r1, r2;

        asm volatile ("mr %0, 1" : "=r" (r1));
        asm volatile ("mr %0, 2" : "=r" (r2));
        printk("  SP = %lx TOC = %lx\n",  r1, r2);
    }
#endif

    /* Set decrementers for 1 second to keep them out of the way during
     * intialization. */
    /* XXX make tickless */
    mtdec(timebase_freq);
    mthdec(timebase_freq);

    /* FIXME Do not set the NAP bit in HID0 until we have had a chance
     * to audit the safe halt and idle loop code. */
    hid0.bits.nap = 0;      /* NAP */
    hid0.bits.dpm = 1;      /* Dynamic Power Management */

    hid0.bits.nhr = 1;      /* Not Hard Reset */
    hid0.bits.hdice_en = 1; /* enable HDEC */
    hid0.bits.en_therm = 0; /* ! Enable ext thermal ints */
    /* only debug Xen should activate ATTN */
    hid0.bits.en_attn = 1;  /* Enable attn instruction */
    hid0.bits.en_mck = 1;   /* Enable external machine check interrupts */

#ifdef SERIALIZE
    hid0.bits.one_ppc = 1;
    hid0.bits.isync_sc = 1;
    hid0.bits.inorder = 1;
    /* may not want these */
    hid0.bits.do_single = 1;
    hid0.bits.ser-gp = 1;
#endif

    mthid0(hid0.word);

    hid1.bits.bht_pm = 7; /* branch history table prediction mode */
    hid1.bits.en_ls = 1; /* enable link stack */

    hid1.bits.en_cc = 1; /* enable count cache */
    hid1.bits.en_ic = 1; /* enable inst cache */

    hid1.bits.pf_mode = 2; /* prefetch mode */

    hid1.bits.en_if_cach = 1; /* i-fetch cacheability control */
    hid1.bits.en_ic_rec = 1; /* i-cache parity error recovery */
    hid1.bits.en_id_rec = 1; /* i-dir parity error recovery */
    hid1.bits.en_er_rec = 1; /* i-ERAT parity error recovery */

    hid1.bits.en_sp_itw = 1; /* En speculative tablewalks */
    mthid1(hid1.word);

    /* no changes to hid4 but we want to make sure that secondaries
     * are sane */
    hid4.bits.lg_pg_dis = 0;    /* make sure we enable large pages */
    mthid4(hid4.word);

    hid5.bits.DC_mck = 1; /* Machine check enabled for dcache errors */
    hid5.bits.DCBZ_size = 0; /* make dcbz size 32 bytes */
    hid5.bits.DCBZ32_ill = 0; /* make dzbz 32byte illeagal */
    mthid5(hid5.word);

#ifdef DEBUG
    printk("hid0 0x%016lx\n"
           "hid1 0x%016lx\n"
           "hid4 0x%016lx\n"
           "hid5 0x%016lx\n",
           mfhid0(), mfhid1(), mfhid4(), mfhid5());
#endif

    /* Make sure firmware has not left this dirty */
    mthior(cpu0_hior);

    /* some machine check goodness */
    /* save this for checkstop processing */
    if (cpuid == 0)
        *mck_good_hid4 = hid4.word;

    if (mfpir() > NR_CPUS)
        panic("we do not expect a processor to have a PIR (%u) "
              "to be larger that NR_CPUS(%u)\n",
              mfpir(), NR_CPUS);

    cpu_scom_init();

    /* initialize the SLB */
#ifdef DEBUG
    dump_segments(1);
#endif
    flush_segments();
    local_flush_tlb();
}

void cpu_init_vcpu(struct vcpu *v)
{
    struct domain *d = v->domain;
    union hid4 hid4;
    struct rma_settings *rma_settings;

    hid4.word = mfhid4();

    hid4.bits.lpes_0 = 0; /* external exceptions set MSR_HV=1 */
    hid4.bits.lpes_1 = 1; /* RMA applies */

    hid4.bits.rmor_0_15 = page_to_maddr(d->arch.rma_page) >> 26;

    hid4.bits.lpid_0_1 = d->domain_id & 3;
    hid4.bits.lpid_2_5 = (d->domain_id >> 2) & 0xf;

    rma_settings = cpu_find_rma(d->arch.rma_order + PAGE_SHIFT);
    ASSERT(rma_settings != NULL);
    hid4.bits.rmlr_0 = rma_settings->rmlr_0;
    hid4.bits.rmlr_1_2 = rma_settings->rmlr_1_2;

    v->arch.cpu.hid4.word = hid4.word;
}

void save_cpu_sprs(struct vcpu *v)
{
    /* HID4 is initialized with a per-domain value at domain creation time, and
     * does not change after that. */
}

void load_cpu_sprs(struct vcpu *v)
{
    mthid4(v->arch.cpu.hid4.word);
}
