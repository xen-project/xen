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
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/init.h>
#include <xen/ctype.h>
#include <xen/iocap.h>
#include <xen/shadow.h>
#include <xen/domain.h>
#include <xen/version.h>
#include <asm/processor.h>
#include <asm/papr.h>
#include <public/arch-powerpc.h>
#include <public/libelf.h>
#include "oftree.h"

/* opt_dom0_mem: memory allocated to domain 0. */
static unsigned int dom0_nrpages;
static void parse_dom0_mem(char *s)
{
    unsigned long long bytes;

    bytes = parse_size_and_unit(s, NULL);
    dom0_nrpages = bytes >> PAGE_SHIFT;
}
custom_param("dom0_mem", parse_dom0_mem);

static unsigned int opt_dom0_max_vcpus;
integer_param("dom0_max_vcpus", opt_dom0_max_vcpus);

static unsigned int opt_dom0_shadow;
boolean_param("dom0_shadow", opt_dom0_shadow);

/* adapted from common/elf.c */
#define RM_MASK(a,l) ((a) & ((1UL << (l)) - 1))

int construct_dom0(struct domain *d,
                   unsigned long image_start, unsigned long image_len, 
                   unsigned long initrd_start, unsigned long initrd_len,
                   char *cmdline)
{
    struct elf_binary elf;
    struct elf_dom_parms parms;
    int rc;
    struct vcpu *v = d->vcpu[0];
    ulong dst;
    u64 *ofh_tree;
    uint rma_nrpages = 1 << d->arch.rma_order;
    ulong rma_sz = rma_size(d->arch.rma_order);
    ulong rma = page_to_maddr(d->arch.rma_page);
    start_info_t *si;
    ulong eomem;
    int preempt = 0;
    int vcpu;

    /* Sanity! */
    BUG_ON(d->domain_id != 0);
    BUG_ON(d->vcpu[0] == NULL);

    if (image_len == 0)
        panic("No Dom0 image supplied\n");

    cpu_init_vcpu(v);

    printk("*** LOADING DOMAIN 0 ***\n");

    rc = elf_init(&elf, (void *)image_start, image_len);
    if (rc)
        return rc;
#ifdef VERBOSE
    elf_set_verbose(&elf);
#endif
    elf_parse_binary(&elf);
    if (0 != (elf_xen_parse(&elf, &parms)))
        return rc;

    printk("Dom0 kernel: %s, paddr 0x%" PRIx64 " -> 0x%" PRIx64 "\n",
            elf_64bit(&elf) ? "64-bit" : "32-bit",
            elf.pstart, elf.pend);

    /* elf contains virtual addresses that can have the upper bits
     * masked while running in real mode, so we do the masking as well
     * as well */
    parms.virt_kend = RM_MASK(parms.virt_kend, 42);
    parms.virt_entry = RM_MASK(parms.virt_entry, 42);

    /* By default DOM0 is allocated all available memory. */
    d->max_pages = ~0U;

    /* default is the max(1/16th of memory, CONFIG_MIN_DOM0_PAGES) */
    if (dom0_nrpages == 0) {
        dom0_nrpages = total_pages >> 4;

        if (dom0_nrpages < CONFIG_MIN_DOM0_PAGES)
            dom0_nrpages = CONFIG_MIN_DOM0_PAGES;
    }

    /* make sure we are at least as big as the RMA */
    if (dom0_nrpages > rma_nrpages)
        dom0_nrpages = allocate_extents(d, dom0_nrpages, rma_nrpages);

    ASSERT(d->tot_pages == dom0_nrpages);
    ASSERT(d->tot_pages >= rma_nrpages);

    if (opt_dom0_shadow == 0) {
        /* 1/64 of memory  */
        opt_dom0_shadow = (d->tot_pages >> 6) >> (20 - PAGE_SHIFT);
    }

    do {
        shadow_set_allocation(d, opt_dom0_shadow, &preempt);
    } while (preempt);
    if (shadow_get_allocation(d) == 0)
        panic("shadow allocation failed: %dMib\n", opt_dom0_shadow);

    ASSERT( image_len < rma_sz );

    si = (start_info_t *)(rma_addr(&d->arch, RMA_START_INFO) + rma);
    printk("xen_start_info: %p\n", si);

    snprintf(si->magic, sizeof(si->magic), "xen-%i.%i-powerpc%d%s",
            xen_major_version(), xen_minor_version(), BITS_PER_LONG, "HV");
    si->flags = SIF_PRIVILEGED | SIF_INITDOMAIN;

    si->shared_info = ((ulong)d->shared_info) - rma;
    printk("shared_info: 0x%lx,%p\n", si->shared_info, d->shared_info);

    eomem = si->shared_info;

    /* number of pages accessible */
    si->nr_pages = rma_sz >> PAGE_SHIFT;

    si->pt_base = 0;
    si->nr_pt_frames = 0;
    si->mfn_list = 0;

    /* OF usually sits here:
     *   - Linux needs it to be loaded before the vmlinux or initrd
     *   - AIX demands it to be @ 32M.
     */
    dst = (32 << 20);

    /* put stack below everything */
    v->arch.ctxt.gprs[1] = dst - STACK_FRAME_OVERHEAD;

    /* startup secondary processors */
    if ( opt_dom0_max_vcpus == 0 )
        opt_dom0_max_vcpus = num_online_cpus();
    if ( opt_dom0_max_vcpus > num_online_cpus() )
        opt_dom0_max_vcpus = num_online_cpus();
    if ( opt_dom0_max_vcpus > MAX_VIRT_CPUS )
        opt_dom0_max_vcpus = MAX_VIRT_CPUS;
#ifdef BITS_PER_GUEST_LONG
    if ( opt_dom0_max_vcpus > BITS_PER_GUEST_LONG(d) )
        opt_dom0_max_vcpus = BITS_PER_GUEST_LONG(d);
#endif
    printk("Dom0 has maximum %u VCPUs\n", opt_dom0_max_vcpus);

    for (vcpu = 1; vcpu < opt_dom0_max_vcpus; vcpu++) {
        if (NULL == alloc_vcpu(dom0, vcpu, vcpu))
            panic("Error creating domain 0 vcpu %d\n", vcpu);
        /* for now we pin Dom0 VCPUs to their coresponding CPUs */
        if (cpu_isset(vcpu, cpu_online_map))
            dom0->vcpu[vcpu]->cpu_affinity = cpumask_of_cpu(vcpu);
    }

    /* copy relative to Xen */
    dst += rma;

    ASSERT((dst - rma) + (ulong)firmware_image_size < eomem);
    printk("loading OFH: 0x%lx, RMA: 0x%lx\n", dst, dst - rma);
    memcpy((void *)dst, firmware_image_start, (ulong)firmware_image_size);

    v->arch.ctxt.gprs[5] = (dst - rma);
    ofh_tree = (u64 *)(dst + 0x10);
    ASSERT(*ofh_tree == 0xdeadbeef00000000);

    /* accomodate for a modest bss section */
    dst = ALIGN_UP(dst + (ulong)firmware_image_size + PAGE_SIZE, PAGE_SIZE);
    ASSERT((dst - rma) + oftree_len < eomem);

    *ofh_tree = dst - rma;
    printk("loading OFD: 0x%lx RMA: 0x%lx, 0x%lx\n", dst, dst - rma,
           oftree_len);
    memcpy((void *)dst, (void *)oftree, oftree_len);
    dst = ALIGN_UP(dst + oftree_len, PAGE_SIZE);

    /* Load the dom0 kernel. */
    elf.dest = (void *)dst;
    elf_load_binary(&elf);
    v->arch.ctxt.pc = dst - rma;
    dst = ALIGN_UP(dst + parms.virt_kend, PAGE_SIZE);

    /* Load the initrd. */
    if (initrd_len > 0) {
        ASSERT((dst - rma) + image_len < eomem);

        printk("loading initrd: 0x%lx, 0x%lx\n", dst, initrd_len);
        memcpy((void *)dst, (void *)initrd_start, initrd_len);

        si->mod_start = dst - rma;
        si->mod_len = image_len;

        dst = ALIGN_UP(dst + initrd_len, PAGE_SIZE);
    } else {
        printk("no initrd\n");
        si->mod_start = 0;
        si->mod_len = 0;
    }

    if (elf_64bit(&elf)) {
        v->arch.ctxt.msr = MSR_SF;
    } else {
        v->arch.ctxt.msr = 0;
    }
    v->arch.ctxt.gprs[2] = 0;
    v->arch.ctxt.gprs[3] = si->mod_start;
    v->arch.ctxt.gprs[4] = si->mod_len;

	printk("dom0 initial register state:\n"
			"    pc %016lx msr %016lx\n"
			"    r1 %016lx r2 %016lx r3 %016lx\n"
			"    r4 %016lx r5 %016lx\n",
			v->arch.ctxt.pc,
			v->arch.ctxt.msr,
			v->arch.ctxt.gprs[1],
			v->arch.ctxt.gprs[2],
			v->arch.ctxt.gprs[3],
			v->arch.ctxt.gprs[4],
			v->arch.ctxt.gprs[5]);

    memset(si->cmd_line, 0, sizeof(si->cmd_line));
    if ( cmdline != NULL )
        strlcpy((char *)si->cmd_line, cmdline, sizeof(si->cmd_line));

    ofd_dom0_fixup(d, *ofh_tree + rma, si);

    set_bit(_VCPUF_initialised, &v->vcpu_flags);

    rc = 0;

    /* DOM0 is permitted full I/O capabilities. */
    rc |= iomem_permit_access(dom0, 0UL, ~0UL);
    rc |= irqs_permit_access(dom0, 0, NR_IRQS-1);

    BUG_ON(rc != 0);

    return 0;
}
