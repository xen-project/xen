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
#include <xen/elf.h>
#include <xen/sched.h>
#include <xen/init.h>
#include <xen/ctype.h>
#include <xen/iocap.h>
#include <xen/version.h>
#include <asm/processor.h>
#include <asm/papr.h>
#include "oftree.h"

extern int parseelfimage_32(struct domain_setup_info *dsi);
extern int loadelfimage_32(struct domain_setup_info *dsi);

/* opt_dom0_mem: memory allocated to domain 0. */
static unsigned int opt_dom0_mem;
static void parse_dom0_mem(char *s)
{
    unsigned long long bytes = parse_size_and_unit(s);
    /* If no unit is specified we default to kB units, not bytes. */
    if (isdigit(s[strlen(s)-1]))
        opt_dom0_mem = (unsigned int)bytes;
    else
        opt_dom0_mem = (unsigned int)(bytes >> 10);
}
custom_param("dom0_mem", parse_dom0_mem);

int elf_sanity_check(Elf_Ehdr *ehdr)
{
    if (IS_ELF(*ehdr))
        /* we are happy with either */
        if ((ehdr->e_ident[EI_CLASS] == ELFCLASS32
             && ehdr->e_machine == EM_PPC)
            || (ehdr->e_ident[EI_CLASS] == ELFCLASS64
                && ehdr->e_machine == EM_PPC64)) {
            if (ehdr->e_ident[EI_DATA] == ELFDATA2MSB
                && ehdr->e_type == ET_EXEC)
                return 1;
        }
    printk("DOM0 image is not a Xen-compatible Elf image.\n");
    return 0;
}

/* adapted from common/elf.c */
#define RM_MASK(a,l) ((a) & ((1UL << (l)) - 1))

static int rm_loadelfimage_64(struct domain_setup_info *dsi, ulong rma)
{
    char *elfbase = (char *)dsi->image_addr;
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)dsi->image_addr;
    Elf64_Phdr *phdr;
    int h;
  
    for (h = 0; h < ehdr->e_phnum; h++ ) 
    {
        phdr = (Elf64_Phdr *)(elfbase + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if (!((phdr->p_type == PT_LOAD) &&
             ((phdr->p_flags & (PF_W|PF_X)) != 0)))
            continue;

        if (phdr->p_filesz != 0)
            memcpy((char *)(rma + RM_MASK(phdr->p_paddr, 42)),
                   elfbase + phdr->p_offset, 
                   phdr->p_filesz);
        if (phdr->p_memsz > phdr->p_filesz)
            memset((char *)(rma + RM_MASK(phdr->p_paddr, 42) + phdr->p_filesz),
                   0, phdr->p_memsz - phdr->p_filesz);
    }

#ifdef NOT_YET
    loadelfsymtab(dsi, 1);
#endif

    return 0;
}

int construct_dom0(struct domain *d,
                   unsigned long image_start, unsigned long image_len, 
                   unsigned long initrd_start, unsigned long initrd_len,
                   char *cmdline)
{
    int rc;
    struct vcpu *v = d->vcpu[0];
    struct domain_setup_info dsi;
    ulong dst;
    u64 *ofh_tree;
    ulong rma_sz = d->arch.rma_size;
    ulong rma = d->arch.rma_base;
    start_info_t *si;
    ulong eomem;
    int am64 = 1;
    ulong msr;
    ulong pc;
    ulong r2;

    /* Sanity! */
    BUG_ON(d->domain_id != 0);
    BUG_ON(d->vcpu[0] == NULL);

    cpu_init_vcpu(v);

    memset(&dsi, 0, sizeof(struct domain_setup_info));
    dsi.image_addr = image_start;
    dsi.image_len  = image_len;

    if ((rc = parseelfimage(&dsi)) != 0) {
        if ((rc = parseelfimage_32(&dsi)) != 0)
            return rc;
        am64 = 0;
    }

    /* elf contains virtual addresses that can have the upper bits
     * masked while running in real mode, so we do the masking as well
     * as well */
    dsi.v_kernstart = RM_MASK(dsi.v_kernstart, 42);
    dsi.v_kernend = RM_MASK(dsi.v_kernend, 42);
    dsi.v_kernentry = RM_MASK(dsi.v_kernentry, 42);

    if (dsi.xen_section_string == NULL) {
        printk("Not a Xen-ELF image: '__xen_guest' section not found.\n");
        return -EINVAL;
    }
    printk("*** LOADING DOMAIN 0 ***\n");

    /* By default DOM0 is allocated all available memory. */
    d->max_pages = ~0U;
    d->tot_pages = (d->arch.rma_size >> PAGE_SHIFT);

    ASSERT( image_len < rma_sz );

    si = (start_info_t *)(rma_addr(&d->arch, RMA_START_INFO) + rma);
    printk("xen_start_info: %p\n", si);

    sprintf(si->magic, "xen-%i.%i-powerpc%d%s",
            xen_major_version(), xen_minor_version(), BITS_PER_LONG, "HV");
    si->flags = SIF_PRIVILEGED | SIF_INITDOMAIN;

    si->shared_info = ((ulong)d->shared_info) - rma;
    printk("shared_info: 0x%lx,%p\n", si->shared_info, d->shared_info);

    eomem = si->shared_info;

    /* allow dom0 to access all of system RAM */
    d->arch.logical_base_pfn = 128 << (20 - PAGE_SHIFT); /* 128 MB */
    d->arch.logical_end_pfn = max_page;

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

    if (am64) {
        ulong kbase;
        ulong *fdesc;

        printk("loading 64-bit Dom0: 0x%lx, in RMA:0x%lx\n", dst, dst - rma);
        rm_loadelfimage_64(&dsi, dst);

        kbase = dst;
        /* move dst to end of bss */
        dst = ALIGN_UP(dsi.v_kernend + dst, PAGE_SIZE);

        if ( initrd_len > 0 ) {
            ASSERT( (dst - rma) + image_len < eomem );

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
        /* it may be a function descriptor */
        fdesc = (ulong *)(dsi.v_kernstart + dsi.v_kernentry + kbase);

        if (fdesc[2] == 0
            && ((fdesc[0] >= dsi.v_kernstart)
                && (fdesc[0] < dsi.v_kernend)) /* text entry is in range */
            && ((fdesc[1] >= dsi.v_kernstart)  /* toc can be > image */
                && (fdesc[1] < (dsi.v_kernend + (0x7fff * sizeof (ulong)))))) {
            /* it is almost certainly a function descriptor */
            pc = RM_MASK(fdesc[0], 42) + kbase - rma;
            r2 = RM_MASK(fdesc[1], 42) + kbase - rma;
        } else {
            pc = ((ulong)fdesc) - rma;
            r2 = 0;
        }
        msr = MSR_SF;
    } else {
        printk("loading 32-bit Dom0: 0x%lx, in RMA:0x%lx\n",
               dsi.v_kernstart + rma, dsi.v_kernstart);
        dsi.v_start = rma;
        loadelfimage_32(&dsi);

        pc = dsi.v_kernentry;
        r2 = 0;
        msr = 0;
    }

    v->arch.ctxt.gprs[3] = si->mod_start;
    v->arch.ctxt.gprs[4] = si->mod_len;

    memset(si->cmd_line, 0, sizeof(si->cmd_line));
    if ( cmdline != NULL )
        strncpy((char *)si->cmd_line, cmdline, sizeof(si->cmd_line)-1);

    v->arch.ctxt.msr = msr;
    v->arch.ctxt.pc = pc;
    v->arch.ctxt.gprs[2] = r2;

    printk("DOM: pc = 0x%lx, r2 = 0x%lx\n", pc, r2);

    ofd_dom0_fixup(d, *ofh_tree + rma, si, dst - rma);

    set_bit(_VCPUF_initialised, &v->vcpu_flags);

    rc = 0;

    /* DOM0 is permitted full I/O capabilities. */
    rc |= iomem_permit_access(dom0, 0UL, ~0UL);
    rc |= irqs_permit_access(dom0, 0, NR_IRQS-1);

    BUG_ON(rc != 0);

    return 0;
}
