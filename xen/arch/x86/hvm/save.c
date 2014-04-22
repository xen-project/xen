/*
 * hvm/save.c: Save and restore HVM guest's emulated hardware state.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2007, XenSource Inc.
 * Copyright (c) 2007, Isaku Yamahata <yamahata at valinux co jp>
 *                     VA Linux Systems Japan K.K.
 *                     split x86 specific part
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <asm/hvm/support.h>
#include <public/hvm/save.h>

void arch_hvm_save(struct domain *d, struct hvm_save_header *hdr)
{
    uint32_t eax, ebx, ecx, edx;

    /* Save some CPUID bits */
    cpuid(1, &eax, &ebx, &ecx, &edx);
    hdr->cpuid = eax;

    /* Save guest's preferred TSC. */
    hdr->gtsc_khz = d->arch.tsc_khz;

    /* Time when saving started */
    rdtscll(d->arch.hvm_domain.sync_tsc);
}

int arch_hvm_load(struct domain *d, struct hvm_save_header *hdr)
{
    uint32_t eax, ebx, ecx, edx;

    if ( hdr->magic != HVM_FILE_MAGIC )
    {
        printk(XENLOG_G_ERR "HVM%d restore: bad magic number %#"PRIx32"\n",
               d->domain_id, hdr->magic);
        return -1;
    }

    if ( hdr->version != HVM_FILE_VERSION )
    {
        printk(XENLOG_G_ERR "HVM%d restore: unsupported version %u\n",
               d->domain_id, hdr->version);
        return -1;
    }

    cpuid(1, &eax, &ebx, &ecx, &edx);
    /* CPUs ought to match but with feature-masking they might not */
    if ( (hdr->cpuid & ~0x0fUL) != (eax & ~0x0fUL) )
        printk(XENLOG_G_INFO "HVM%d restore: VM saved on one CPU "
               "(%#"PRIx32") and restored on another (%#"PRIx32").\n",
               d->domain_id, hdr->cpuid, eax);

    /* Restore guest's preferred TSC frequency. */
    if ( hdr->gtsc_khz )
        d->arch.tsc_khz = hdr->gtsc_khz;
    if ( d->arch.vtsc )
        hvm_set_rdtsc_exiting(d, 1);

    /* Time when restore started  */
    rdtscll(d->arch.hvm_domain.sync_tsc);

    /* VGA state is not saved/restored, so we nobble the cache. */
    d->arch.hvm_domain.stdvga.cache = 0;

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
