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
}

int arch_hvm_load(struct domain *d, struct hvm_save_header *hdr)
{
    uint32_t eax, ebx, ecx, edx;

    if ( hdr->magic != HVM_FILE_MAGIC )
    {
        gdprintk(XENLOG_ERR, 
                 "HVM restore: bad magic number %#"PRIx32"\n", hdr->magic);
        return -1;
    }

    if ( hdr->version != HVM_FILE_VERSION )
    {
        gdprintk(XENLOG_ERR, 
                 "HVM restore: unsupported version %u\n", hdr->version);
        return -1;
    }

    cpuid(1, &eax, &ebx, &ecx, &edx);
    /* TODO: need to define how big a difference is acceptable? */
    if ( hdr->cpuid != eax )
        gdprintk(XENLOG_WARNING, "HVM restore: saved CPUID (%#"PRIx32") "
               "does not match host (%#"PRIx32").\n", hdr->cpuid, eax);

    /* Restore guest's preferred TSC frequency. */
    if ( hdr->gtsc_khz )
        d->arch.tsc_khz = hdr->gtsc_khz;
    if ( d->arch.vtsc )
    {
        hvm_set_rdtsc_exiting(d, 1);
        gdprintk(XENLOG_WARNING, "Domain %d expects freq %uMHz "
                "but host's freq is %luMHz: trap and emulate rdtsc\n",
                d->domain_id, hdr->gtsc_khz / 1000, cpu_khz / 1000);
    }

    /* VGA state is not saved/restored, so we nobble the cache. */
    d->arch.hvm_domain.stdvga.cache = 0;

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
