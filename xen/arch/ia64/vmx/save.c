/*
 * hvm/save.c: Save and restore HVM guest's emulated hardware state.
 *
 * Copyright (c) 2007, Isaku Yamahata <yamahata at valinux co jp>
 *                     VA Linux Systems Japan K.K.
 *                     IA64 support
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/types.h>
#include <xen/hvm/save.h>

void arch_hvm_save(struct domain *d, struct hvm_save_header *hdr)
{
    unsigned int i;
    
    for (i = 0; i < 5; ++i)
        hdr->cpuid[i] = ia64_get_cpuid(i);
}

int arch_hvm_load(struct domain *d, struct hvm_save_header *hdr)
{
    unsigned int i;
    if (hdr->magic != HVM_FILE_MAGIC) {
        gdprintk(XENLOG_ERR, 
                 "HVM restore: bad magic number %#"PRIx64"\n", hdr->magic);
        return -1;
    }

    if (hdr->version != HVM_FILE_VERSION) {
        gdprintk(XENLOG_ERR, 
                 "HVM restore: unsupported version %"PRIx64"\n", hdr->version);
        return -1;
    }

    for (i = 0; i < 5; ++i) {
        unsigned long cpuid = ia64_get_cpuid(i);
        /* TODO: need to define how big a difference is acceptable */
        if (hdr->cpuid[i] != cpuid)
            gdprintk(XENLOG_WARNING,
                     "HVM restore: saved CPUID[%d] (%#lx) "
                     "does not match host (%#lx).\n", i, hdr->cpuid[i], cpuid);
    }

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
