/*
 * pv/domain.h
 *
 * PV guest interface definitions
 *
 * Copyright (C) 2017 Wei Liu <wei.liu2@citrix.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __X86_PV_DOMAIN_H__
#define __X86_PV_DOMAIN_H__

/*
 * PCID values for the address spaces of 64-bit pv domains:
 *
 * We are using 4 PCID values for a 64 bit pv domain subject to XPTI:
 * - hypervisor active and guest in kernel mode   PCID 0
 * - hypervisor active and guest in user mode     PCID 1
 * - guest active and in kernel mode              PCID 2
 * - guest active and in user mode                PCID 3
 *
 * Without XPTI only 2 values are used:
 * - guest in kernel mode                         PCID 0
 * - guest in user mode                           PCID 1
 */

#define PCID_PV_PRIV      0x0000    /* Used for other domains, too. */
#define PCID_PV_USER      0x0001
#define PCID_PV_XPTI      0x0002    /* To be ORed to above values. */

/*
 * Return additional PCID specific cr3 bits.
 *
 * Note that X86_CR3_NOFLUSH will not be readable in cr3. Anyone consuming
 * v->arch.cr3 should mask away X86_CR3_NOFLUSH and X86_CR3_PCIDMASK in case
 * the value is used to address the root page table.
 */
static inline unsigned long get_pcid_bits(const struct vcpu *v, bool is_xpti)
{
    return X86_CR3_NOFLUSH | (is_xpti ? PCID_PV_XPTI : 0) |
           ((v->arch.flags & TF_kernel_mode) ? PCID_PV_PRIV : PCID_PV_USER);
}

#ifdef CONFIG_PV

void pv_vcpu_destroy(struct vcpu *v);
int pv_vcpu_initialise(struct vcpu *v);
void pv_domain_destroy(struct domain *d);
int pv_domain_initialise(struct domain *d, unsigned int domcr_flags,
                         struct xen_arch_domainconfig *config);

#else  /* !CONFIG_PV */

#include <xen/errno.h>

static inline void pv_vcpu_destroy(struct vcpu *v) {}
static inline int pv_vcpu_initialise(struct vcpu *v) { return -EOPNOTSUPP; }
static inline void pv_domain_destroy(struct domain *d) {}
static inline int pv_domain_initialise(struct domain *d,
                                       unsigned int domcr_flags,
                                       struct xen_arch_domainconfig *config);
{
    return -EOPNOTSUPP;
}
#endif	/* CONFIG_PV */

void paravirt_ctxt_switch_from(struct vcpu *v);
void paravirt_ctxt_switch_to(struct vcpu *v);

#endif	/* __X86_PV_DOMAIN_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
