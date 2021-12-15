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

#include <xen/sched.h>

#ifdef CONFIG_PV32
extern int8_t opt_pv32;
#else
# define opt_pv32 false
#endif

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
#ifdef CONFIG_PV
    return X86_CR3_NOFLUSH | (is_xpti ? PCID_PV_XPTI : 0) |
           ((v->arch.flags & TF_kernel_mode) ? PCID_PV_PRIV : PCID_PV_USER);
#else
    ASSERT_UNREACHABLE();
    return 0;
#endif
}

#ifdef CONFIG_PV

void pv_vcpu_destroy(struct vcpu *v);
int pv_vcpu_initialise(struct vcpu *v);
void pv_domain_destroy(struct domain *d);
int pv_domain_initialise(struct domain *d);

/*
 * Bits which a PV guest can toggle in its view of cr4.  Some are loaded into
 * hardware, while some are fully emulated.
 */
#define PV_CR4_GUEST_MASK \
    (X86_CR4_TSD | X86_CR4_DE | X86_CR4_FSGSBASE | X86_CR4_OSXSAVE)

/* Bits which a PV guest may observe from the real hardware settings. */
#define PV_CR4_GUEST_VISIBLE_MASK \
    (X86_CR4_PAE | X86_CR4_MCE | X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT)

/* Given a new cr4 value, construct the resulting guest-visible cr4 value. */
unsigned long pv_fixup_guest_cr4(const struct vcpu *v, unsigned long cr4);

/* Create a cr4 value to load into hardware, based on vcpu settings. */
unsigned long pv_make_cr4(const struct vcpu *v);

bool xpti_pcid_enabled(void);

#else  /* !CONFIG_PV */

#include <xen/errno.h>

static inline void pv_vcpu_destroy(struct vcpu *v) {}
static inline int pv_vcpu_initialise(struct vcpu *v) { return -EOPNOTSUPP; }
static inline void pv_domain_destroy(struct domain *d) {}
static inline int pv_domain_initialise(struct domain *d) { return -EOPNOTSUPP; }

static inline unsigned long pv_make_cr4(const struct vcpu *v) { return ~0ul; }

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
