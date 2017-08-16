/*
 * Guest page table walk
 * Copyright (c) 2017 Sergej Proskurin <proskurin@sec.in.tum.de>
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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/sched.h>

/*
 * The function guest_walk_sd translates a given GVA into an IPA using the
 * short-descriptor translation table format in software. This function assumes
 * that the domain is running on the currently active vCPU. To walk the guest's
 * page table on a different vCPU, the following registers would need to be
 * loaded: TCR_EL1, TTBR0_EL1, TTBR1_EL1, and SCTLR_EL1.
 */
static int guest_walk_sd(const struct vcpu *v,
                         vaddr_t gva, paddr_t *ipa,
                         unsigned int *perms)
{
    /* Not implemented yet. */
    return -EFAULT;
}

/*
 * The function guest_walk_ld translates a given GVA into an IPA using the
 * long-descriptor translation table format in software. This function assumes
 * that the domain is running on the currently active vCPU. To walk the guest's
 * page table on a different vCPU, the following registers would need to be
 * loaded: TCR_EL1, TTBR0_EL1, TTBR1_EL1, and SCTLR_EL1.
 */
static int guest_walk_ld(const struct vcpu *v,
                         vaddr_t gva, paddr_t *ipa,
                         unsigned int *perms)
{
    /* Not implemented yet. */
    return -EFAULT;
}

int guest_walk_tables(const struct vcpu *v, vaddr_t gva,
                      paddr_t *ipa, unsigned int *perms)
{
    uint32_t sctlr = READ_SYSREG(SCTLR_EL1);
    register_t tcr = READ_SYSREG(TCR_EL1);
    unsigned int _perms;

    /* We assume that the domain is running on the currently active domain. */
    if ( v != current )
        return -EFAULT;

    /* Allow perms to be NULL. */
    perms = perms ?: &_perms;

    /*
     * Currently, we assume a GVA to IPA translation with EL1 privileges.
     * Since, valid mappings in the first stage address translation table are
     * readable by default for EL1, we initialize perms with GV2M_READ and
     * extend the permissions as part of the particular page table walk. Please
     * note that the current implementation does not consider further
     * attributes that distinguish between EL0 and EL1 permissions (EL0 might
     * not have permissions on the particular mapping).
     */
    *perms = GV2M_READ;

    /* If the MMU is disabled, there is no need to translate the gva. */
    if ( !(sctlr & SCTLR_M) )
    {
        *ipa = gva;

        /* Memory can be accessed without any restrictions. */
        *perms = GV2M_READ|GV2M_WRITE|GV2M_EXEC;

        return 0;
    }

    if ( is_32bit_domain(v->domain) && !(tcr & TTBCR_EAE) )
        return guest_walk_sd(v, gva, ipa, perms);
    else
        return guest_walk_ld(v, gva, ipa, perms);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
