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

#include <xen/domain_page.h>
#include <xen/sched.h>
#include <asm/guest_access.h>
#include <asm/guest_walk.h>
#include <asm/short-desc.h>

/*
 * The function guest_walk_sd translates a given GVA into an IPA using the
 * short-descriptor translation table format in software. This function assumes
 * that the domain is running on the currently active vCPU. To walk the guest's
 * page table on a different vCPU, the following registers would need to be
 * loaded: TCR_EL1, TTBR0_EL1, TTBR1_EL1, and SCTLR_EL1.
 */
static bool guest_walk_sd(const struct vcpu *v,
                          vaddr_t gva, paddr_t *ipa,
                          unsigned int *perms)
{
    int ret;
    bool disabled = true;
    uint32_t ttbr;
    paddr_t mask, paddr;
    short_desc_t pte;
    register_t ttbcr = READ_SYSREG(TCR_EL1);
    unsigned int n = ttbcr & TTBCR_N_MASK;
    struct domain *d = v->domain;

    mask = GENMASK_ULL(31, (32 - n));

    if ( n == 0 || !(gva & mask) )
    {
        /*
         * Use TTBR0 for GVA to IPA translation.
         *
         * Note that on AArch32, the TTBR0_EL1 register is 32-bit wide.
         * Nevertheless, we have to use the READ_SYSREG64 macro, as it is
         * required for reading TTBR0_EL1.
         */
        ttbr = READ_SYSREG64(TTBR0_EL1);

        /* If TTBCR.PD0 is set, translations using TTBR0 are disabled. */
        disabled = ttbcr & TTBCR_PD0;
    }
    else
    {
        /*
         * Use TTBR1 for GVA to IPA translation.
         *
         * Note that on AArch32, the TTBR1_EL1 register is 32-bit wide.
         * Nevertheless, we have to use the READ_SYSREG64 macro, as it is
         * required for reading TTBR1_EL1.
         */
        ttbr = READ_SYSREG64(TTBR1_EL1);

        /* If TTBCR.PD1 is set, translations using TTBR1 are disabled. */
        disabled = ttbcr & TTBCR_PD1;

        /*
         * TTBR1 translation always works like n==0 TTBR0 translation (ARM DDI
         * 0487B.a J1-6003).
         */
        n = 0;
    }

    if ( disabled )
        return false;

    /*
     * The address of the L1 descriptor for the initial lookup has the
     * following format: [ttbr<31:14-n>:gva<31-n:20>:00] (ARM DDI 0487B.a
     * J1-6003). Note that the following GPA computation already considers that
     * the first level address translation might comprise up to four
     * consecutive pages and does not need to be page-aligned if n > 2.
     */
    mask = GENMASK(31, (14 - n));
    paddr = (ttbr & mask);

    mask = GENMASK((31 - n), 20);
    paddr |= (gva & mask) >> 18;

    /* Access the guest's memory to read only one PTE. */
    ret = access_guest_memory_by_ipa(d, paddr, &pte, sizeof(short_desc_t), false);
    if ( ret )
        return false;

    switch ( pte.walk.dt )
    {
    case L1DESC_INVALID:
        return false;

    case L1DESC_PAGE_TABLE:
        /*
         * The address of the L2 descriptor has the following format:
         * [l1desc<31:10>:gva<19:12>:00] (ARM DDI 0487B.aJ1-6004). Note that
         * the following address computation already considers that the second
         * level translation table does not need to be page aligned.
         */
        mask = GENMASK(19, 12);
        /*
         * Cast pte.walk.base to paddr_t to cope with C type promotion of types
         * smaller than int. Otherwise pte.walk.base would be casted to int and
         * subsequently sign extended, thus leading to a wrong value.
         */
        paddr = ((paddr_t)pte.walk.base << 10) | ((gva & mask) >> 10);

        /* Access the guest's memory to read only one PTE. */
        ret = access_guest_memory_by_ipa(d, paddr, &pte, sizeof(short_desc_t), false);
        if ( ret )
            return false;

        if ( pte.walk.dt == L2DESC_INVALID )
            return false;

        if ( pte.pg.page ) /* Small page. */
        {
            mask = (1ULL << L2DESC_SMALL_PAGE_SHIFT) - 1;
            *ipa = ((paddr_t)pte.pg.base << L2DESC_SMALL_PAGE_SHIFT) | (gva & mask);

            /* Set execute permissions associated with the small page. */
            if ( !pte.pg.xn )
                *perms |= GV2M_EXEC;
        }
        else /* Large page. */
        {
            mask = (1ULL << L2DESC_LARGE_PAGE_SHIFT) - 1;
            *ipa = ((paddr_t)pte.lpg.base << L2DESC_LARGE_PAGE_SHIFT) | (gva & mask);

            /* Set execute permissions associated with the large page. */
            if ( !pte.lpg.xn )
                *perms |= GV2M_EXEC;
        }

        /* Set permissions so that the caller can check the flags by herself. */
        if ( !pte.pg.ro )
            *perms |= GV2M_WRITE;

        break;

    case L1DESC_SECTION:
    case L1DESC_SECTION_PXN:
        if ( !pte.sec.supersec ) /* Section */
        {
            mask = (1ULL << L1DESC_SECTION_SHIFT) - 1;
            *ipa = ((paddr_t)pte.sec.base << L1DESC_SECTION_SHIFT) | (gva & mask);
        }
        else /* Supersection */
        {
            mask = (1ULL << L1DESC_SUPERSECTION_SHIFT) - 1;
            *ipa = gva & mask;
            *ipa |= (paddr_t)(pte.supersec.base) << L1DESC_SUPERSECTION_SHIFT;
            *ipa |= (paddr_t)(pte.supersec.extbase1) << L1DESC_SUPERSECTION_EXT_BASE1_SHIFT;
            *ipa |= (paddr_t)(pte.supersec.extbase2) << L1DESC_SUPERSECTION_EXT_BASE2_SHIFT;
        }

        /* Set permissions so that the caller can check the flags by herself. */
        if ( !pte.sec.ro )
            *perms |= GV2M_WRITE;
        if ( !pte.sec.xn )
            *perms |= GV2M_EXEC;
    }

    return true;
}

/*
 * Get the IPA output_size (configured in TCR_EL1) that shall be used for the
 * long-descriptor based translation table walk.
 */
static int get_ipa_output_size(struct domain *d, register_t tcr,
                               unsigned int *output_size)
{
#ifdef CONFIG_ARM_64
    register_t ips;

    static const unsigned int ipa_sizes[7] = {
        TCR_EL1_IPS_32_BIT_VAL,
        TCR_EL1_IPS_36_BIT_VAL,
        TCR_EL1_IPS_40_BIT_VAL,
        TCR_EL1_IPS_42_BIT_VAL,
        TCR_EL1_IPS_44_BIT_VAL,
        TCR_EL1_IPS_48_BIT_VAL,
        TCR_EL1_IPS_52_BIT_VAL
    };

    if ( is_64bit_domain(d) )
    {
        /* Get the intermediate physical address size. */
        ips = tcr & TCR_EL1_IPS_MASK;

        /*
         * Return an error on reserved IPA output-sizes and if the IPA
         * output-size is 52bit.
         *
         * XXX: 52 bit output-size is not supported yet.
         */
        if ( ips > TCR_EL1_IPS_48_BIT )
            return -EFAULT;

        *output_size = ipa_sizes[ips >> TCR_EL1_IPS_SHIFT];
    }
    else
#endif
        *output_size = TCR_EL1_IPS_40_BIT_VAL;

    return 0;
}

/* Normalized page granule size indices. */
enum granule_size_index {
    GRANULE_SIZE_INDEX_4K,
    GRANULE_SIZE_INDEX_16K,
    GRANULE_SIZE_INDEX_64K
};

/* Represent whether TTBR0 or TTBR1 is active. */
enum active_ttbr {
    TTBR0_ACTIVE,
    TTBR1_ACTIVE
};

/*
 * Select the TTBR(0|1)_EL1 that will be used for address translation using the
 * long-descriptor translation table format and return the page granularity
 * that is used by the selected TTBR. Please note that the TCR.TG0 and TCR.TG1
 * encodings differ.
 */
static bool get_ttbr_and_gran_64bit(uint64_t *ttbr, unsigned int *gran,
                                    register_t tcr, enum active_ttbr ttbrx)
{
    bool disabled;

    if ( ttbrx == TTBR0_ACTIVE )
    {
        /* Normalize granule size. */
        switch ( tcr & TCR_TG0_MASK )
        {
        case TCR_TG0_16K:
            *gran = GRANULE_SIZE_INDEX_16K;
            break;
        case TCR_TG0_64K:
            *gran = GRANULE_SIZE_INDEX_64K;
            break;
        default:
            /*
             * According to ARM DDI 0487B.a D7-2487, if the TCR_EL1.TG0 value
             * is programmed to either a reserved value, or a size that has not
             * been implemented, then the hardware will treat the field as if
             * it has been programmed to an IMPLEMENTATION DEFINED choice.
             *
             * This implementation strongly follows the pseudo-code
             * implementation from ARM DDI 0487B.a J1-5924 which suggests to
             * fall back to 4K by default.
             */
            *gran = GRANULE_SIZE_INDEX_4K;
        }

        /* Use TTBR0 for GVA to IPA translation. */
        *ttbr = READ_SYSREG64(TTBR0_EL1);

        /* If TCR.EPD0 is set, translations using TTBR0 are disabled. */
        disabled = tcr & TCR_EPD0;
    }
    else
    {
        /* Normalize granule size. */
        switch ( tcr & TCR_EL1_TG1_MASK )
        {
        case TCR_EL1_TG1_16K:
            *gran = GRANULE_SIZE_INDEX_16K;
            break;
        case TCR_EL1_TG1_64K:
            *gran = GRANULE_SIZE_INDEX_64K;
            break;
        default:
            /*
             * According to ARM DDI 0487B.a D7-2486, if the TCR_EL1.TG1 value
             * is programmed to either a reserved value, or a size that has not
             * been implemented, then the hardware will treat the field as if
             * it has been programmed to an IMPLEMENTATION DEFINED choice.
             *
             * This implementation strongly follows the pseudo-code
             * implementation from ARM DDI 0487B.a J1-5924 which suggests to
             * fall back to 4K by default.
             */
            *gran = GRANULE_SIZE_INDEX_4K;
        }

        /* Use TTBR1 for GVA to IPA translation. */
        *ttbr = READ_SYSREG64(TTBR1_EL1);

        /* If TCR.EPD1 is set, translations using TTBR1 are disabled. */
        disabled = tcr & TCR_EPD1;
    }

    return disabled;
}

/*
 * Get the MSB number of the GVA, according to "AddrTop" pseudocode
 * implementation in ARM DDI 0487B.a J1-6066.
 */
static unsigned int get_top_bit(struct domain *d, vaddr_t gva, register_t tcr)
{
    unsigned int topbit;

    /*
     * If EL1 is using AArch64 then addresses from EL0 using AArch32 are
     * zero-extended to 64 bits (ARM DDI 0487B.a J1-6066).
     */
    if ( is_32bit_domain(d) )
        topbit = 31;
    else
    {
        if ( ((gva & BIT(55, ULL)) && (tcr & TCR_EL1_TBI1)) ||
             (!(gva & BIT(55, ULL)) && (tcr & TCR_EL1_TBI0)) )
            topbit = 55;
        else
            topbit = 63;
    }

    return topbit;
}

/* Make sure the base address does not exceed its configured size. */
static bool check_base_size(unsigned int output_size, uint64_t base)
{
    paddr_t mask = GENMASK_ULL((TCR_EL1_IPS_48_BIT_VAL - 1), output_size);

    if ( (output_size < TCR_EL1_IPS_48_BIT_VAL) && (base & mask) )
        return false;

    return true;
}

/*
 * The function guest_walk_ld translates a given GVA into an IPA using the
 * long-descriptor translation table format in software. This function assumes
 * that the domain is running on the currently active vCPU. To walk the guest's
 * page table on a different vCPU, the following registers would need to be
 * loaded: TCR_EL1, TTBR0_EL1, TTBR1_EL1, and SCTLR_EL1.
 */
static bool guest_walk_ld(const struct vcpu *v,
                          vaddr_t gva, paddr_t *ipa,
                          unsigned int *perms)
{
    int ret;
    bool disabled = true;
    bool ro_table = false, xn_table = false;
    unsigned int t0_sz, t1_sz;
    unsigned int level, gran;
    unsigned int topbit = 0, input_size = 0, output_size;
    uint64_t ttbr = 0;
    paddr_t mask, paddr;
    lpae_t pte;
    register_t tcr = READ_SYSREG(TCR_EL1);
    struct domain *d = v->domain;

#define OFFSETS(gva, gran)              \
{                                       \
    zeroeth_table_offset_##gran(gva),   \
    first_table_offset_##gran(gva),     \
    second_table_offset_##gran(gva),    \
    third_table_offset_##gran(gva)      \
}

    const paddr_t offsets[3][4] = {
        OFFSETS(gva, 4K),
        OFFSETS(gva, 16K),
        OFFSETS(gva, 64K)
    };

#undef OFFSETS

#define MASKS(gran)                     \
{                                       \
    zeroeth_size(gran) - 1,             \
    first_size(gran) - 1,               \
    second_size(gran) - 1,              \
    third_size(gran) - 1                \
}

    static const paddr_t masks[3][4] = {
        MASKS(4K),
        MASKS(16K),
        MASKS(64K)
    };

#undef MASKS

    static const unsigned int grainsizes[3] = {
        PAGE_SHIFT_4K,
        PAGE_SHIFT_16K,
        PAGE_SHIFT_64K
    };

    t0_sz = (tcr >> TCR_T0SZ_SHIFT) & TCR_SZ_MASK;
    t1_sz = (tcr >> TCR_T1SZ_SHIFT) & TCR_SZ_MASK;

    /* Get the MSB number of the GVA. */
    topbit = get_top_bit(d, gva, tcr);

    if ( is_64bit_domain(d) )
    {
        /* Select the TTBR(0|1)_EL1 that will be used for address translation. */

        if ( (gva & BIT(topbit, ULL)) == 0 )
        {
            input_size = 64 - t0_sz;

            /* Get TTBR0 and configured page granularity. */
            disabled = get_ttbr_and_gran_64bit(&ttbr, &gran, tcr, TTBR0_ACTIVE);
        }
        else
        {
            input_size = 64 - t1_sz;

            /* Get TTBR1 and configured page granularity. */
            disabled = get_ttbr_and_gran_64bit(&ttbr, &gran, tcr, TTBR1_ACTIVE);
        }

        /*
         * The current implementation supports intermediate physical address
         * sizes (IPS) up to 48 bit.
         *
         * XXX: Determine whether the IPS_MAX_VAL is 48 or 52 in software.
         */
        if ( (input_size > TCR_EL1_IPS_48_BIT_VAL) ||
             (input_size < TCR_EL1_IPS_MIN_VAL) )
            return false;
    }
    else
    {
        /* Granule size of AArch32 architectures is always 4K. */
        gran = GRANULE_SIZE_INDEX_4K;

        /* Select the TTBR(0|1)_EL1 that will be used for address translation. */

        /*
         * Check if the bits <31:32-t0_sz> of the GVA are set to 0 (DDI 0487B.a
         * J1-5999). If so, TTBR0 shall be used for address translation.
         */
        mask = GENMASK_ULL(31, (32 - t0_sz));

        if ( t0_sz == 0 || !(gva & mask) )
        {
            input_size = 32 - t0_sz;

            /* Use TTBR0 for GVA to IPA translation. */
            ttbr = READ_SYSREG64(TTBR0_EL1);

            /* If TCR.EPD0 is set, translations using TTBR0 are disabled. */
            disabled = tcr & TCR_EPD0;
        }

        /*
         * Check if the bits <31:32-t1_sz> of the GVA are set to 1 (DDI 0487B.a
         * J1-6000). If so, TTBR1 shall be used for address translation.
         */
        mask = GENMASK_ULL(31, (32 - t1_sz));

        if ( ((t1_sz == 0) && !ttbr) || (t1_sz && (gva & mask) == mask) )
        {
            input_size = 32 - t1_sz;

            /* Use TTBR1 for GVA to IPA translation. */
            ttbr = READ_SYSREG64(TTBR1_EL1);

            /* If TCR.EPD1 is set, translations using TTBR1 are disabled. */
            disabled = tcr & TCR_EPD1;
        }
    }

    if ( disabled )
        return false;

    /*
     * The starting level is the number of strides (grainsizes[gran] - 3)
     * needed to consume the input address (ARM DDI 0487B.a J1-5924).
     */
    level = 4 - DIV_ROUND_UP((input_size - grainsizes[gran]), (grainsizes[gran] - 3));

    /* Get the IPA output_size. */
    ret = get_ipa_output_size(d, tcr, &output_size);
    if ( ret )
        return false;

    /* Make sure the base address does not exceed its configured size. */
    ret = check_base_size(output_size, ttbr);
    if ( !ret )
        return false;

    /*
     * Compute the base address of the first level translation table that is
     * given by TTBRx_EL1 (ARM DDI 0487B.a D4-2024 and J1-5926).
     */
    mask = GENMASK_ULL(47, grainsizes[gran]);
    paddr = (ttbr & mask);

    for ( ; ; level++ )
    {
        /*
         * Add offset given by the GVA to the translation table base address.
         * Shift the offset by 3 as it is 8-byte aligned.
         */
        paddr |= offsets[gran][level] << 3;

        /* Access the guest's memory to read only one PTE. */
        ret = access_guest_memory_by_ipa(d, paddr, &pte, sizeof(lpae_t), false);
        if ( ret )
            return false;

        /* Make sure the base address does not exceed its configured size. */
        ret = check_base_size(output_size, pfn_to_paddr(pte.walk.base));
        if ( !ret )
            return false;

        /*
         * If page granularity is 64K, make sure the address is aligned
         * appropriately.
         */
        if ( (output_size < TCR_EL1_IPS_52_BIT_VAL) &&
             (gran == GRANULE_SIZE_INDEX_64K) &&
             (pte.walk.base & 0xf) )
            return false;

        /*
         * Break if one of the following conditions is true:
         *
         * - We have found the PTE holding the IPA (level == 3).
         * - The PTE is not valid.
         * - If (level < 3) and the PTE is valid, we found a block descriptor.
         */
        if ( level == 3 || !lpae_is_valid(pte) || lpae_is_superpage(pte, level) )
            break;

        /*
         * Temporarily store permissions of the table descriptor as they are
         * inherited by page table attributes (ARM DDI 0487B.a J1-5928).
         */
        xn_table |= pte.pt.xnt;             /* Execute-Never */
        ro_table |= pte.pt.apt & BIT(1, UL);/* Read-Only */

        /* Compute the base address of the next level translation table. */
        mask = GENMASK_ULL(47, grainsizes[gran]);
        paddr = pfn_to_paddr(pte.walk.base) & mask;
    }

    /*
     * According to ARM DDI 0487B.a J1-5927, we return an error if the found
     * PTE is invalid or holds a reserved entry (PTE<1:0> == x0)) or if the PTE
     * maps a memory block at level 3 (PTE<1:0> == 01).
     */
    if ( !lpae_is_valid(pte) || !lpae_is_mapping(pte, level) )
        return false;

    /* Make sure that the lower bits of the PTE's base address are zero. */
    mask = GENMASK_ULL(47, grainsizes[gran]);
    *ipa = (pfn_to_paddr(pte.walk.base) & mask) | (gva & masks[gran][level]);

    /*
     * Set permissions so that the caller can check the flags by herself. Note
     * that stage 1 translations also inherit attributes from the tables
     * (ARM DDI 0487B.a J1-5928).
     */
    if ( !pte.pt.ro && !ro_table )
        *perms |= GV2M_WRITE;
    if ( !pte.pt.xn && !xn_table )
        *perms |= GV2M_EXEC;

    return true;
}

bool guest_walk_tables(const struct vcpu *v, vaddr_t gva,
                       paddr_t *ipa, unsigned int *perms)
{
    register_t sctlr = READ_SYSREG(SCTLR_EL1);
    register_t tcr = READ_SYSREG(TCR_EL1);
    unsigned int _perms;

    /* We assume that the domain is running on the currently active domain. */
    if ( v != current )
        return false;

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
    if ( !(sctlr & SCTLR_Axx_ELx_M) )
    {
        *ipa = gva;

        /* Memory can be accessed without any restrictions. */
        *perms = GV2M_READ|GV2M_WRITE|GV2M_EXEC;

        return true;
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
