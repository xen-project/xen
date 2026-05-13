/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <asm/p2m.h>

void __init setup_virt_paging(void)
{
    register_t vtcr_el2 = READ_SYSREG(VTCR_EL2);
    register_t vstcr_el2 = READ_SYSREG(VSTCR_EL2);

    /* PA size */
    const unsigned int pa_range_info[] = {32, 36, 40, 42, 44, 48, 52, 0,
                                          /* Invalid */};

    /*
     * Restrict "p2m_ipa_bits" if needed. As P2M table is always configured
     * with IPA bits == PA bits, compare against PA size.
     */
    if ( pa_range_info[system_cpuinfo.mm64.pa_range] < p2m_ipa_bits )
        p2m_ipa_bits = pa_range_info[system_cpuinfo.mm64.pa_range];

    /*
     * The MSA and MSA_frac fields in the ID_AA64MMFR0_EL1 register identify the
     * memory system configurations supported. In Armv8-R AArch64, the
     * only permitted value for ID_AA64MMFR0_EL1.MSA is 0b1111.
     */
    if ( system_cpuinfo.mm64.msa != MM64_MSA_PMSA_SUPPORT )
        goto fault;

    /* Permitted values for ID_AA64MMFR0_EL1.MSA_frac are 0b0001 and 0b0010. */
    if ( (system_cpuinfo.mm64.msa_frac != MM64_MSA_FRAC_PMSA_SUPPORT) &&
         (system_cpuinfo.mm64.msa_frac != MM64_MSA_FRAC_VMSA_SUPPORT) )
        goto fault;

    /* Stage 1 EL1&0 translation regime uses PMSAv8 by default */
    vtcr_el2 &= ~VTCR_MSA;

    /*
     * Clear VTCR_EL2.NSA bit to configure non-secure stage 2 translation output
     * address space to access the Secure PA space as Armv8-R only implements
     * secure state.
     */
    vtcr_el2 &= ~VTCR_NSA;

    /*
     * cpuinfo sanitization makes sure we support 16-bits VMID only if all cores
     * are supporting it.
     *
     * Set the VS bit only if 16 bit VMID is supported.
     */
    if ( system_cpuinfo.mm64.vmid_bits == MM64_VMID_16_BITS_SUPPORT )
    {
        vtcr_el2 |= VTCR_VS;
        max_vmid = MAX_VMID_16_BIT;
    }
    else
        vtcr_el2 &= ~VTCR_VS;

    WRITE_SYSREG(vtcr_el2, VTCR_EL2);

    p2m_vmid_allocator_init();

    /*
     * VSTCR_EL2.SA defines secure stage 2 translation output address space.
     * To make sure that all stage 2 translations for the Secure PA space access
     * the Secure PA space, we keep SA bit as 0.
     *
     * VSTCR_EL2.SC is NS check enable bit. To make sure that Stage 2 NS
     * configuration is checked against stage 1 NS configuration in EL1&0
     * translation regime for the given address, and generates a fault if they
     * are different, we set SC bit 1.
     */
    vstcr_el2 &= ~VSTCR_EL2_SA;
    vstcr_el2 |= VSTCR_EL2_SC;
    WRITE_SYSREG(vstcr_el2, VSTCR_EL2);

    printk("P2M: %u-bit IPA with %u-bit PA and %u-bit VMID\n",
           p2m_ipa_bits,
           pa_range_info[system_cpuinfo.mm64.pa_range],
           (MAX_VMID == MAX_VMID_16_BIT) ? 16 : 8);

    return;

 fault:
    panic("Hardware with no PMSAv8-64 support in any translation regime\n");
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
