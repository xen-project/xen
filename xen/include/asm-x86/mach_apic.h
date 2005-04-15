/*
 *  based on linux-2.6.10/include/asm-i386/mach-default/mach_apic.h
 *
 */
#ifndef __ASM_MACH_APIC_H
#define __ASM_MACH_APIC_H

#define APIC_DFR_VALUE    (APIC_DFR_FLAT)
#define esr_disable (0)

/*
 * Set up the logical destination ID.
 *
 * Intel recommends to set DFR, LDR and TPR before enabling
 * an APIC.  See e.g. "AP-388 82489DX User's Manual" (Intel
 * document number 292116).  So here it goes...
 */
static inline void init_apic_ldr(void)
{
    unsigned long val;

    apic_write_around(APIC_DFR, APIC_DFR_VALUE);
    val = apic_read(APIC_LDR) & ~APIC_LDR_MASK;
    val |= SET_APIC_LOGICAL_ID(1UL << smp_processor_id());
    apic_write_around(APIC_LDR, val);
}

static inline int apic_id_registered(void)
{
    return test_bit(GET_APIC_ID(apic_read(APIC_ID)), &phys_cpu_present_map);
}
#endif /* __ASM_MACH_APIC_H */
