#ifndef __ASM_APIC_H
#define __ASM_APIC_H

#include <asm/apicdef.h>
#include <asm/fixmap.h>
#include <asm/msr.h>

#define Dprintk(x...) do {} while (0)

/*
 * Debugging macros
 */
#define APIC_QUIET   0
#define APIC_VERBOSE 1
#define APIC_DEBUG   2

#define	SET_APIC_LOGICAL_ID(x)	(((x)<<24))

/* Possible APIC states */
enum apic_mode {
    APIC_MODE_INVALID,  /* Not set yet */
    APIC_MODE_DISABLED, /* If uniprocessor, or MP in uniprocessor mode */
    APIC_MODE_XAPIC,    /* xAPIC mode - default upon chipset reset */
    APIC_MODE_X2APIC    /* x2APIC mode - common for large MP machines */
};

extern bool iommu_x2apic_enabled;
extern u8 apic_verbosity;
extern bool directed_eoi_enabled;

void check_x2apic_preenabled(void);
void x2apic_bsp_setup(void);
void x2apic_ap_setup(void);
const struct genapic *apic_x2apic_probe(void);

/*
 * Define the default level of output to be very little
 * This can be turned up by using apic=verbose for more
 * information and apic=debug for _lots_ of information.
 * apic_verbosity is defined in apic.c
 */
#define apic_printk(v, s, a...) do {       \
		if ((v) <= apic_verbosity) \
			printk(s, ##a);    \
	} while (0)


/*
 * Basic functions accessing APICs.
 */

static inline void apic_mem_write(unsigned long reg, u32 v)
{
	*((volatile u32 *)(APIC_BASE+reg)) = v;
}

static inline u32 apic_mem_read(unsigned long reg)
{
	return *((volatile u32 *)(APIC_BASE+reg));
}

/* NOTE: in x2APIC mode, we should use apic_icr_write()/apic_icr_read() to
 * access the 64-bit ICR register.
 */

static inline void apic_wrmsr(unsigned long reg, uint64_t msr_content)
{
    if (reg == APIC_DFR || reg == APIC_ID || reg == APIC_LDR ||
        reg == APIC_LVR)
        return;

    wrmsrl(MSR_X2APIC_FIRST + (reg >> 4), msr_content);
}

static inline uint64_t apic_rdmsr(unsigned long reg)
{
    uint64_t msr_content;

    if (reg == APIC_DFR)
        return -1u;

    rdmsrl(MSR_X2APIC_FIRST + (reg >> 4), msr_content);
    return msr_content;
}

static inline void apic_write(unsigned long reg, u32 v)
{

    if ( x2apic_enabled )
        apic_wrmsr(reg, v);
    else
        apic_mem_write(reg, v);
}

static inline u32 apic_read(unsigned long reg)
{
    if ( x2apic_enabled )
        return apic_rdmsr(reg);
    else
        return apic_mem_read(reg);
}

static inline u64 apic_icr_read(void)
{
    u32 lo, hi;

    if ( x2apic_enabled )
        return apic_rdmsr(APIC_ICR);
    else
    {
        lo = apic_mem_read(APIC_ICR);
        hi = apic_mem_read(APIC_ICR2);
    }
    
    return ((u64)lo) | (((u64)hi) << 32);
}

static inline void apic_icr_write(u32 low, u32 dest)
{
    if ( x2apic_enabled )
        apic_wrmsr(APIC_ICR, low | ((uint64_t)dest << 32));
    else
    {
        apic_mem_write(APIC_ICR2, dest << 24);
        apic_mem_write(APIC_ICR, low);
    }
}

static inline bool apic_isr_read(uint8_t vector)
{
    return (apic_read(APIC_ISR + ((vector & ~0x1f) >> 1)) >>
            (vector & 0x1f)) & 1;
}

static inline bool apic_irr_read(unsigned int vector)
{
    return apic_read(APIC_IRR + (vector / 32 * 0x10)) & (1U << (vector % 32));
}

static inline u32 get_apic_id(void)
{
    u32 id = apic_read(APIC_ID);
    return x2apic_enabled ? id : GET_xAPIC_ID(id);
}

void apic_wait_icr_idle(void);

int get_physical_broadcast(void);

static inline void ack_APIC_irq(void)
{
	/* Docs say use 0 for future compatibility */
	apic_write(APIC_EOI, 0);
}

extern int get_maxlvt(void);
extern void clear_local_APIC(void);
extern void connect_bsp_APIC (void);
extern void disconnect_bsp_APIC (int virt_wire_setup);
extern void disable_local_APIC (void);
extern int verify_local_APIC (void);
extern void cache_APIC_registers (void);
extern void sync_Arb_IDs (void);
extern void init_bsp_APIC (void);
extern void setup_local_APIC(bool bsp);
extern void init_apic_mappings (void);
extern void smp_local_timer_interrupt (struct cpu_user_regs *regs);
extern void setup_boot_APIC_clock (void);
extern void setup_secondary_APIC_clock (void);
extern void setup_apic_nmi_watchdog (void);
extern void disable_lapic_nmi_watchdog(void);
extern int reserve_lapic_nmi(void);
extern void release_lapic_nmi(void);
extern void self_nmi(void);
extern void disable_timer_nmi_watchdog(void);
extern void enable_timer_nmi_watchdog(void);
extern bool nmi_watchdog_tick(const struct cpu_user_regs *regs);
extern int APIC_init_uniprocessor (void);
extern void disable_APIC_timer(void);
extern void enable_APIC_timer(void);
extern int lapic_suspend(void);
extern int lapic_resume(void);
extern void record_boot_APIC_mode(void);
extern enum apic_mode current_local_apic_mode(void);
extern void check_for_unexpected_msi(unsigned int vector);

uint64_t calibrate_apic_timer(void);
uint32_t apic_tmcct_read(void);

extern void check_nmi_watchdog(void);

extern unsigned int nmi_watchdog;
#define NMI_NONE	0
#define NMI_LOCAL_APIC	1

#endif /* __ASM_APIC_H */
