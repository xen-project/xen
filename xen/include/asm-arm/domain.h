#ifndef __ASM_DOMAIN_H__
#define __ASM_DOMAIN_H__

#include <xen/cache.h>
#include <xen/sched.h>
#include <asm/page.h>
#include <asm/p2m.h>
#include <asm/vfp.h>
#include <asm/mmio.h>
#include <asm/gic.h>
#include <asm/vgic.h>
#include <asm/vpl011.h>
#include <public/hvm/params.h>
#include <xen/serial.h>
#include <xen/rbtree.h>

struct hvm_domain
{
    uint64_t              params[HVM_NR_PARAMS];
};

#ifdef CONFIG_ARM_64
enum domain_type {
    DOMAIN_32BIT,
    DOMAIN_64BIT,
};
#define is_32bit_domain(d) ((d)->arch.type == DOMAIN_32BIT)
#define is_64bit_domain(d) ((d)->arch.type == DOMAIN_64BIT)
#else
#define is_32bit_domain(d) (1)
#define is_64bit_domain(d) (0)
#endif

/* The hardware domain has always its memory direct mapped. */
#define is_domain_direct_mapped(d) ((d) == hardware_domain)

struct vtimer {
    struct vcpu *v;
    int irq;
    struct timer timer;
    uint32_t ctl;
    uint64_t cval;
};

struct arch_domain
{
#ifdef CONFIG_ARM_64
    enum domain_type type;
#endif

    /* Virtual MMU */
    struct p2m_domain p2m;

    struct hvm_domain hvm;

    struct vmmio vmmio;

    /* Continuable domain_relinquish_resources(). */
    unsigned int rel_priv;

    struct {
        uint64_t offset;
    } virt_timer_base;

    struct vgic_dist vgic;

    struct vuart {
#define VUART_BUF_SIZE 128
        char                        *buf;
        int                         idx;
        const struct vuart_info     *info;
        spinlock_t                  lock;
    } vuart;

    unsigned int evtchn_irq;
#ifdef CONFIG_ACPI
    void *efi_acpi_table;
    paddr_t efi_acpi_gpa;
    paddr_t efi_acpi_len;
#endif

    /* Monitor options */
    struct {
        uint8_t privileged_call_enabled : 1;
    } monitor;

#ifdef CONFIG_SBSA_VUART_CONSOLE
    struct vpl011 vpl011;
#endif

#ifdef CONFIG_TEE
    void *tee;
#endif
}  __cacheline_aligned;

struct arch_vcpu
{
    struct {
#ifdef CONFIG_ARM_32
        register_t r4;
        register_t r5;
        register_t r6;
        register_t r7;
        register_t r8;
        register_t r9;
        register_t sl;
#else
        register_t x19;
        register_t x20;
        register_t x21;
        register_t x22;
        register_t x23;
        register_t x24;
        register_t x25;
        register_t x26;
        register_t x27;
        register_t x28;
#endif
        register_t fp;
        register_t sp;
        register_t pc;
    } saved_context;

    void *stack;

    /*
     * Points into ->stack, more convenient than doing pointer arith
     * all the time.
     */
    struct cpu_info *cpu_info;

    /* Fault Status */
#ifdef CONFIG_ARM_32
    uint32_t dfsr;
    uint32_t dfar, ifar;
#else
    uint64_t far;
    uint32_t esr;
#endif

    uint32_t ifsr; /* 32-bit guests only */
    uint32_t afsr0, afsr1;

    /* MMU */
    register_t vbar;
    register_t ttbcr;
    uint64_t ttbr0, ttbr1;

    uint32_t dacr; /* 32-bit guests only */
    uint64_t par;
#ifdef CONFIG_ARM_32
    uint32_t mair0, mair1;
    uint32_t amair0, amair1;
#else
    uint64_t mair;
    uint64_t amair;
#endif

    /* Control Registers */
    register_t sctlr;
    uint32_t actlr;
    uint32_t cpacr;

    uint32_t contextidr;
    register_t tpidr_el0;
    register_t tpidr_el1;
    register_t tpidrro_el0;

    /* HYP configuration */
    register_t hcr_el2;

    uint32_t teecr, teehbr; /* ThumbEE, 32-bit guests only */
#ifdef CONFIG_ARM_32
    /*
     * ARMv8 only supports a trivial implementation on Jazelle when in AArch32
     * mode and therefore has no extended control registers.
     */
    uint32_t joscr, jmcr;
#endif

    /* Float-pointer */
    struct vfp_state vfp;

    /* CP 15 */
    uint32_t csselr;
    register_t vmpidr;

    /* Holds gic context data */
    union gic_state_data gic;
    uint64_t lr_mask;

    struct vgic_cpu vgic;

    /* Timer registers  */
    uint32_t cntkctl;

    struct vtimer phys_timer;
    struct vtimer virt_timer;
    bool   vtimer_initialized;

    /*
     * The full P2M may require some cleaning (e.g when emulation
     * set/way). As the action can take a long time, it requires
     * preemption. It is deferred until we return to guest, where we can
     * more easily check for softirqs and preempt the vCPU safely.
     */
    bool need_flush_to_ram;

}  __cacheline_aligned;

void vcpu_show_execution_state(struct vcpu *);
void vcpu_show_registers(const struct vcpu *);
void vcpu_switch_to_aarch64_mode(struct vcpu *);

/*
 * Due to the restriction of GICv3, the number of vCPUs in AFF0 is
 * limited to 16, thus only the first 4 bits of AFF0 are legal. We will
 * use the first 2 affinity levels here, expanding the number of vCPU up
 * to 4096(==16*256), which is more than the PEs that GIC-500 supports.
 *
 * Since we don't save information of vCPU's topology (affinity) in
 * vMPIDR at the moment, we map the vcpuid to the vMPIDR linearly.
 */
static inline unsigned int vaffinity_to_vcpuid(register_t vaff)
{
    unsigned int vcpuid;

    vaff &= MPIDR_HWID_MASK;

    vcpuid = MPIDR_AFFINITY_LEVEL(vaff, 0);
    vcpuid |= MPIDR_AFFINITY_LEVEL(vaff, 1) << 4;

    return vcpuid;
}

static inline register_t vcpuid_to_vaffinity(unsigned int vcpuid)
{
    register_t vaff;

    /*
     * Right now only AFF0 and AFF1 are supported in virtual affinity.
     * Since only the first 4 bits in AFF0 are used in GICv3, the
     * available bits are 12 (4+8).
     */
    BUILD_BUG_ON(!(MAX_VIRT_CPUS < ((1 << 12))));

    vaff = (vcpuid & 0x0f) << MPIDR_LEVEL_SHIFT(0);
    vaff |= ((vcpuid >> 4) & MPIDR_LEVEL_MASK) << MPIDR_LEVEL_SHIFT(1);

    return vaff;
}

static inline struct vcpu_guest_context *alloc_vcpu_guest_context(void)
{
    return xmalloc(struct vcpu_guest_context);
}

static inline void free_vcpu_guest_context(struct vcpu_guest_context *vgc)
{
    xfree(vgc);
}

static inline void arch_vcpu_block(struct vcpu *v) {}

#endif /* __ASM_DOMAIN_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
