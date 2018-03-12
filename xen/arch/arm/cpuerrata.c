#include <xen/cpumask.h>
#include <xen/mm.h>
#include <xen/sizes.h>
#include <xen/smp.h>
#include <xen/spinlock.h>
#include <xen/vmap.h>
#include <xen/warning.h>
#include <asm/cpufeature.h>
#include <asm/cpuerrata.h>
#include <asm/psci.h>

/* Override macros from asm/page.h to make them work with mfn_t */
#undef virt_to_mfn
#define virt_to_mfn(va) _mfn(__virt_to_mfn(va))

/* Hardening Branch predictor code for Arm64 */
#ifdef CONFIG_ARM64_HARDEN_BRANCH_PREDICTOR

#define VECTOR_TABLE_SIZE SZ_2K

/*
 * Number of available table vectors (this should be in-sync with
 * arch/arm64/bpi.S
 */
#define NR_BPI_HYP_VECS 4

extern char __bp_harden_hyp_vecs_start[], __bp_harden_hyp_vecs_end[];

/*
 * Key for each slot. This is used to find whether a specific workaround
 * had a slot assigned.
 *
 * The key is virtual address of the vector workaround
 */
static uintptr_t bp_harden_slot_key[NR_BPI_HYP_VECS];

/*
 * [hyp_vec_start, hyp_vec_end[ corresponds to the first 31 instructions
 * of each vector. The last (i.e 32th) instruction is used to branch to
 * the original entry.
 *
 * Those instructions will be copied on each vector to harden them.
 */
static bool copy_hyp_vect_bpi(unsigned int slot, const char *hyp_vec_start,
                              const char *hyp_vec_end)
{
    void *dst_remapped;
    const void *dst = __bp_harden_hyp_vecs_start + slot * VECTOR_TABLE_SIZE;
    unsigned int i;
    mfn_t dst_mfn = virt_to_mfn(dst);

    BUG_ON(((hyp_vec_end - hyp_vec_start) / 4) > 31);

    /*
     * Vectors are part of the text that are mapped read-only. So re-map
     * the vector table to be able to update vectors.
     */
    dst_remapped = __vmap(&dst_mfn,
                          1UL << get_order_from_bytes(VECTOR_TABLE_SIZE),
                          1, 1, PAGE_HYPERVISOR, VMAP_DEFAULT);
    if ( !dst_remapped )
        return false;

    dst_remapped += (vaddr_t)dst & ~PAGE_MASK;

    for ( i = 0; i < VECTOR_TABLE_SIZE; i += 0x80 )
    {
        memcpy(dst_remapped + i, hyp_vec_start, hyp_vec_end - hyp_vec_start);
    }

    clean_dcache_va_range(dst_remapped, VECTOR_TABLE_SIZE);
    invalidate_icache();

    vunmap(dst_remapped);

    return true;
}

static bool __maybe_unused
install_bp_hardening_vec(const struct arm_cpu_capabilities *entry,
                         const char *hyp_vec_start,
                         const char *hyp_vec_end,
                         const char *desc)
{
    static int last_slot = -1;
    static DEFINE_SPINLOCK(bp_lock);
    unsigned int i, slot = -1;
    bool ret = true;

    /*
     * Enable callbacks are called on every CPU based on the
     * capabilities. So double-check whether the CPU matches the
     * entry.
     */
    if ( !entry->matches(entry) )
        return true;

    printk(XENLOG_INFO "CPU%u will %s on exception entry\n",
           smp_processor_id(), desc);

    /*
     * No need to install hardened vector when the processor has
     * ID_AA64PRF0_EL1.CSV2 set.
     */
    if ( cpu_data[smp_processor_id()].pfr64.csv2 )
        return true;

    spin_lock(&bp_lock);

    /*
     * Look up whether the hardening vector had a slot already
     * assigned.
     */
    for ( i = 0; i < 4; i++ )
    {
        if ( bp_harden_slot_key[i] == (uintptr_t)hyp_vec_start )
        {
            slot = i;
            break;
        }
    }

    if ( slot == -1 )
    {
        last_slot++;
        /* Check we don't overrun the number of slots available. */
        BUG_ON(NR_BPI_HYP_VECS <= last_slot);

        slot = last_slot;
        ret = copy_hyp_vect_bpi(slot, hyp_vec_start, hyp_vec_end);

        /* Only update the slot if the copy succeeded. */
        if ( ret )
            bp_harden_slot_key[slot] = (uintptr_t)hyp_vec_start;
    }

    if ( ret )
    {
        /* Install the new vector table. */
        WRITE_SYSREG((vaddr_t)(__bp_harden_hyp_vecs_start + slot * VECTOR_TABLE_SIZE),
                     VBAR_EL2);
        isb();
    }

    spin_unlock(&bp_lock);

    return ret;
}

extern char __smccc_workaround_1_smc_start[], __smccc_workaround_1_smc_end[];

static int enable_smccc_arch_workaround_1(void *data)
{
    struct arm_smccc_res res;
    static bool warned = false;
    const struct arm_cpu_capabilities *entry = data;

    /*
     * Enable callbacks are called on every CPU based on the
     * capabilities. So double-check whether the CPU matches the
     * entry.
     */
    if ( !entry->matches(entry) )
        return 0;

    if ( smccc_ver < SMCCC_VERSION(1, 1) )
        goto warn;

    arm_smccc_1_1_smc(ARM_SMCCC_ARCH_FEATURES_FID,
                      ARM_SMCCC_ARCH_WORKAROUND_1_FID, &res);
    /* The return value is in the lower 32-bits. */
    if ( (int)res.a0 < 0 )
        goto warn;

    return !install_bp_hardening_vec(entry,__smccc_workaround_1_smc_start,
                                     __smccc_workaround_1_smc_end,
                                     "call ARM_SMCCC_ARCH_WORKAROUND_1");

warn:
    if ( !warned )
    {
        ASSERT(system_state < SYS_STATE_active);
        warning_add("No support for ARM_SMCCC_ARCH_WORKAROUND_1.\n"
                    "Please update your firmware.\n");
        warned = false;
    }

    return 0;
}

#endif /* CONFIG_ARM64_HARDEN_BRANCH_PREDICTOR */

/* Hardening Branch predictor code for Arm32 */
#ifdef CONFIG_ARM32_HARDEN_BRANCH_PREDICTOR

/*
 * Per-CPU vector tables to use when returning to the guests. They will
 * only be used on platform requiring to harden the branch predictor.
 */
DEFINE_PER_CPU_READ_MOSTLY(const char *, bp_harden_vecs);

extern char hyp_traps_vector_bp_inv[];
extern char hyp_traps_vector_ic_inv[];

static void __maybe_unused
install_bp_hardening_vecs(const struct arm_cpu_capabilities *entry,
                          const char *hyp_vecs, const char *desc)
{
    /*
     * Enable callbacks are called on every CPU based on the
     * capabilities. So double-check whether the CPU matches the
     * entry.
     */
    if ( !entry->matches(entry) )
        return;

    printk(XENLOG_INFO "CPU%u will %s on guest exit\n",
           smp_processor_id(), desc);
    this_cpu(bp_harden_vecs) = hyp_vecs;
}

static int enable_bp_inv_hardening(void *data)
{
    install_bp_hardening_vecs(data, hyp_traps_vector_bp_inv,
                              "execute BPIALL");
    return 0;
}

static int enable_ic_inv_hardening(void *data)
{
    install_bp_hardening_vecs(data, hyp_traps_vector_ic_inv,
                              "execute ICIALLU");
    return 0;
}

#endif

#define MIDR_RANGE(model, min, max)     \
    .matches = is_affected_midr_range,  \
    .midr_model = model,                \
    .midr_range_min = min,              \
    .midr_range_max = max

#define MIDR_ALL_VERSIONS(model)        \
    .matches = is_affected_midr_range,  \
    .midr_model = model,                \
    .midr_range_min = 0,                \
    .midr_range_max = (MIDR_VARIANT_MASK | MIDR_REVISION_MASK)

static bool __maybe_unused
is_affected_midr_range(const struct arm_cpu_capabilities *entry)
{
    return MIDR_IS_CPU_MODEL_RANGE(current_cpu_data.midr.bits, entry->midr_model,
                                   entry->midr_range_min,
                                   entry->midr_range_max);
}

static const struct arm_cpu_capabilities arm_errata[] = {
    {
        /* Cortex-A15 r0p4 */
        .desc = "ARM erratum 766422",
        .capability = ARM32_WORKAROUND_766422,
        MIDR_RANGE(MIDR_CORTEX_A15, 0x04, 0x04),
    },
#if defined(CONFIG_ARM64_ERRATUM_827319) || \
    defined(CONFIG_ARM64_ERRATUM_824069)
    {
        /* Cortex-A53 r0p[012] */
        .desc = "ARM errata 827319, 824069",
        .capability = ARM64_WORKAROUND_CLEAN_CACHE,
        MIDR_RANGE(MIDR_CORTEX_A53, 0x00, 0x02),
    },
#endif
#ifdef CONFIG_ARM64_ERRATUM_819472
    {
        /* Cortex-A53 r0[01] */
        .desc = "ARM erratum 819472",
        .capability = ARM64_WORKAROUND_CLEAN_CACHE,
        MIDR_RANGE(MIDR_CORTEX_A53, 0x00, 0x01),
    },
#endif
#ifdef CONFIG_ARM64_ERRATUM_832075
    {
        /* Cortex-A57 r0p0 - r1p2 */
        .desc = "ARM erratum 832075",
        .capability = ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE,
        MIDR_RANGE(MIDR_CORTEX_A57, 0x00,
                   (1 << MIDR_VARIANT_SHIFT) | 2),
    },
#endif
#ifdef CONFIG_ARM64_ERRATUM_834220
    {
        /* Cortex-A57 r0p0 - r1p2 */
        .desc = "ARM erratum 834220",
        .capability = ARM64_WORKAROUND_834220,
        MIDR_RANGE(MIDR_CORTEX_A57, 0x00,
                   (1 << MIDR_VARIANT_SHIFT) | 2),
    },
#endif
#ifdef CONFIG_ARM64_HARDEN_BRANCH_PREDICTOR
    {
        .capability = ARM_HARDEN_BRANCH_PREDICTOR,
        MIDR_ALL_VERSIONS(MIDR_CORTEX_A57),
        .enable = enable_smccc_arch_workaround_1,
    },
    {
        .capability = ARM_HARDEN_BRANCH_PREDICTOR,
        MIDR_ALL_VERSIONS(MIDR_CORTEX_A72),
        .enable = enable_smccc_arch_workaround_1,
    },
    {
        .capability = ARM_HARDEN_BRANCH_PREDICTOR,
        MIDR_ALL_VERSIONS(MIDR_CORTEX_A73),
        .enable = enable_smccc_arch_workaround_1,
    },
    {
        .capability = ARM_HARDEN_BRANCH_PREDICTOR,
        MIDR_ALL_VERSIONS(MIDR_CORTEX_A75),
        .enable = enable_smccc_arch_workaround_1,
    },
#endif
#ifdef CONFIG_ARM32_HARDEN_BRANCH_PREDICTOR
    {
        .capability = ARM_HARDEN_BRANCH_PREDICTOR,
        MIDR_ALL_VERSIONS(MIDR_CORTEX_A12),
        .enable = enable_bp_inv_hardening,
    },
    {
        .capability = ARM_HARDEN_BRANCH_PREDICTOR,
        MIDR_ALL_VERSIONS(MIDR_CORTEX_A17),
        .enable = enable_bp_inv_hardening,
    },
    {
        .capability = ARM_HARDEN_BRANCH_PREDICTOR,
        MIDR_ALL_VERSIONS(MIDR_CORTEX_A15),
        .enable = enable_ic_inv_hardening,
    },
#endif
    {},
};

void check_local_cpu_errata(void)
{
    update_cpu_capabilities(arm_errata, "enabled workaround for");
}

void __init enable_errata_workarounds(void)
{
    enable_cpu_capabilities(arm_errata);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
