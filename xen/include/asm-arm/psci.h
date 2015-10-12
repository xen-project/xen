#ifndef __ASM_PSCI_H__
#define __ASM_PSCI_H__

/* PSCI return values (inclusive of all PSCI versions) */
#define PSCI_SUCCESS                 0
#define PSCI_NOT_SUPPORTED          -1
#define PSCI_INVALID_PARAMETERS     -2
#define PSCI_DENIED                 -3
#define PSCI_ALREADY_ON             -4
#define PSCI_ON_PENDING             -5
#define PSCI_INTERNAL_FAILURE       -6
#define PSCI_NOT_PRESENT            -7
#define PSCI_DISABLED               -8

/* availability of PSCI on the host for SMP bringup */
extern uint32_t psci_ver;

int psci_init(void);
int call_psci_cpu_on(int cpu);
void call_psci_system_off(void);
void call_psci_system_reset(void);

/* functions to handle guest PSCI requests */
int32_t do_psci_cpu_on(uint32_t vcpuid, register_t entry_point);
int32_t do_psci_cpu_off(uint32_t power_state);
int32_t do_psci_cpu_suspend(uint32_t power_state, register_t entry_point);
int32_t do_psci_migrate(uint32_t vcpuid);

/* PSCI 0.2 functions to handle guest PSCI requests */
uint32_t do_psci_0_2_version(void);
register_t do_psci_0_2_cpu_suspend(uint32_t power_state, register_t entry_point,
                            register_t context_id);
int32_t do_psci_0_2_cpu_off(void);
int32_t do_psci_0_2_cpu_on(register_t target_cpu, register_t entry_point,
                       register_t context_id);
int32_t do_psci_0_2_affinity_info(register_t target_affinity,
                              uint32_t lowest_affinity_level);
int32_t do_psci_0_2_migrate(uint32_t target_cpu);
uint32_t do_psci_0_2_migrate_info_type(void);
register_t do_psci_0_2_migrate_info_up_cpu(void);
void do_psci_0_2_system_off(void);
void do_psci_0_2_system_reset(void);

/* PSCI v0.2 interface */
#define PSCI_0_2_FN_BASE        0x84000000
#define PSCI_0_2_FN(n)          (PSCI_0_2_FN_BASE + (n))
#define PSCI_0_2_64BIT          0x40000000
#define PSCI_0_2_FN64_BASE      \
                        (PSCI_0_2_FN_BASE + PSCI_0_2_64BIT)
#define PSCI_0_2_FN64(n)        (PSCI_0_2_FN64_BASE + (n))

#define PSCI_0_2_FN_PSCI_VERSION        PSCI_0_2_FN(0)
#define PSCI_0_2_FN_CPU_SUSPEND         PSCI_0_2_FN(1)
#define PSCI_0_2_FN_CPU_OFF             PSCI_0_2_FN(2)
#define PSCI_0_2_FN_CPU_ON              PSCI_0_2_FN(3)
#define PSCI_0_2_FN_AFFINITY_INFO       PSCI_0_2_FN(4)
#define PSCI_0_2_FN_MIGRATE             PSCI_0_2_FN(5)
#define PSCI_0_2_FN_MIGRATE_INFO_TYPE   PSCI_0_2_FN(6)
#define PSCI_0_2_FN_MIGRATE_INFO_UP_CPU PSCI_0_2_FN(7)
#define PSCI_0_2_FN_SYSTEM_OFF          PSCI_0_2_FN(8)
#define PSCI_0_2_FN_SYSTEM_RESET        PSCI_0_2_FN(9)

#define PSCI_0_2_FN64_CPU_SUSPEND       PSCI_0_2_FN64(1)
#define PSCI_0_2_FN64_CPU_ON            PSCI_0_2_FN64(3)
#define PSCI_0_2_FN64_AFFINITY_INFO     PSCI_0_2_FN64(4)
#define PSCI_0_2_FN64_MIGRATE           PSCI_0_2_FN64(5)
#define PSCI_0_2_FN64_MIGRATE_INFO_UP_CPU   PSCI_0_2_FN64(7)

/* PSCI v0.2 affinity level state returned by AFFINITY_INFO */
#define PSCI_0_2_AFFINITY_LEVEL_ON      0
#define PSCI_0_2_AFFINITY_LEVEL_OFF     1
#define PSCI_0_2_AFFINITY_LEVEL_ON_PENDING  2

/* PSCI v0.2 multicore support in Trusted OS returned by MIGRATE_INFO_TYPE */
#define PSCI_0_2_TOS_UP_MIGRATE_CAPABLE          0
#define PSCI_0_2_TOS_UP_NOT_MIGRATE_CAPABLE      1
#define PSCI_0_2_TOS_MP_OR_NOT_PRESENT           2

/* PSCI v0.2 power state encoding for CPU_SUSPEND function */
#define PSCI_0_2_POWER_STATE_ID_MASK        0xffff
#define PSCI_0_2_POWER_STATE_ID_SHIFT       0
#define PSCI_0_2_POWER_STATE_TYPE_SHIFT     16
#define PSCI_0_2_POWER_STATE_TYPE_MASK      \
                    (0x1 << PSCI_0_2_POWER_STATE_TYPE_SHIFT)

/* PSCI version decoding (independent of PSCI version) */
#define PSCI_VERSION_MAJOR_SHIFT            16
#define PSCI_VERSION_MINOR_MASK             \
        ((1U << PSCI_VERSION_MAJOR_SHIFT) - 1)
#define PSCI_VERSION_MAJOR_MASK             ~PSCI_VERSION_MINOR_MASK
#define PSCI_VERSION_MAJOR(ver)             \
        (((ver) & PSCI_VERSION_MAJOR_MASK) >> PSCI_VERSION_MAJOR_SHIFT)
#define PSCI_VERSION_MINOR(ver)             \
        ((ver) & PSCI_VERSION_MINOR_MASK)

#define PSCI_VERSION(major, minor)          \
    (((major) << PSCI_VERSION_MAJOR_SHIFT) | (minor))

#endif /* __ASM_PSCI_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
