#ifndef __ASM_PSCI_H__
#define __ASM_PSCI_H__

#define PSCI_SUCCESS  0
#define PSCI_ENOSYS  -1
#define PSCI_EINVAL  -2
#define PSCI_DENIED  -3

int do_psci_cpu_on(uint32_t vcpuid, register_t entry_point);
int do_psci_cpu_off(uint32_t power_state);
int do_psci_cpu_suspend(uint32_t power_state, register_t entry_point);
int do_psci_migrate(uint32_t vcpuid);

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
