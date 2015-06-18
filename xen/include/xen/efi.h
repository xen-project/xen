#ifndef __XEN_EFI_H__
#define __XEN_EFI_H__

#ifndef __ASSEMBLY__
#include <xen/types.h>
#endif

extern const bool_t efi_enabled;

#define EFI_INVALID_TABLE_ADDR (~0UL)

/* Add fields here only if they need to be referenced from non-EFI code. */
struct efi {
    unsigned long mps;          /* MPS table */
    unsigned long acpi;         /* ACPI table (IA64 ext 0.71) */
    unsigned long acpi20;       /* ACPI table (ACPI 2.0) */
    unsigned long smbios;       /* SM BIOS table */
};

extern struct efi efi;

#ifndef __ASSEMBLY__

union xenpf_efi_info;
union compat_pf_efi_info;

struct xenpf_efi_runtime_call;
struct compat_pf_efi_runtime_call;

void efi_init_memory(void);
bool_t efi_rs_using_pgtables(void);
unsigned long efi_get_time(void);
void efi_halt_system(void);
void efi_reset_system(bool_t warm);
#ifndef COMPAT
int efi_get_info(uint32_t idx, union xenpf_efi_info *);
int efi_runtime_call(struct xenpf_efi_runtime_call *);
#endif
int efi_compat_get_info(uint32_t idx, union compat_pf_efi_info *);
int efi_compat_runtime_call(struct compat_pf_efi_runtime_call *);

#endif /* !__ASSEMBLY__ */

#endif /* __XEN_EFI_H__ */
