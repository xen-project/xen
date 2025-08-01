#ifndef __XEN_EFI_H__
#define __XEN_EFI_H__

#include <xen/types.h>

#define EFI_INVALID_TABLE_ADDR (~0UL)

extern unsigned int efi_flags;
#define EFI_BOOT	0	/* Were we booted from EFI? */
#define EFI_LOADER	1	/* Were we booted directly from EFI loader? */
#define EFI_RS		2	/* Can we use runtime services? */

/* Add fields here only if they need to be referenced from non-EFI code. */
struct efi {
    unsigned long mps;          /* MPS table */
    unsigned long acpi;         /* ACPI table (IA64 ext 0.71) */
    unsigned long acpi20;       /* ACPI table (ACPI 2.0) */
    unsigned long smbios;       /* SM BIOS table */
    unsigned long smbios3;      /* SMBIOS v3 table */
};

extern struct efi efi;

union xenpf_efi_info;
union compat_pf_efi_info;

struct xenpf_efi_runtime_call;
struct compat_pf_efi_runtime_call;

#if defined(CONFIG_X86) || defined(CONFIG_ARM)
bool efi_enabled(unsigned int feature);
#else
static inline bool efi_enabled(unsigned int feature)
{
    return false;
}
#endif

void efi_init_memory(void);
bool efi_boot_mem_unused(unsigned long *start, unsigned long *end);
bool efi_rs_using_pgtables(void);
unsigned long efi_get_time(void);
void efi_halt_system(void);
void efi_reset_system(bool warm);
#ifndef COMPAT
int efi_get_info(uint32_t idx, union xenpf_efi_info *info);
int efi_runtime_call(struct xenpf_efi_runtime_call *op);
#endif
int efi_compat_get_info(uint32_t idx, union compat_pf_efi_info *info);
int efi_compat_runtime_call(struct compat_pf_efi_runtime_call *op);

#endif /* __XEN_EFI_H__ */
