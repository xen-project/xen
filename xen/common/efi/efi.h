#include <asm/efibind.h>
#include <efi/efidef.h>
#include <efi/efierr.h>
#include <efi/eficon.h>
#include <efi/efidevp.h>
#include <efi/eficapsule.h>
#include <efi/efiapi.h>
#include <xen/efi.h>
#include <xen/spinlock.h>
#include <asm/page.h>

struct efi_pci_rom {
    const struct efi_pci_rom *next;
    u16 vendor, devid, segment;
    u8 bus, devfn;
    unsigned long size;
    unsigned char data[];
};

extern unsigned int efi_num_ct;
extern const EFI_CONFIGURATION_TABLE *efi_ct;

extern unsigned int efi_version, efi_fw_revision;
extern const CHAR16 *efi_fw_vendor;

extern const EFI_RUNTIME_SERVICES *efi_rs;

extern UINTN efi_memmap_size, efi_mdesc_size;
extern void *efi_memmap;

#ifdef CONFIG_X86
extern l4_pgentry_t *efi_l4_pgtable;
#endif

extern const struct efi_pci_rom *efi_pci_roms;

extern UINT64 efi_boot_max_var_store_size, efi_boot_remain_var_store_size,
              efi_boot_max_var_size;

unsigned long efi_rs_enter(void);
void efi_rs_leave(unsigned long);
