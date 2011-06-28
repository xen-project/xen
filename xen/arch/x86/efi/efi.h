#include <asm/efibind.h>
#include <efi/efidef.h>
#include <efi/efierr.h>
#include <efi/eficon.h>
#include <efi/efidevp.h>
#include <efi/efiapi.h>
#include <xen/efi.h>

extern unsigned int efi_num_ct;
extern EFI_CONFIGURATION_TABLE *efi_ct;

extern unsigned int efi_version, efi_fw_revision;
extern const CHAR16 *efi_fw_vendor;

extern EFI_RUNTIME_SERVICES *efi_rs;

extern UINTN efi_memmap_size, efi_mdesc_size;
extern void *efi_memmap;
