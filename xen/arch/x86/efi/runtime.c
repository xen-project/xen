#include "efi.h"
#include <xen/cache.h>
#include <xen/errno.h>
#include <xen/guest_access.h>

DEFINE_XEN_GUEST_HANDLE(CHAR16);

#ifndef COMPAT

# include <public/platform.h>

const bool_t efi_enabled = 1;

unsigned int __read_mostly efi_num_ct;
EFI_CONFIGURATION_TABLE *__read_mostly efi_ct;

unsigned int __read_mostly efi_version;
unsigned int __read_mostly efi_fw_revision;
const CHAR16 *__read_mostly efi_fw_vendor;

EFI_RUNTIME_SERVICES *__read_mostly efi_rs;

UINTN __read_mostly efi_memmap_size;
UINTN __read_mostly efi_mdesc_size;
void *__read_mostly efi_memmap;

struct efi __read_mostly efi = {
	.acpi   = EFI_INVALID_TABLE_ADDR,
	.acpi20 = EFI_INVALID_TABLE_ADDR,
	.smbios = EFI_INVALID_TABLE_ADDR,
};

#endif

int efi_get_info(uint32_t idx, union xenpf_efi_info *info)
{
    unsigned int i, n;

    switch ( idx )
    {
    case XEN_FW_EFI_VERSION:
        info->version = efi_version;
        break;
    case XEN_FW_EFI_CONFIG_TABLE:
        info->cfg.addr = __pa(efi_ct);
        info->cfg.nent = efi_num_ct;
        break;
    case XEN_FW_EFI_VENDOR:
        info->vendor.revision = efi_fw_revision;
        n = info->vendor.bufsz / sizeof(*efi_fw_vendor);
        if ( !guest_handle_okay(guest_handle_cast(info->vendor.name,
                                                  CHAR16), n) )
            return -EFAULT;
        for ( i = 0; i < n; ++i )
        {
            if ( __copy_to_guest_offset(info->vendor.name, i,
                                        efi_fw_vendor + i, 1) )
                return -EFAULT;
            if ( !efi_fw_vendor[i] )
                break;
        }
        break;
    case XEN_FW_EFI_MEM_INFO:
        for ( i = 0; i < efi_memmap_size; i += efi_mdesc_size )
        {
            EFI_MEMORY_DESCRIPTOR *desc = efi_memmap + i;
            u64 len = desc->NumberOfPages << EFI_PAGE_SHIFT;

            if ( info->mem.addr >= desc->PhysicalStart &&
                 info->mem.addr < desc->PhysicalStart + len )
            {
                info->mem.type = desc->Type;
                info->mem.attr = desc->Attribute;
                if ( info->mem.addr + info->mem.size < info->mem.addr ||
                     info->mem.addr + info->mem.size >
                     desc->PhysicalStart + len )
                    info->mem.size = desc->PhysicalStart + len -
                                     info->mem.addr;
                return 0;
            }
        }
        return -ESRCH;
    default:
        return -EINVAL;
    }

    return 0;
}
