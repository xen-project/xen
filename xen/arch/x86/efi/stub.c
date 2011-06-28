#include <xen/efi.h>
#include <xen/errno.h>
#include <xen/init.h>

#ifndef efi_enabled
const bool_t efi_enabled = 0;
#endif

void __init efi_init_memory(void) { }

int efi_get_info(uint32_t idx, union xenpf_efi_info *info)
{
    return -ENOSYS;
}

int efi_compat_get_info(uint32_t idx, union compat_pf_efi_info *)
    __attribute__((__alias__("efi_get_info")));
