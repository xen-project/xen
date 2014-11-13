#include <xen/efi.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>

#ifndef efi_enabled
const bool_t efi_enabled = 0;
#endif

void __init efi_init_memory(void) { }

paddr_t efi_rs_page_table(void)
{
    BUG();
    return 0;
}

unsigned long efi_get_time(void)
{
    BUG();
    return 0;
}

void efi_halt_system(void) { }
void efi_reset_system(bool_t warm) { }

int efi_get_info(uint32_t idx, union xenpf_efi_info *info)
{
    return -ENOSYS;
}

int efi_compat_get_info(uint32_t idx, union compat_pf_efi_info *)
    __attribute__((__alias__("efi_get_info")));

int efi_runtime_call(struct xenpf_efi_runtime_call *op)
{
    return -ENOSYS;
}

int efi_compat_runtime_call(struct compat_pf_efi_runtime_call *)
    __attribute__((__alias__("efi_runtime_call")));
