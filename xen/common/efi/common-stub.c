#include <xen/bug.h>
#include <xen/efi.h>
#include <xen/errno.h>

bool efi_enabled(unsigned int feature)
{
    return false;
}

bool efi_rs_using_pgtables(void)
{
    return false;
}

unsigned long efi_get_time(void)
{
    BUG();
    return 0;
}

void efi_halt_system(void) { }
void efi_reset_system(bool warm) { }

int efi_get_info(uint32_t idx, union xenpf_efi_info *info)
{
    return -ENOSYS;
}

int efi_runtime_call(struct xenpf_efi_runtime_call *op)
{
    return -ENOSYS;
}

#ifdef CONFIG_COMPAT

int efi_compat_get_info(uint32_t idx, union compat_pf_efi_info *)
    __attribute__((__alias__("efi_get_info")));

int efi_compat_runtime_call(struct compat_pf_efi_runtime_call *)
    __attribute__((__alias__("efi_runtime_call")));

#endif
