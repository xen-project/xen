#include <xen/efi.h>
#include <xen/errno.h>
#include <xen/lib.h>

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
