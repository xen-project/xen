#include <xen/domain_page.h>
#include <xen/mm.h>
#include <asm/atomic.h>
#include <asm/mc146818rtc.h>

#ifndef COMPAT
mfn_t __read_mostly efi_l4_mfn = INVALID_MFN_INITIALIZER;

void efi_update_l4_pgtable(unsigned int l4idx, l4_pgentry_t l4e)
{
    if ( !mfn_eq(efi_l4_mfn, INVALID_MFN) )
    {
        l4_pgentry_t *efi_l4t = map_domain_page(efi_l4_mfn);

        l4e_write(efi_l4t + l4idx, l4e);
        unmap_domain_page(efi_l4t);
    }
}
#endif
