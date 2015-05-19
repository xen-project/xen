#include <asm/atomic.h>
#include <asm/mc146818rtc.h>

#ifndef COMPAT
l4_pgentry_t *__read_mostly efi_l4_pgtable;

void efi_update_l4_pgtable(unsigned int l4idx, l4_pgentry_t l4e)
{
    if ( efi_l4_pgtable )
        l4e_write(efi_l4_pgtable + l4idx, l4e);
}
#endif
