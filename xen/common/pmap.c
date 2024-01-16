#include <xen/bitops.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/pmap.h>

#include <asm/pmap.h>
#include <asm/fixmap.h>

/*
 * Simple mapping infrastructure to map / unmap pages in fixed map.
 * This is used to set the page table before the map domain page infrastructure
 * is initialized.
 *
 * This structure is not protected by any locks, so it must not be used after
 * smp bring-up.
 */

/* Bitmap to track which slot is used */
static __initdata DECLARE_BITMAP(inuse, NUM_FIX_PMAP);

void *__init pmap_map(mfn_t mfn)
{
    unsigned int idx;
    unsigned int slot;

    ASSERT(system_state < SYS_STATE_smp_boot);
    ASSERT(!in_irq());

    idx = find_first_zero_bit(inuse, NUM_FIX_PMAP);
    if ( idx == NUM_FIX_PMAP )
        panic("Out of PMAP slots\n");

    __set_bit(idx, inuse);

    slot = idx + FIX_PMAP_BEGIN;
    ASSERT(slot >= FIX_PMAP_BEGIN && slot <= FIX_PMAP_END);

    /*
     * We cannot use set_fixmap() here. We use PMAP when the domain map
     * page infrastructure is not yet initialized, so map_pages_to_xen() called
     * by set_fixmap() needs to map pages on demand, which then calls pmap()
     * again, resulting in a loop. Modify the PTEs directly instead. The same
     * is true for pmap_unmap().
     */
    arch_pmap_map(slot, mfn);

    return fix_to_virt(slot);
}

void __init pmap_unmap(const void *p)
{
    unsigned int idx;
    unsigned int slot = virt_to_fix((unsigned long)p);

    ASSERT(system_state < SYS_STATE_smp_boot);
    ASSERT(slot >= FIX_PMAP_BEGIN && slot <= FIX_PMAP_END);
    ASSERT(!in_irq());

    idx = slot - FIX_PMAP_BEGIN;

    __clear_bit(idx, inuse);
    arch_pmap_unmap(slot);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
