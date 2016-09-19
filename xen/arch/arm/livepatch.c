/*
 *  Copyright (C) 2016 Citrix Systems R&D Ltd.
 */
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/livepatch_elf.h>
#include <xen/livepatch.h>
#include <xen/vmap.h>

#include <asm/livepatch.h>
#include <asm/mm.h>

void *vmap_of_xen_text;

int arch_livepatch_quiesce(void)
{
    mfn_t text_mfn;
    unsigned int text_order;

    if ( vmap_of_xen_text )
        return -EINVAL;

    text_mfn = _mfn(virt_to_mfn(_start));
    text_order = get_order_from_bytes(_end - _start);

    /*
     * The text section is read-only. So re-map Xen to be able to patch
     * the code.
     */
    vmap_of_xen_text = __vmap(&text_mfn, 1U << text_order, 1, 1, PAGE_HYPERVISOR,
                              VMAP_DEFAULT);

    if ( !vmap_of_xen_text )
    {
        printk(XENLOG_ERR LIVEPATCH "Failed to setup vmap of hypervisor! (order=%u)\n",
               text_order);
        return -ENOMEM;
    }

    return 0;
}

void arch_livepatch_revive(void)
{
    /*
     * Nuke the instruction cache. Data cache has been cleaned before in
     * arch_livepatch_[apply|revert].
     */
    invalidate_icache();

    if ( vmap_of_xen_text )
        vunmap(vmap_of_xen_text);

    vmap_of_xen_text = NULL;
}

int arch_livepatch_verify_func(const struct livepatch_func *func)
{
    /* If NOPing only do up to maximum amount we can put in the ->opaque. */
    if ( !func->new_addr && (func->new_size > sizeof(func->opaque) ||
         func->new_size % ARCH_PATCH_INSN_SIZE) )
        return -EOPNOTSUPP;

    if ( func->old_size < ARCH_PATCH_INSN_SIZE )
        return -EINVAL;

    return 0;
}

void arch_livepatch_post_action(void)
{
    /* arch_livepatch_revive has nuked the instruction cache. */
}

void arch_livepatch_mask(void)
{
    /* Mask System Error (SError) */
    local_abort_disable();
}

void arch_livepatch_unmask(void)
{
    local_abort_enable();
}

int arch_livepatch_perform_rel(struct livepatch_elf *elf,
                               const struct livepatch_elf_sec *base,
                               const struct livepatch_elf_sec *rela)
{
    return -ENOSYS;
}

int arch_livepatch_secure(const void *va, unsigned int pages, enum va_type type)
{
    unsigned long start = (unsigned long)va;
    unsigned int flags = 0;

    ASSERT(va);
    ASSERT(pages);

    switch ( type )
    {
    case LIVEPATCH_VA_RX:
        flags = PTE_RO; /* R set, NX clear */
        break;

    case LIVEPATCH_VA_RW:
        flags = PTE_NX; /* R clear, NX set */
        break;

    case LIVEPATCH_VA_RO:
        flags = PTE_NX | PTE_RO; /* R set, NX set */
        break;

    default:
        return -EINVAL;
    }

    return modify_xen_mappings(start, start + pages * PAGE_SIZE, flags);
}

void __init arch_livepatch_init(void)
{
    void *start, *end;

    start = (void *)LIVEPATCH_VMAP_START;
    end = (void *)LIVEPATCH_VMAP_END;

    vm_init_type(VMAP_XEN, start, end);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
