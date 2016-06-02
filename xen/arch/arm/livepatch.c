/*
 *  Copyright (C) 2016 Citrix Systems R&D Ltd.
 */
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/livepatch_elf.h>
#include <xen/livepatch.h>

void arch_livepatch_quiesce(void)
{
}

void arch_livepatch_revive(void)
{
}

int arch_livepatch_verify_func(const struct livepatch_func *func)
{
    return -ENOSYS;
}

void arch_livepatch_apply_jmp(struct livepatch_func *func)
{
}

void arch_livepatch_revert_jmp(const struct livepatch_func *func)
{
}

void arch_livepatch_post_action(void)
{
}

void arch_livepatch_mask(void)
{
}

void arch_livepatch_unmask(void)
{
}

int arch_livepatch_verify_elf(const struct livepatch_elf *elf)
{
    return -ENOSYS;
}

int arch_livepatch_perform_rel(struct livepatch_elf *elf,
                               const struct livepatch_elf_sec *base,
                               const struct livepatch_elf_sec *rela)
{
    return -ENOSYS;
}

int arch_livepatch_perform_rela(struct livepatch_elf *elf,
                                const struct livepatch_elf_sec *base,
                                const struct livepatch_elf_sec *rela)
{
    return -ENOSYS;
}

int arch_livepatch_secure(const void *va, unsigned int pages, enum va_type type)
{
    return -ENOSYS;
}

void __init arch_livepatch_init(void)
{
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
