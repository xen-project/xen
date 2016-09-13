/*
 *  Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 */

#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/livepatch_elf.h>
#include <xen/livepatch.h>

void arch_livepatch_apply(struct livepatch_func *func)
{
}

void arch_livepatch_revert(const struct livepatch_func *func)
{
}

int arch_livepatch_verify_elf(const struct livepatch_elf *elf)
{
    return -EOPNOTSUPP;
}

bool arch_livepatch_symbol_deny(const struct livepatch_elf *elf,
                                const struct livepatch_elf_sym *sym)
{
    /*
     * Xen does not use Thumb instructions - and we should not see any of
     * them. If we do, abort.
     */
    if ( sym->name && sym->name[0] == '$' && sym->name[1] == 't' )
        return ( !sym->name[2] || sym->name[2] == '.' );

    return false;
}

int arch_livepatch_perform_rela(struct livepatch_elf *elf,
                                const struct livepatch_elf_sec *base,
                                const struct livepatch_elf_sec *rela)
{
    return -ENOSYS;
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
