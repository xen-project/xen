/*
 *  Copyright (C) 2016 Citrix Systems R&D Ltd.
 */
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/xsplice_elf.h>
#include <xen/xsplice.h>

int arch_xsplice_verify_elf(const struct xsplice_elf *elf)
{
    return -ENOSYS;
}

int arch_xsplice_perform_rel(struct xsplice_elf *elf,
                             const struct xsplice_elf_sec *base,
                             const struct xsplice_elf_sec *rela)
{
    return -ENOSYS;
}

int arch_xsplice_perform_rela(struct xsplice_elf *elf,
                              const struct xsplice_elf_sec *base,
                              const struct xsplice_elf_sec *rela)
{
    return -ENOSYS;
}

int arch_xsplice_secure(const void *va, unsigned int pages, enum va_type type)
{
    return -ENOSYS;
}

void __init arch_xsplice_init(void)
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
