/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#ifndef __XEN_XSPLICE_H__
#define __XEN_XSPLICE_H__

struct xsplice_elf;
struct xsplice_elf_sec;
struct xsplice_elf_sym;
struct xen_sysctl_xsplice_op;

#ifdef CONFIG_XSPLICE

/* Convenience define for printk. */
#define XSPLICE             "xsplice: "

int xsplice_op(struct xen_sysctl_xsplice_op *);

/* Arch hooks. */
int arch_xsplice_verify_elf(const struct xsplice_elf *elf);
int arch_xsplice_perform_rel(struct xsplice_elf *elf,
                             const struct xsplice_elf_sec *base,
                             const struct xsplice_elf_sec *rela);
int arch_xsplice_perform_rela(struct xsplice_elf *elf,
                              const struct xsplice_elf_sec *base,
                              const struct xsplice_elf_sec *rela);
enum va_type {
    XSPLICE_VA_RX, /* .text */
    XSPLICE_VA_RW, /* .data */
    XSPLICE_VA_RO, /* .rodata */
};

/*
 * Function to secure the allocate pages (from arch_xsplice_alloc_payload)
 * with the right page permissions.
 */
int arch_xsplice_secure(const void *va, unsigned int pages, enum va_type types);

void arch_xsplice_init(void);
#else

#include <xen/errno.h> /* For -ENOSYS */
static inline int xsplice_op(struct xen_sysctl_xsplice_op *op)
{
    return -ENOSYS;
}

#endif /* CONFIG_XSPLICE */

#endif /* __XEN_XSPLICE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
