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

#include <xen/elfstructs.h>
#ifdef CONFIG_XSPLICE

/* Convenience define for printk. */
#define XSPLICE             "xsplice: "
/* ELF payload special section names. */
#define ELF_XSPLICE_FUNC    ".xsplice.funcs"

int xsplice_op(struct xen_sysctl_xsplice_op *);
void check_for_xsplice_work(void);

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

#include <public/sysctl.h> /* For struct xsplice_patch_func. */
int arch_xsplice_verify_func(const struct xsplice_patch_func *func);
/*
 * These functions are called around the critical region patching live code,
 * for an architecture to take make appropratie global state adjustments.
 */
void arch_xsplice_patching_enter(void);
void arch_xsplice_patching_leave(void);

void arch_xsplice_apply_jmp(struct xsplice_patch_func *func);
void arch_xsplice_revert_jmp(const struct xsplice_patch_func *func);
void arch_xsplice_post_action(void);

void arch_xsplice_mask(void);
void arch_xsplice_unmask(void);
#else

#include <xen/errno.h> /* For -ENOSYS */
static inline int xsplice_op(struct xen_sysctl_xsplice_op *op)
{
    return -ENOSYS;
}

static inline void check_for_xsplice_work(void) { };
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
