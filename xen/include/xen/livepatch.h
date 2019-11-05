/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#ifndef __XEN_LIVEPATCH_H__
#define __XEN_LIVEPATCH_H__

struct livepatch_elf;
struct livepatch_elf_sec;
struct livepatch_elf_sym;
struct xen_sysctl_livepatch_op;

#include <xen/elfstructs.h>
#include <xen/errno.h> /* For -ENOSYS or -EOVERFLOW */
#ifdef CONFIG_LIVEPATCH

/*
 * We use alternative and exception table code - which by default are __init
 * only, however we need them during runtime. These macros allows us to build
 * the image with these functions built-in. (See the #else below).
 */
#define init_or_livepatch_const
#define init_or_livepatch_constrel
#define init_or_livepatch_data
#define init_or_livepatch_read_mostly __read_mostly
#define init_or_livepatch

/* Convenience define for printk. */
#define LIVEPATCH             "livepatch: "
/* ELF payload special section names. */
#define ELF_LIVEPATCH_FUNC    ".livepatch.funcs"
#define ELF_LIVEPATCH_DEPENDS ".livepatch.depends"
#define ELF_BUILD_ID_NOTE      ".note.gnu.build-id"
/* Arbitrary limit for payload size and .bss section size. */
#define LIVEPATCH_MAX_SIZE     MB(2)

struct livepatch_symbol {
    const char *name;
    unsigned long value;
    unsigned int size;
    bool_t new_symbol;
};

int livepatch_op(struct xen_sysctl_livepatch_op *);
void check_for_livepatch_work(void);
unsigned long livepatch_symbols_lookup_by_name(const char *symname);
bool_t is_patch(const void *addr);

/* Arch hooks. */
int arch_livepatch_verify_elf(const struct livepatch_elf *elf);
bool arch_livepatch_symbol_ok(const struct livepatch_elf *elf,
                              const struct livepatch_elf_sym *sym);
bool arch_livepatch_symbol_deny(const struct livepatch_elf *elf,
                                const struct livepatch_elf_sym *sym);
int arch_livepatch_perform_rel(struct livepatch_elf *elf,
                               const struct livepatch_elf_sec *base,
                               const struct livepatch_elf_sec *rela);
int arch_livepatch_perform_rela(struct livepatch_elf *elf,
                                const struct livepatch_elf_sec *base,
                                const struct livepatch_elf_sec *rela);
enum va_type {
    LIVEPATCH_VA_RX, /* .text */
    LIVEPATCH_VA_RW, /* .data */
    LIVEPATCH_VA_RO, /* .rodata */
};

/*
 * Function to secure the allocate pages (from arch_livepatch_alloc_payload)
 * with the right page permissions.
 */
int arch_livepatch_secure(const void *va, unsigned int pages, enum va_type types);

void arch_livepatch_init(void);

#include <public/sysctl.h> /* For struct livepatch_func. */
#include <asm/livepatch.h>
int arch_livepatch_verify_func(const struct livepatch_func *func);

static inline
unsigned int livepatch_insn_len(const struct livepatch_func *func)
{
    if ( !func->new_addr )
        return func->new_size;

    return ARCH_PATCH_INSN_SIZE;
}

static inline int livepatch_verify_distance(const struct livepatch_func *func)
{
    long offset;
    long range = ARCH_LIVEPATCH_RANGE;

    if ( !func->new_addr ) /* Ignore NOPs. */
        return 0;

    offset = func->old_addr - func->new_addr;
    if ( offset < -range || offset >= range )
        return -EOVERFLOW;

    return 0;
}
/*
 * These functions are called around the critical region patching live code,
 * for an architecture to take make appropratie global state adjustments.
 */
int arch_livepatch_safety_check(void);
int arch_livepatch_quiesce(void);
void arch_livepatch_revive(void);

void arch_livepatch_apply(struct livepatch_func *func);
void arch_livepatch_revert(const struct livepatch_func *func);
void arch_livepatch_post_action(void);

void arch_livepatch_mask(void);
void arch_livepatch_unmask(void);
#else

/*
 * If not compiling with Live Patch certain functionality should stay as
 * __init.
 */
#define init_or_livepatch_const       __initconst
#define init_or_livepatch_constrel    __initconstrel
#define init_or_livepatch_data        __initdata
#define init_or_livepatch_read_mostly __initdata
#define init_or_livepatch             __init

static inline int livepatch_op(struct xen_sysctl_livepatch_op *op)
{
    return -ENOSYS;
}

static inline void check_for_livepatch_work(void) { };
static inline bool_t is_patch(const void *addr)
{
    return 0;
}
#endif /* CONFIG_LIVEPATCH */

#endif /* __XEN_LIVEPATCH_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
