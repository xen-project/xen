/*
 * Copyright (C) 2016 Citrix Systems R&D Ltd.
 */

#ifndef __XEN_LIVEPATCH_ELF_H__
#define __XEN_LIVEPATCH_ELF_H__

#include <xen/types.h>
#include <xen/elfstructs.h>

/* The following describes an Elf file as consumed by Xen Live Patch. */
struct livepatch_elf_sec {
    const Elf_Shdr *sec;                 /* Hooked up in elf_resolve_sections.*/
    const char *name;                    /* Human readable name hooked in
                                            elf_resolve_section_names. */
    const void *data;                    /* Pointer to the section (done by
                                            elf_resolve_sections). */
    void *load_addr;                     /* A pointer to the allocated destination.
                                            Done by load_payload_data. */
};

struct livepatch_elf_sym {
    const Elf_Sym *sym;
    const char *name;
};

struct livepatch_elf {
    const char *name;                    /* Pointer to payload->name. */
    size_t len;                          /* Length of the ELF file. */
    const Elf_Ehdr *hdr;                 /* ELF file. */
    struct livepatch_elf_sec *sec;       /* Array of sections, allocated by us. */
    struct livepatch_elf_sym *sym;       /* Array of symbols , allocated by us. */
    unsigned int nsym;
    const struct livepatch_elf_sec *symtab;/* Pointer to .symtab section - aka to
                                            sec[symtab_idx]. */
    const struct livepatch_elf_sec *strtab;/* Pointer to .strtab section. */
    unsigned int symtab_idx;
};

const struct livepatch_elf_sec *
livepatch_elf_sec_by_name(const struct livepatch_elf *elf,
                          const char *name);
int livepatch_elf_load(struct livepatch_elf *elf, const void *data);
void livepatch_elf_free(struct livepatch_elf *elf);

int livepatch_elf_resolve_symbols(struct livepatch_elf *elf);
int livepatch_elf_perform_relocs(struct livepatch_elf *elf);

static inline bool livepatch_elf_ignore_section(const Elf_Shdr *sec)
{
    return !(sec->sh_flags & SHF_ALLOC) || sec->sh_size == 0;
}
#endif /* __XEN_LIVEPATCH_ELF_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
