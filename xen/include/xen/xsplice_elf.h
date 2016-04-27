/*
 * Copyright (C) 2016 Citrix Systems R&D Ltd.
 */

#ifndef __XEN_XSPLICE_ELF_H__
#define __XEN_XSPLICE_ELF_H__

#include <xen/types.h>
#include <xen/elfstructs.h>

/* The following describes an Elf file as consumed by xSplice. */
struct xsplice_elf_sec {
    const Elf_Shdr *sec;                 /* Hooked up in elf_resolve_sections.*/
    const char *name;                    /* Human readable name hooked in
                                            elf_resolve_section_names. */
    const void *data;                    /* Pointer to the section (done by
                                            elf_resolve_sections). */
    void *load_addr;                     /* A pointer to the allocated destination.
                                            Done by load_payload_data. */
};

struct xsplice_elf_sym {
    const Elf_Sym *sym;
    const char *name;
};

struct xsplice_elf {
    const char *name;                    /* Pointer to payload->name. */
    size_t len;                          /* Length of the ELF file. */
    const Elf_Ehdr *hdr;                 /* ELF file. */
    struct xsplice_elf_sec *sec;         /* Array of sections, allocated by us. */
    struct xsplice_elf_sym *sym;         /* Array of symbols , allocated by us. */
    unsigned int nsym;
    const struct xsplice_elf_sec *symtab;/* Pointer to .symtab section - aka to
                                            sec[symtab_idx]. */
    const struct xsplice_elf_sec *strtab;/* Pointer to .strtab section. */
    unsigned int symtab_idx;
};

const struct xsplice_elf_sec *xsplice_elf_sec_by_name(const struct xsplice_elf *elf,
                                                      const char *name);
int xsplice_elf_load(struct xsplice_elf *elf, const void *data);
void xsplice_elf_free(struct xsplice_elf *elf);

int xsplice_elf_resolve_symbols(struct xsplice_elf *elf);
int xsplice_elf_perform_relocs(struct xsplice_elf *elf);

#endif /* __XEN_XSPLICE_ELF_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
