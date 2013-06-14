/******************************************************************************
 * libelf.h
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef __XEN_LIBELF_H__
#define __XEN_LIBELF_H__

#if defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)
#define XEN_ELF_LITTLE_ENDIAN
#else
#error define architectural endianness
#endif

#undef ELFSIZE
#include "elfstructs.h"
#ifdef __XEN__
#include <public/elfnote.h>
#include <public/features.h>
#else
#include <xen/elfnote.h>
#include <xen/features.h>

#include <stdarg.h>

struct elf_binary;
typedef void elf_log_callback(struct elf_binary*, void *caller_data,
                              int iserr, const char *fmt, va_list al);

#endif

/* ------------------------------------------------------------------------ */

/* Macros for accessing the input image and output area. */

/*
 * We abstract away the pointerness of these pointers, replacing
 * various void*, char* and struct* with the following:
 *   PTRVAL      A pointer to a byte; one can do pointer arithmetic
 *               on this.
 *               This replaces variables which were char*,void*
 *               and their const versions, so we provide four
 *               different declaration macros:
 *                   ELF_PTRVAL_{,CONST}{VOID,CHAR}
 *   HANDLE      A pointer to a struct.  There is one of these types
 *               for each pointer type - that is, for each "structname".
 *               In the arguments to the various HANDLE macros, structname
 *               must be a single identifier which is a typedef.
 *               It is not permitted to do arithmetic on these
 *               pointers.  In the current code attempts to do so will
 *               compile, but in the next patch this will become a
 *               compile error.
 *               We provide two declaration macros for const and
 *               non-const pointers.
 */

#define ELF_REALPTR2PTRVAL(realpointer) (realpointer)
  /* Converts an actual C pointer into a PTRVAL */

#define ELF_HANDLE_DECL_NONCONST(structname)  structname *
#define ELF_HANDLE_DECL(structname)           const structname *
  /* Provides a type declaration for a HANDLE. */
  /* May only be used to declare ONE variable at a time */

#define ELF_PTRVAL_VOID         void *
#define ELF_PTRVAL_CHAR         char *
#define ELF_PTRVAL_CONST_VOID   const void *
#define ELF_PTRVAL_CONST_CHAR   const char *
  /* Provides a type declaration for a PTRVAL. */
  /* May only be used to declare ONE variable at a time */

#define ELF_DEFINE_HANDLE(structname) /* empty */
  /*
   * This must be invoked for each HANDLE type to define
   * the actual C type used for that kind of HANDLE.
   */

#define ELF_PRPTRVAL "p"
  /* printf format a la PRId... for a PTRVAL */

#define ELF_MAKE_HANDLE(structname, ptrval) (ptrval)
  /* Converts a PTRVAL to a HANDLE */

#define ELF_IMAGE_BASE(elf) ((elf)->image)
  /* Returns the base of the image as a PTRVAL. */

#define ELF_HANDLE_PTRVAL(handleval) ((void*)(handleval))
  /* Converts a HANDLE to a PTRVAL. */

#define ELF_OBSOLETE_VOIDP_CAST (void*)(uintptr_t)
  /*
   * In some places the existing code needs to
   *  - cast away const (the existing code uses const a fair
   *    bit but actually sometimes wants to write to its input)
   *    from a PTRVAL.
   *  - convert an integer representing a pointer to a PTRVAL
   * This macro provides a suitable cast.
   */

#define ELF_UNSAFE_PTR(ptrval) ((void*)(uintptr_t)(ptrval))
  /*
   * Turns a PTRVAL into an actual C pointer.  Before this is done
   * the caller must have ensured that the PTRVAL does in fact point
   * to a permissible location.
   */

/* PTRVALs can be INVALID (ie, NULL). */
#define ELF_INVALID_PTRVAL            (NULL)        /* returns NULL PTRVAL */
#define ELF_INVALID_HANDLE(structname)		    /* returns NULL handle */ \
    ELF_MAKE_HANDLE(structname, ELF_INVALID_PTRVAL)
#define ELF_PTRVAL_VALID(ptrval)      (ptrval)            /* }            */
#define ELF_HANDLE_VALID(handleval)   (handleval)         /* } predicates */
#define ELF_PTRVAL_INVALID(ptrval)    ((ptrval) == NULL)  /* }            */

/* For internal use by other macros here */
#define ELF__HANDLE_FIELD_TYPE(handleval, elm) \
  typeof((handleval)->elm)
#define ELF__HANDLE_FIELD_OFFSET(handleval, elm) \
  offsetof(typeof(*(handleval)),elm)


/* ------------------------------------------------------------------------ */


typedef union {
    Elf32_Ehdr e32;
    Elf64_Ehdr e64;
} elf_ehdr;

typedef union {
    Elf32_Phdr e32;
    Elf64_Phdr e64;
} elf_phdr;

typedef union {
    Elf32_Shdr e32;
    Elf64_Shdr e64;
} elf_shdr;

typedef union {
    Elf32_Sym e32;
    Elf64_Sym e64;
} elf_sym;

typedef union {
    Elf32_Rel e32;
    Elf64_Rel e64;
} elf_rel;

typedef union {
    Elf32_Rela e32;
    Elf64_Rela e64;
} elf_rela;

typedef union {
    Elf32_Note e32;
    Elf64_Note e64;
} elf_note;

ELF_DEFINE_HANDLE(elf_ehdr)
ELF_DEFINE_HANDLE(elf_shdr)
ELF_DEFINE_HANDLE(elf_phdr)
ELF_DEFINE_HANDLE(elf_sym)
ELF_DEFINE_HANDLE(elf_note)

struct elf_binary {
    /* elf binary */
    const char *image;
    size_t size;
    char class;
    char data;

    ELF_HANDLE_DECL(elf_ehdr) ehdr;
    ELF_PTRVAL_CONST_CHAR sec_strtab;
    ELF_HANDLE_DECL(elf_shdr) sym_tab;
    ELF_PTRVAL_CONST_CHAR sym_strtab;

    /* loaded to */
    char *dest;
    uint64_t pstart;
    uint64_t pend;
    uint64_t reloc_offset;

    uint64_t bsd_symtab_pstart;
    uint64_t bsd_symtab_pend;

#ifndef __XEN__
    /* misc */
    elf_log_callback *log_callback;
    void *log_caller_data;
#endif
    int verbose;
};

/* ------------------------------------------------------------------------ */
/* accessing elf header fields                                              */

#ifdef XEN_ELF_BIG_ENDIAN
# define NATIVE_ELFDATA ELFDATA2MSB
#else
# define NATIVE_ELFDATA ELFDATA2LSB
#endif

#define elf_32bit(elf) (ELFCLASS32 == (elf)->class)
#define elf_64bit(elf) (ELFCLASS64 == (elf)->class)
#define elf_msb(elf)   (ELFDATA2MSB == (elf)->data)
#define elf_lsb(elf)   (ELFDATA2LSB == (elf)->data)
#define elf_swap(elf)  (NATIVE_ELFDATA != (elf)->data)

#define elf_uval(elf, str, elem)                                        \
    ((ELFCLASS64 == (elf)->class)                                       \
     ? elf_access_unsigned((elf), (str),                                \
                           offsetof(typeof(*(str)),e64.elem),           \
                           sizeof((str)->e64.elem))                     \
     : elf_access_unsigned((elf), (str),                                \
                           offsetof(typeof(*(str)),e32.elem),           \
                           sizeof((str)->e32.elem)))
  /*
   * Reads an unsigned field in a header structure in the ELF.
   * str is a HANDLE, and elem is the field name in it.
   */

#define elf_size(elf, str)                              \
    ((ELFCLASS64 == (elf)->class)                       \
     ? sizeof((str)->e64) : sizeof((str)->e32))
  /*
   * Returns the size of the substructure for the appropriate 32/64-bitness.
   * str should be a HANDLE.
   */

uint64_t elf_access_unsigned(struct elf_binary *elf, ELF_PTRVAL_CONST_VOID ptr,
                             uint64_t offset, size_t size);
  /* Reads a field at arbitrary offset and alignemnt */

uint64_t elf_round_up(struct elf_binary *elf, uint64_t addr);


#define elf_memcpy_safe(elf, dst, src, sz) memcpy((dst),(src),(sz))
#define elf_memset_safe(elf, dst, c, sz)   memset((dst),(c),(sz))
  /*
   * Versions of memcpy and memset which will (in the next patch)
   * arrange never to write outside permitted areas.
   */

#define elf_store_val(elf, type, ptr, val)   (*(type*)(ptr) = (val))
  /* Stores a value at a particular PTRVAL. */

#define elf_store_field(elf, hdr, elm, val)                     \
    (elf_store_val((elf), ELF__HANDLE_FIELD_TYPE(hdr, elm),     \
                   &((hdr)->elm),                               \
                   (val)))
  /* Stores a 32/64-bit field.  hdr is a HANDLE and elm is the field name. */


/* ------------------------------------------------------------------------ */
/* xc_libelf_tools.c                                                        */

int elf_shdr_count(struct elf_binary *elf);
int elf_phdr_count(struct elf_binary *elf);

ELF_HANDLE_DECL(elf_shdr) elf_shdr_by_name(struct elf_binary *elf, const char *name);
ELF_HANDLE_DECL(elf_shdr) elf_shdr_by_index(struct elf_binary *elf, int index);
ELF_HANDLE_DECL(elf_phdr) elf_phdr_by_index(struct elf_binary *elf, int index);

const char *elf_section_name(struct elf_binary *elf, ELF_HANDLE_DECL(elf_shdr) shdr);
ELF_PTRVAL_CONST_VOID elf_section_start(struct elf_binary *elf, ELF_HANDLE_DECL(elf_shdr) shdr);
ELF_PTRVAL_CONST_VOID elf_section_end(struct elf_binary *elf, ELF_HANDLE_DECL(elf_shdr) shdr);

ELF_PTRVAL_CONST_VOID elf_segment_start(struct elf_binary *elf, ELF_HANDLE_DECL(elf_phdr) phdr);
ELF_PTRVAL_CONST_VOID elf_segment_end(struct elf_binary *elf, ELF_HANDLE_DECL(elf_phdr) phdr);

ELF_HANDLE_DECL(elf_sym) elf_sym_by_name(struct elf_binary *elf, const char *symbol);
ELF_HANDLE_DECL(elf_sym) elf_sym_by_index(struct elf_binary *elf, int index);

const char *elf_note_name(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note);
ELF_PTRVAL_CONST_VOID elf_note_desc(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note);
uint64_t elf_note_numeric(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note);
uint64_t elf_note_numeric_array(struct elf_binary *, ELF_HANDLE_DECL(elf_note),
                                unsigned int unitsz, unsigned int idx);
ELF_HANDLE_DECL(elf_note) elf_note_next(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note);

int elf_is_elfbinary(const void *image);
int elf_phdr_is_loadable(struct elf_binary *elf, ELF_HANDLE_DECL(elf_phdr) phdr);

/* ------------------------------------------------------------------------ */
/* xc_libelf_loader.c                                                       */

int elf_init(struct elf_binary *elf, const char *image, size_t size);
#ifdef __XEN__
void elf_set_verbose(struct elf_binary *elf);
#else
void elf_set_log(struct elf_binary *elf, elf_log_callback*,
                 void *log_caller_pointer, int verbose);
#endif

void elf_parse_binary(struct elf_binary *elf);
int elf_load_binary(struct elf_binary *elf);

ELF_PTRVAL_VOID elf_get_ptr(struct elf_binary *elf, unsigned long addr);
uint64_t elf_lookup_addr(struct elf_binary *elf, const char *symbol);

void elf_parse_bsdsyms(struct elf_binary *elf, uint64_t pstart); /* private */

/* ------------------------------------------------------------------------ */
/* xc_libelf_relocate.c                                                     */

int elf_reloc(struct elf_binary *elf);

/* ------------------------------------------------------------------------ */
/* xc_libelf_dominfo.c                                                      */

#define UNSET_ADDR          ((uint64_t)-1)

enum xen_elfnote_type {
    XEN_ENT_NONE = 0,
    XEN_ENT_LONG = 1,
    XEN_ENT_STR  = 2
};

struct xen_elfnote {
    enum xen_elfnote_type type;
    const char *name;
    union {
        const char *str;
        uint64_t num;
    } data;
};

struct elf_dom_parms {
    /* raw */
    ELF_PTRVAL_CONST_CHAR guest_info;
    ELF_PTRVAL_CONST_VOID elf_note_start;
    ELF_PTRVAL_CONST_VOID elf_note_end;
    struct xen_elfnote elf_notes[XEN_ELFNOTE_MAX + 1];

    /* parsed */
    char guest_os[16];
    char guest_ver[16];
    char xen_ver[16];
    char loader[16];
    int pae;
    int bsd_symtab;
    uint64_t virt_base;
    uint64_t virt_entry;
    uint64_t virt_hypercall;
    uint64_t virt_hv_start_low;
    uint64_t p2m_base;
    uint64_t elf_paddr_offset;
    uint32_t f_supported[XENFEAT_NR_SUBMAPS];
    uint32_t f_required[XENFEAT_NR_SUBMAPS];

    /* calculated */
    uint64_t virt_offset;
    uint64_t virt_kstart;
    uint64_t virt_kend;
};

static inline void elf_xen_feature_set(int nr, uint32_t * addr)
{
    addr[nr >> 5] |= 1 << (nr & 31);
}
static inline int elf_xen_feature_get(int nr, uint32_t * addr)
{
    return !!(addr[nr >> 5] & (1 << (nr & 31)));
}

int elf_xen_parse_features(const char *features,
                           uint32_t *supported,
                           uint32_t *required);
int elf_xen_parse_note(struct elf_binary *elf,
                       struct elf_dom_parms *parms,
                       ELF_HANDLE_DECL(elf_note) note);
int elf_xen_parse_guest_info(struct elf_binary *elf,
                             struct elf_dom_parms *parms);
int elf_xen_parse(struct elf_binary *elf,
                  struct elf_dom_parms *parms);

#define elf_memcpy_unchecked memcpy
#define elf_memset_unchecked memset
  /*
   * Unsafe versions of memcpy and memset which take actual C
   * pointers.  These are just like real memcpy and memset.
   */


#define ELF_ADVANCE_DEST(elf, amount)  elf->dest += (amount)
  /* Advances past amount bytes of the current destination area. */


#endif /* __XEN_LIBELF_H__ */
