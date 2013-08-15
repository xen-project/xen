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

typedef int elf_errorstatus; /* 0: ok; -ve (normally -1): error */
typedef int elf_negerrnoval; /* 0: ok; -EFOO: error */

#undef ELFSIZE
#include "elfstructs.h"
#ifdef __XEN__
#include <public/elfnote.h>
#include <public/features.h>
#include <xen/stdbool.h>
#include <xen/string.h>
#else
#include <xen/elfnote.h>
#include <xen/features.h>

#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

struct elf_binary;
typedef void elf_log_callback(struct elf_binary*, void *caller_data,
                              bool iserr, const char *fmt, va_list al);

#endif

#define ELF_MAX_STRING_LENGTH 4096
#define ELF_MAX_TOTAL_NOTE_COUNT 65536

/* ------------------------------------------------------------------------ */

/* Macros for accessing the input image and output area. */

/*
 * We abstract away the pointerness of these pointers, replacing
 * various void*, char* and struct* with the following:
 *   elf_ptrval  A pointer to a byte; one can do pointer arithmetic
 *               on this.
 *   HANDLE      A pointer to a struct.  There is one of these types
 *               for each pointer type - that is, for each "structname".
 *               In the arguments to the various HANDLE macros, structname
 *               must be a single identifier which is a typedef.
 *               It is not permitted to do arithmetic on these
 *               pointers.  In the current code attempts to do so will
 *               compile, but in the next patch this will become a
 *               compile error.
 */

typedef uintptr_t elf_ptrval;

#define ELF_REALPTR2PTRVAL(realpointer) ((elf_ptrval)(realpointer))
  /* Converts an actual C pointer into a PTRVAL */

#define ELF_HANDLE_DECL(structname)          structname##_handle
  /* Provides a type declaration for a HANDLE. */

#ifdef __XEN__
# define ELF_PRPTRVAL "lx"
  /*
   * PRIxPTR is misdefined in xen/include/xen/inttypes.h, on 32-bit,
   * to "x", when in fact uintptr_t is an unsigned long.
   */
#else
# define ELF_PRPTRVAL PRIxPTR
#endif
  /* printf format a la PRId... for a PTRVAL */

#define ELF_DEFINE_HANDLE(structname)                                   \
    typedef union {                                                     \
        elf_ptrval ptrval;                                              \
        const structname *typeonly; /* for sizeof, offsetof, &c only */ \
    } structname##_handle;
  /*
   * This must be invoked for each HANDLE type to define
   * the actual C type used for that kind of HANDLE.
   */

#define ELF_MAKE_HANDLE(structname, ptrval)    ((structname##_handle){ ptrval })
  /* Converts a PTRVAL to a HANDLE */

#define ELF_IMAGE_BASE(elf)    ((elf_ptrval)(elf)->image_base)
  /* Returns the base of the image as a PTRVAL. */

#define ELF_HANDLE_PTRVAL(handleval)      ((handleval).ptrval)
  /* Converts a HANDLE to a PTRVAL. */

#define ELF_UNSAFE_PTR(ptrval) ((void*)(elf_ptrval)(ptrval))
  /*
   * Turns a PTRVAL into an actual C pointer.  Before this is done
   * the caller must have ensured that the PTRVAL does in fact point
   * to a permissible location.
   */

/* PTRVALs can be INVALID (ie, NULL). */
#define ELF_INVALID_PTRVAL    ((elf_ptrval)0)       /* returns NULL PTRVAL */
#define ELF_INVALID_HANDLE(structname)		    /* returns NULL handle */ \
    ELF_MAKE_HANDLE(structname, ELF_INVALID_PTRVAL)
#define ELF_PTRVAL_VALID(ptrval)    (!!(ptrval))            /* }            */
#define ELF_HANDLE_VALID(handleval) (!!(handleval).ptrval)  /* } predicates */
#define ELF_PTRVAL_INVALID(ptrval)  (!ELF_PTRVAL_VALID((ptrval))) /* }      */

#define ELF_MAX_PTRVAL        (~(elf_ptrval)0)
  /* PTRVAL value guaranteed to compare > to any valid PTRVAL */

/* For internal use by other macros here */
#define ELF__HANDLE_FIELD_TYPE(handleval, elm) \
  typeof((handleval).typeonly->elm)
#define ELF__HANDLE_FIELD_OFFSET(handleval, elm) \
  offsetof(typeof(*(handleval).typeonly),elm)


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
    const void *image_base;
    size_t size;
    char class;
    char data;

    ELF_HANDLE_DECL(elf_ehdr) ehdr;
    elf_ptrval sec_strtab;
    ELF_HANDLE_DECL(elf_shdr) sym_tab;
    uint64_t sym_strtab;

    /* loaded to */
    /*
     * dest_base and dest_size are trusted and must be correct;
     * whenever dest_size is not 0, both of these must be valid
     * so long as the struct elf_binary is in use.
     */
    char *dest_base;
    size_t dest_size;
    uint64_t pstart;
    uint64_t pend;
    uint64_t reloc_offset;

    uint64_t bsd_symtab_pstart;
    uint64_t bsd_symtab_pend;

    /*
     * caller's other acceptable destination
     *
     * Again, these are trusted and must be valid (or 0) so long
     * as the struct elf_binary is in use.
     */
    void *caller_xdest_base;
    uint64_t caller_xdest_size;

#ifndef __XEN__
    /* misc */
    elf_log_callback *log_callback;
    void *log_caller_data;
#endif
    bool verbose;
    const char *broken;
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

#define elf_uval_3264(elf, handle, elem)                                \
    elf_access_unsigned((elf), (handle).ptrval,                         \
                           offsetof(typeof(*(handle).typeonly),elem),    \
                           sizeof((handle).typeonly->elem))

#define elf_uval(elf, handle, elem)             \
    ((ELFCLASS64 == (elf)->class)               \
     ? elf_uval_3264(elf, handle, e64.elem)     \
     : elf_uval_3264(elf, handle, e32.elem))
  /*
   * Reads an unsigned field in a header structure in the ELF.
   * str is a HANDLE, and elem is the field name in it.
   */


#define elf_size(elf, handle_or_handletype) ({          \
    typeof(handle_or_handletype) elf_size__dummy;       \
    ((ELFCLASS64 == (elf)->class)                       \
     ? sizeof(elf_size__dummy.typeonly->e64)             \
     : sizeof(elf_size__dummy.typeonly->e32));           \
})
  /*
   * Returns the size of the substructure for the appropriate 32/64-bitness.
   * str should be a HANDLE.
   */

uint64_t elf_access_unsigned(struct elf_binary *elf, elf_ptrval ptr,
                             uint64_t offset, size_t size);
  /* Reads a field at arbitrary offset and alignemnt */

uint64_t elf_round_up(struct elf_binary *elf, uint64_t addr);

const char *elf_strval(struct elf_binary *elf, elf_ptrval start);
  /* may return NULL if the string is out of range etc. */

const char *elf_strfmt(struct elf_binary *elf, elf_ptrval start);
  /* like elf_strval but returns "(invalid)" instead of NULL */

void elf_memcpy_safe(struct elf_binary*, elf_ptrval dst, elf_ptrval src, size_t);
void elf_memset_safe(struct elf_binary*, elf_ptrval dst, int c, size_t);
  /*
   * Versions of memcpy and memset which arrange never to write
   * outside permitted areas.
   */

bool elf_access_ok(struct elf_binary * elf,
                   uint64_t ptrval, size_t size);

#define elf_store_val(elf, type, ptr, val)                              \
    ({                                                                  \
        typeof(type) elf_store__val = (val);                            \
        elf_ptrval elf_store__targ = ptr;                               \
        if (elf_access_ok((elf), elf_store__targ,                       \
                          sizeof(elf_store__val))) {			\
            elf_memcpy_unchecked((void*)elf_store__targ, &elf_store__val, \
                             sizeof(elf_store__val));                   \
        }                                                               \
    })									\
  /* Stores a value at a particular PTRVAL. */

#define elf_store_field(elf, hdr, elm, val)                             \
    (elf_store_val((elf), ELF__HANDLE_FIELD_TYPE(hdr, elm),                   \
                   ELF_HANDLE_PTRVAL(hdr) + ELF__HANDLE_FIELD_OFFSET(hdr, elm), \
                   (val)))
  /* Stores a 32/64-bit field.  hdr is a HANDLE and elm is the field name. */


/* ------------------------------------------------------------------------ */
/* xc_libelf_tools.c                                                        */

unsigned elf_shdr_count(struct elf_binary *elf);
unsigned elf_phdr_count(struct elf_binary *elf);

ELF_HANDLE_DECL(elf_shdr) elf_shdr_by_name(struct elf_binary *elf, const char *name);
ELF_HANDLE_DECL(elf_shdr) elf_shdr_by_index(struct elf_binary *elf, unsigned index);
ELF_HANDLE_DECL(elf_phdr) elf_phdr_by_index(struct elf_binary *elf, unsigned index);

const char *elf_section_name(struct elf_binary *elf, ELF_HANDLE_DECL(elf_shdr) shdr); /* might return NULL if inputs are invalid */
elf_ptrval elf_section_start(struct elf_binary *elf, ELF_HANDLE_DECL(elf_shdr) shdr);
elf_ptrval elf_section_end(struct elf_binary *elf, ELF_HANDLE_DECL(elf_shdr) shdr);

elf_ptrval elf_segment_start(struct elf_binary *elf, ELF_HANDLE_DECL(elf_phdr) phdr);
elf_ptrval elf_segment_end(struct elf_binary *elf, ELF_HANDLE_DECL(elf_phdr) phdr);

ELF_HANDLE_DECL(elf_sym) elf_sym_by_name(struct elf_binary *elf, const char *symbol);
ELF_HANDLE_DECL(elf_sym) elf_sym_by_index(struct elf_binary *elf, unsigned index);

const char *elf_note_name(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note); /* may return NULL */
elf_ptrval elf_note_desc(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note);
uint64_t elf_note_numeric(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note);
uint64_t elf_note_numeric_array(struct elf_binary *, ELF_HANDLE_DECL(elf_note),
                                unsigned int unitsz, unsigned int idx);

/*
 * If you use elf_note_next in a loop, you must put a nontrivial upper
 * bound on the returned value as part of your loop condition.  In
 * some cases elf_note_next will substitute ELF_PTRVAL_MAX as return
 * value to indicate that the iteration isn't going well (for example,
 * the putative "next" value would be earlier in memory).  In this
 * case the caller's loop must terminate.  Checking against the
 * end of the notes segment with a strict inequality is sufficient.
 */
ELF_HANDLE_DECL(elf_note) elf_note_next(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) note);

/* (Only) checks that the image has the right magic number. */
bool elf_is_elfbinary(const void *image_start, size_t image_size);

bool elf_phdr_is_loadable(struct elf_binary *elf, ELF_HANDLE_DECL(elf_phdr) phdr);

/* ------------------------------------------------------------------------ */
/* xc_libelf_loader.c                                                       */

elf_errorstatus elf_init(struct elf_binary *elf, const char *image, size_t size);
  /*
   * image and size must be correct.  They will be recorded in
   * *elf, and must remain valid while the elf is in use.
   */
#ifdef __XEN__
void elf_set_verbose(struct elf_binary *elf);
#else
void elf_set_log(struct elf_binary *elf, elf_log_callback*,
                 void *log_caller_pointer, bool verbose);
#endif

void elf_parse_binary(struct elf_binary *elf);
elf_errorstatus elf_load_binary(struct elf_binary *elf);

elf_ptrval elf_get_ptr(struct elf_binary *elf, unsigned long addr);
uint64_t elf_lookup_addr(struct elf_binary *elf, const char *symbol);

void elf_parse_bsdsyms(struct elf_binary *elf, uint64_t pstart); /* private */

void elf_mark_broken(struct elf_binary *elf, const char *msg);
const char *elf_check_broken(const struct elf_binary *elf); /* NULL means OK */

/* ------------------------------------------------------------------------ */
/* xc_libelf_relocate.c                                                     */

elf_errorstatus elf_reloc(struct elf_binary *elf);

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
    elf_ptrval guest_info;
    elf_ptrval elf_note_start;
    elf_ptrval elf_note_end;
    struct xen_elfnote elf_notes[XEN_ELFNOTE_MAX + 1];

    /* parsed */
    char guest_os[16];
    char guest_ver[16];
    char xen_ver[16];
    char loader[16];
    int pae; /* some kind of enum apparently */
    bool bsd_symtab;
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

static inline void *elf_memcpy_unchecked(void *dest, const void *src, size_t n)
    { return memcpy(dest, src, n); }
static inline void *elf_memmove_unchecked(void *dest, const void *src, size_t n)
    { return memmove(dest, src, n); }
static inline void *elf_memset_unchecked(void *s, int c, size_t n)
    { return memset(s, c, n); }
  /*
   * Unsafe versions of memcpy, memmove memset which take actual C
   * pointers.  These are just like the real functions.
   * We provide these so that in libelf-private.h we can #define
   * memcpy, memset and memmove to undefined MISTAKE things.
   */


/* Advances past amount bytes of the current destination area. */
static inline void ELF_ADVANCE_DEST(struct elf_binary *elf, uint64_t amount)
{
    if ( elf->dest_base == NULL )
    {
        elf_mark_broken(elf, "advancing in null image");
    }
    else if ( elf->dest_size >= amount )
    {
        elf->dest_base += amount;
        elf->dest_size -= amount;
    }
    else
    {
        elf->dest_size = 0;
        elf_mark_broken(elf, "advancing past end (image very short?)");
    }
}


#endif /* __XEN_LIBELF_H__ */
