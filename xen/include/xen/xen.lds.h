#ifndef __XEN_LDS_H__
#define __XEN_LDS_H__

/*
 * Common macros to be used in architecture specific linker scripts.
 */

#ifdef DECL_SECTION_WITH_LADDR

/*
 * Declare a section whose load address is based at PA 0 rather than
 * Xen's virtual base address.
 */
#ifdef CONFIG_LD_IS_GNU
# define DECL_SECTION(x) x : AT(ADDR(#x) - __XEN_VIRT_START)
#else
# define DECL_SECTION(x) x : AT(ADDR(x) - __XEN_VIRT_START)
#endif

#else /* !DECL_SECTION_WITH_LADDR */
#define DECL_SECTION(x) x :
#endif

/*
 * To avoid any confusion, please note that the EFI macro does not correspond
 * to EFI support and is used when linking a native EFI (i.e. PE/COFF) binary,
 * hence its usage in this header.
 */

/* Macros to declare debug sections. */
#ifdef EFI
/*
 * Use the NOLOAD directive, despite currently ignored by (at least) GNU ld
 * for PE output, in order to record that we'd prefer these sections to not
 * be loaded into memory.
 */
#define DECL_DEBUG(x, a) x ALIGN(a) (NOLOAD) : { *(x) }
#define DECL_DEBUG2(x, y, a) x ALIGN(a) (NOLOAD) : { *(x) *(y) }
#else
#define DECL_DEBUG(x, a) x 0 : { *(x) }
#define DECL_DEBUG2(x, y, a) x 0 : { *(x) *(y) }
#endif

/*
 * DWARF2+ debug sections.
 * Explicitly list debug sections, first of all to avoid these sections being
 * viewed as "orphan" by the linker.
 *
 * For the PE output this is further necessary so that they don't end up at
 * VA 0, which is below image base and thus invalid. Note that this macro is
 * to be used after _end, so if these sections get loaded they'll be discarded
 * at runtime anyway.
 */
#define DWARF2_DEBUG_SECTIONS                     \
  DECL_DEBUG(.debug_abbrev, 1)                    \
  DECL_DEBUG2(.debug_info, .gnu.linkonce.wi.*, 1) \
  DECL_DEBUG(.debug_types, 1)                     \
  DECL_DEBUG(.debug_str, 1)                       \
  DECL_DEBUG2(.debug_line, .debug_line.*, 1)      \
  DECL_DEBUG(.debug_line_str, 1)                  \
  DECL_DEBUG(.debug_names, 4)                     \
  DECL_DEBUG(.debug_frame, 4)                     \
  DECL_DEBUG(.debug_loc, 1)                       \
  DECL_DEBUG(.debug_loclists, 4)                  \
  DECL_DEBUG(.debug_macinfo, 1)                   \
  DECL_DEBUG(.debug_macro, 1)                     \
  DECL_DEBUG(.debug_ranges, POINTER_ALIGN)        \
  DECL_DEBUG(.debug_rnglists, 4)                  \
  DECL_DEBUG(.debug_addr, POINTER_ALIGN)          \
  DECL_DEBUG(.debug_aranges, 1)                   \
  DECL_DEBUG(.debug_pubnames, 1)                  \
  DECL_DEBUG(.debug_pubtypes, 1)

/* Stabs debug sections. */
#define STABS_DEBUG_SECTIONS                 \
  .stab 0 : { *(.stab) }                     \
  .stabstr 0 : { *(.stabstr) }               \
  .stab.excl 0 : { *(.stab.excl) }           \
  .stab.exclstr 0 : { *(.stab.exclstr) }     \
  .stab.index 0 : { *(.stab.index) }         \
  .stab.indexstr 0 : { *(.stab.indexstr) }

/*
 * ELF sections.
 *
 * LLVM ld also wants .symtab, .strtab, and .shstrtab placed. These look to
 * be benign to GNU ld, so we can have them here unconditionally.
 */
#define ELF_DETAILS_SECTIONS                 \
  .comment 0 : { *(.comment) *(.comment.*) } \
  .symtab 0 : { *(.symtab) }                 \
  .strtab 0 : { *(.strtab) }                 \
  .shstrtab 0 : { *(.shstrtab) }

#ifdef EFI
#define DISCARD_EFI_SECTIONS \
       *(.comment)   \
       *(.comment.*) \
       *(.note.*)
#else
#define DISCARD_EFI_SECTIONS
#endif

/* Sections to be discarded. */
#define DISCARD_SECTIONS     \
  /DISCARD/ : {              \
       *(.text.exit)         \
       *(.exit.text)         \
       *(.exit.data)         \
       *(.exitcall.exit)     \
       *(.discard)           \
       *(.discard.*)         \
       *(.eh_frame)          \
       *(.dtors)             \
       *(.dtors.*)           \
       *(.fini_array)        \
       *(.fini_array.*)      \
       DISCARD_EFI_SECTIONS  \
  }

/* List of constructs other than *_SECTIONS in alphabetical order. */

#define ACPI_DEV_INFO        \
  . = ALIGN(POINTER_ALIGN);  \
  DECL_SECTION(.adev.info) { \
      _asdevice = .;         \
      *(.adev.info)          \
      _aedevice = .;         \
  } :text

#define BUGFRAMES                               \
    __start_bug_frames_0 = .;                   \
    *(.bug_frames.0)                            \
    __stop_bug_frames_0 = .;                    \
                                                \
    __start_bug_frames_1 = .;                   \
    *(.bug_frames.1)                            \
    __stop_bug_frames_1 = .;                    \
                                                \
    __start_bug_frames_2 = .;                   \
    *(.bug_frames.2)                            \
    __stop_bug_frames_2 = .;                    \
                                                \
    __start_bug_frames_3 = .;                   \
    *(.bug_frames.3)                            \
    __stop_bug_frames_3 = .;

#define DT_DEV_INFO         \
  . = ALIGN(POINTER_ALIGN); \
  DECL_SECTION(.dev.info) { \
       _sdevice = .;        \
       *(.dev.info)         \
       _edevice = .;        \
  } :text

#ifdef CONFIG_HYPFS
#define HYPFS_PARAM              \
       . = ALIGN(POINTER_ALIGN); \
       __paramhypfs_start = .;   \
       *(.data.paramhypfs)       \
       __paramhypfs_end = .;
#else
#define HYPFS_PARAM
#endif

#ifdef CONFIG_DEBUG_LOCK_PROFILE
#define LOCK_PROFILE_DATA        \
       . = ALIGN(POINTER_ALIGN); \
       __lock_profile_start = .; \
       *(.lockprofile.data)      \
       __lock_profile_end = .;
#else
#define LOCK_PROFILE_DATA
#endif

#define PERCPU_BSS                 \
       . = ALIGN(PAGE_SIZE);       \
       __per_cpu_start = .;        \
       *(.bss.percpu.page_aligned) \
       *(.bss.percpu)              \
       . = ALIGN(SMP_CACHE_BYTES); \
       *(.bss.percpu.read_mostly)  \
       . = ALIGN(SMP_CACHE_BYTES); \
       __per_cpu_data_end = .;     \

#ifdef CONFIG_HAS_VPCI
#define VPCI_ARRAY               \
       . = ALIGN(POINTER_ALIGN); \
       __start_vpci_array = .;   \
       *(SORT(.data.vpci.*))     \
       __end_vpci_array = .;
#else
#define VPCI_ARRAY
#endif

#endif /* __XEN_LDS_H__ */
