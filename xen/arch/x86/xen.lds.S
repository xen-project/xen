/* Excerpts written by Martin Mares <mj@atrey.karlin.mff.cuni.cz> */
/* Modified for i386/x86-64 Xen by Keir Fraser */

#include <xen/cache.h>
#include <xen/lib.h>

#ifndef EFI
# define DECL_SECTION_WITH_LADDR
#endif
#include <xen/xen.lds.h>
#include <asm/page.h>
#include <asm/trampoline.h>

#ifdef EFI

#define FORMAT "pei-x86-64"
#undef __XEN_VIRT_START
#define __XEN_VIRT_START __image_base__

ENTRY(efi_start)

#else /* !EFI */

#define FORMAT "elf64-x86-64"

ENTRY(start_pa)

#endif /* EFI */

#if defined(CONFIG_XEN_ALIGN_2M) || defined(EFI)
# define SECTION_ALIGN MB(2)
#else
# define SECTION_ALIGN PAGE_SIZE
#endif

#ifndef HAVE_LD_SORT_BY_INIT_PRIORITY
# define SORT_BY_INIT_PRIORITY SORT
#endif

OUTPUT_FORMAT(FORMAT, FORMAT, FORMAT)

OUTPUT_ARCH(i386:x86-64)

#ifndef EFI
PHDRS
{
  text PT_LOAD ;
  note PT_NOTE ;
}
#define PHDR(x) :x
#else
#define PHDR(x)
#endif

SECTIONS
{
#if !defined(EFI)
  . = __XEN_VIRT_START;
  __image_base__ = .;
#else
  . = __image_base__;
#endif

#if 0
/*
 * We don't really use this symbol anywhere, and the way it would get defined
 * here would result in it having a negative (wrapped to huge positive)
 * offset relative to the .text section. That, in turn, causes an assembler
 * truncation warning when including all symbols in the symbol table for Live
 * Patching code.
 */
  __2M_text_start = .;         /* Start of 2M superpages, mapped RX. */
#endif

  start_pa = ABSOLUTE(start - __XEN_VIRT_START);

  . = __XEN_VIRT_START + XEN_IMG_OFFSET;
  _start = .;
  DECL_SECTION(.text) {
        _stext = .;            /* Text and read-only data */
       *(.text.header)

       . = ALIGN(PAGE_SIZE);
       _stextentry = .;
       *(.text.entry)
       . = ALIGN(PAGE_SIZE);
       _etextentry = .;

       *(.text.kexec)          /* Page aligned in the object file. */
       kexec_reloc_end = .;

       *(.text.cold)
       *(.text.unlikely .text.*_unlikely .text.unlikely.*)

       *(.text.page_aligned)
       *(.text)
#ifdef CONFIG_CC_SPLIT_SECTIONS
       *(.text.*)
#endif
       *(.text.__x86_indirect_thunk_*)

       *(.fixup)
       *(.gnu.warning)
       _etext = .;             /* End of text section */
  } PHDR(text) = 0x9090

  . = ALIGN(SECTION_ALIGN);
  __2M_text_end = .;

  __2M_rodata_start = .;       /* Start of 2M superpages, mapped RO. */
  DECL_SECTION(.rodata) {
       _srodata = .;

       __ro_after_init_start = .;
       *(.data.ro_after_init)

       . = ALIGN(8);
       /* Exception table */
       __start___ex_table = .;
       *(.ex_table)
       __stop___ex_table = .;

       /* Pre-exception table */
       __start___pre_ex_table = .;
       *(.ex_table.pre)
       __stop___pre_ex_table = .;

       . = ALIGN(PAGE_SIZE);
       __ro_after_init_end = .;

       BUGFRAMES

       *(.rodata)
       *(.rodata.*)
       *(.data.rel.ro)
       *(.data.rel.ro.*)

#if defined(BUILD_ID) && defined(EFI) && !defined(BUILD_ID_EFI)
/*
 * No mechanism to put an PT_NOTE in the EFI file - so put
 * it in .rodata section. (notes.o supplies us with .note.gnu.build-id).
 */
       . = ALIGN(4);
       __note_gnu_build_id_start = .;
       *(.note.gnu.build-id)
       __note_gnu_build_id_end = .;
#endif
       VPCI_ARRAY
  } PHDR(text)

#if defined(CONFIG_PVH_GUEST) && !defined(EFI)
  /*
   * In principle this should be fine to live in .note (below), but let's keep
   * it separate in case anyone decided to find these notes by section name.
   */
  DECL_SECTION(.note.Xen) {
      *(.note.Xen)
  } PHDR(note) PHDR(text)
#endif

#if defined(BUILD_ID)
#if !defined(EFI)
/*
 * What a strange section name. The reason is that on ELF builds this section
 * is extracted to notes.o (which then is ingested in the EFI file). But the
 * compiler may want to inject other things in the .note which we don't care
 * about - hence this unique name.
 */
  DECL_SECTION(.note.gnu.build-id) {
       __note_gnu_build_id_start = .;
       *(.note.gnu.build-id)
       __note_gnu_build_id_end = .;
  } PHDR(note) PHDR(text)
#elif defined(BUILD_ID_EFI)
  DECL_SECTION(.buildid) {
       __note_gnu_build_id_start = .;
       *(.buildid)
       __note_gnu_build_id_end = .;
  }
#endif
#endif

#ifndef EFI
  /* Retain these just for the purpose of possible analysis tools. */
  DECL_SECTION(.note) {
       *(.note.*)
  } PHDR(note) PHDR(text)
#endif

  _erodata = .;

  . = ALIGN(SECTION_ALIGN);
  __2M_rodata_end = .;

  __2M_init_start = .;         /* Start of 2M superpages, mapped RWX (boot only). */
  . = ALIGN(PAGE_SIZE);             /* Init code and data */
  __init_begin = .;
#ifdef EFI /* EFI wants to merge all of .init.*  ELF doesn't. */
  DECL_SECTION(.init) {
#else
  DECL_SECTION(.init.text) {
#endif
       _sinittext = .;
       *(.init.text)
       *(.text.startup)
       _einittext = .;
       /*
        * Here are the replacement instructions. The linker sticks them
        * as binary blobs. The .altinstructions has enough data to get
        * the address and the length of them to patch the kernel safely.
        */
       *(.altinstr_replacement)

#ifdef EFI /* EFI wants to merge all of .init.*  ELF doesn't. */
       . = ALIGN(SMP_CACHE_BYTES);
#else
  } PHDR(text)
  DECL_SECTION(.init.data) {
#endif
       *(.init.bss.stack_aligned)

       . = ALIGN(POINTER_ALIGN);
       __initdata_cf_clobber_start = .;
       *(.init.data.cf_clobber)
       *(.init.rodata.cf_clobber)
       __initdata_cf_clobber_end = .;

       *(.init.rodata)
       *(.init.rodata.*)

       . = ALIGN(POINTER_ALIGN);
       __setup_start = .;
       *(.init.setup)
       __setup_end = .;

       __initcall_start = .;
       *(.initcallpresmp.init)
       __presmp_initcall_end = .;
       *(.initcall1.init)
       __initcall_end = .;

       *(.init.data)
       *(.init.data.rel)
       *(.init.data.rel.*)
       . = ALIGN(4);
       __trampoline_rel_start = .;
       *(.trampoline_rel)
       __trampoline_rel_stop = .;
       __trampoline_seg_start = .;
       *(.trampoline_seg)
       __trampoline_seg_stop = .;
       /*
        * struct alt_inst entries. From the header (alternative.h):
        * "Alternative instructions for different CPU types or capabilities"
        * Think locking instructions on spinlocks.
        */
       . = ALIGN(8);
        __alt_instructions = .;
        *(.altinstructions)
        __alt_instructions_end = .;

       LOCK_PROFILE_DATA

       . = ALIGN(8);
       __ctors_start = .;
       *(SORT_BY_INIT_PRIORITY(.init_array.*))
       *(SORT_BY_INIT_PRIORITY(.ctors.*))
       *(.init_array)
       *(.ctors)
       __ctors_end = .;
  } PHDR(text)

#ifndef EFI
  /*
   * With --orphan-sections=warn (or =error) we need to handle certain linker
   * generated sections.  These are all expected to be empty; respective
   * ASSERT()s can be found towards the end of this file.  Put them in the
   * text program header, just to be on the safe side against e.g. a linker
   * otherwise chosing to put them in a separate one.
   */
  DECL_SECTION(.got) {
       *(.got)
  } PHDR(text)
  DECL_SECTION(.got.plt) {
       *(.got.plt)
  } PHDR(text)
  DECL_SECTION(.igot.plt) {
       *(.igot.plt)
  } PHDR(text)
  DECL_SECTION(.iplt) {
       *(.iplt)
  } PHDR(text)
  DECL_SECTION(.plt) {
       *(.plt)
  } PHDR(text)
  DECL_SECTION(.rela) {
       *(.rela.*)
  } PHDR(text)
#endif

  . = ALIGN(SECTION_ALIGN);
  __init_end = .;
  __2M_init_end = .;

  __2M_rwdata_start = .;       /* Start of 2M superpages, mapped RW. */
  . = ALIGN(SMP_CACHE_BYTES);
  DECL_SECTION(.data.read_mostly) {
       *(.data.read_mostly)
       . = ALIGN(8);
       __start_schedulers_array = .;
       *(.data.schedulers)
       __end_schedulers_array = .;

       HYPFS_PARAM
  } PHDR(text)

  DECL_SECTION(.data) {
       *(.data.page_aligned)
       *(.data .data.*)
  } PHDR(text)

  DECL_SECTION(.bss) {
       __bss_start = .;
       *(.bss.page_aligned*)
       PERCPU_BSS
       *(.bss .bss.*)
       . = ALIGN(POINTER_ALIGN);
       __bss_end = .;
  } PHDR(text)
  _end = . ;

  __2M_rwdata_end = ALIGN(SECTION_ALIGN);

#ifdef EFI
  .reloc ALIGN(4) : {
    __base_relocs_start = .;
    *(.reloc)
    __base_relocs_end = .;
  }
#elif defined(XEN_BUILD_EFI)
  /*
   * Due to the way EFI support is currently implemented, these two symbols
   * need to be defined.  Their precise values shouldn't matter (the consuming
   * function doesn't get called), but to be on the safe side both values would
   * better match.  Of course the need to be reachable by the relocations
   * referencing them.
   */
  PROVIDE(__base_relocs_start = .);
  PROVIDE(__base_relocs_end = .);
#else
  efi = .;
#endif

  DWARF2_DEBUG_SECTIONS

#ifdef CONFIG_HYPERV_GUEST
  hv_hcall_page = ABSOLUTE(HV_HCALL_PAGE - XEN_VIRT_START + __XEN_VIRT_START);
#endif

  DISCARD_SECTIONS

#ifndef EFI
  STABS_DEBUG_SECTIONS

  ELF_DETAILS_SECTIONS
#endif
}

ASSERT(__2M_rwdata_end <= XEN_VIRT_END - XEN_VIRT_START + __XEN_VIRT_START -
                          FIXADDR_X_SIZE -
                          NR_CPUS * PAGE_SIZE,
       "Xen image overlaps stubs area")

#ifdef CONFIG_KEXEC
ASSERT(kexec_reloc_end - kexec_reloc <= PAGE_SIZE, "kexec_reloc is too large")
#endif

/* The Multiboot setup paths relies on this to simplify superpage PTE creation. */
ASSERT(IS_ALIGNED(_start,            MB(2)), "_start misaligned")

ASSERT(IS_ALIGNED(__2M_text_end,     SECTION_ALIGN), "__2M_text_end misaligned")
ASSERT(IS_ALIGNED(__2M_rodata_start, SECTION_ALIGN), "__2M_rodata_start misaligned")
ASSERT(IS_ALIGNED(__2M_rodata_end,   SECTION_ALIGN), "__2M_rodata_end misaligned")
ASSERT(IS_ALIGNED(__2M_init_start,   SECTION_ALIGN), "__2M_init_start misaligned")
ASSERT(IS_ALIGNED(__2M_init_end,     SECTION_ALIGN), "__2M_init_end misaligned")
ASSERT(IS_ALIGNED(__2M_rwdata_start, SECTION_ALIGN), "__2M_rwdata_start misaligned")
ASSERT(IS_ALIGNED(__2M_rwdata_end,   SECTION_ALIGN), "__2M_rwdata_end misaligned")

ASSERT(IS_ALIGNED(cpu0_stack, STACK_SIZE), "cpu0_stack misaligned")

ASSERT(IS_ALIGNED(__init_begin, PAGE_SIZE), "__init_begin misaligned")
ASSERT(IS_ALIGNED(__init_end,   PAGE_SIZE), "__init_end misaligned")

ASSERT(IS_ALIGNED(trampoline_start, 4), "trampoline_start misaligned")
ASSERT(IS_ALIGNED(trampoline_end,   4), "trampoline_end misaligned")
ASSERT(IS_ALIGNED(__bss_start,      8), "__bss_start misaligned")
ASSERT(IS_ALIGNED(__bss_end,        8), "__bss_end misaligned")

#ifndef EFI
ASSERT(!SIZEOF(.got),      ".got non-empty")
/*
 * At least GNU ld 2.30 and earlier fail to discard the generic part of
 * .got.plt when no actual entries were allocated. Permit this case alongside
 * the section being empty.
 */
ASSERT(!SIZEOF(.got.plt) || SIZEOF(.got.plt) == 3 * 8,
       "unexpected .got.plt size")
ASSERT(!SIZEOF(.igot.plt), ".igot.plt non-empty")
ASSERT(!SIZEOF(.iplt),     ".iplt non-empty")
ASSERT(!SIZEOF(.plt),      ".plt non-empty")
ASSERT(!SIZEOF(.rela),     "leftover relocations")
#endif

/*
 * The permanent trampoline resides in a single 4k page.  Placement logic
 * takes care to ensure that trampoline_phys is page aligned.
 *
 * The wakeup stack wants to reside in the same page and wants to be at least
 * 3k in size, so make sure the text/data fits in 1k.
 */
ASSERT((trampoline_perm_end - trampoline_start) <= 1024,
       "Permentant trampoline too large")

ASSERT((trampoline_end - trampoline_start) < TRAMPOLINE_HEAP_END - MBI_SPACE_MIN,
    "not enough room for trampoline and mbi data")
