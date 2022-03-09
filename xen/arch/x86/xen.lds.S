/* Excerpts written by Martin Mares <mj@atrey.karlin.mff.cuni.cz> */
/* Modified for i386/x86-64 Xen by Keir Fraser */

#include <xen/cache.h>
#include <asm/page.h>
#undef ENTRY
#undef ALIGN

#ifdef EFI

#define FORMAT "pei-x86-64"
#undef __XEN_VIRT_START
#define __XEN_VIRT_START __image_base__
#define DECL_SECTION(x) x :

ENTRY(efi_start)

#else /* !EFI */

#define FORMAT "elf64-x86-64"
#define DECL_SECTION(x) #x : AT(ADDR(#x) - __XEN_VIRT_START)

ENTRY(start_pa)

#endif /* EFI */

#if defined(CONFIG_XEN_ALIGN_2M) || defined(EFI)
# define SECTION_ALIGN MB(2)
#else
# define SECTION_ALIGN PAGE_SIZE
#endif

OUTPUT_FORMAT(FORMAT, FORMAT, FORMAT)

OUTPUT_ARCH(i386:x86-64)

#ifndef EFI
PHDRS
{
  text PT_LOAD ;
#if defined(BUILD_ID) || defined(CONFIG_PVH_GUEST)
  note PT_NOTE ;
#endif
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

       *(.text)
       *(.text.__x86_indirect_thunk_*)
       *(.text.page_aligned)

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

       /* Bug frames table */
       __start_bug_frames = .;
       *(.bug_frames.0)
       __stop_bug_frames_0 = .;
       *(.bug_frames.1)
       __stop_bug_frames_1 = .;
       *(.bug_frames.2)
       __stop_bug_frames_2 = .;
       *(.bug_frames.3)
       __stop_bug_frames_3 = .;

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
#ifdef CONFIG_HAS_VPCI
       . = ALIGN(POINTER_ALIGN);
       __start_vpci_array = .;
       *(SORT(.data.vpci.*))
       __end_vpci_array = .;
#endif
  } PHDR(text)

#if defined(CONFIG_PVH_GUEST) && !defined(EFI)
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

#ifdef CONFIG_DEBUG_LOCK_PROFILE
       . = ALIGN(POINTER_ALIGN);
       __lock_profile_start = .;
       *(.lockprofile.data)
       __lock_profile_end = .;
#endif

       . = ALIGN(8);
       __ctors_start = .;
       *(SORT_BY_INIT_PRIORITY(.init_array.*))
       *(SORT_BY_INIT_PRIORITY(.ctors.*))
       *(.init_array)
       *(.ctors)
       __ctors_end = .;
  } PHDR(text)

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

#ifdef CONFIG_HYPFS
       . = ALIGN(8);
       __paramhypfs_start = .;
       *(.data.paramhypfs)
       __paramhypfs_end = .;
#endif
  } PHDR(text)

  DECL_SECTION(.data) {
       *(.data.page_aligned)
       *(.data)
       *(.data.rel)
       *(.data.rel.*)
  } PHDR(text)

  DECL_SECTION(.bss) {
       __bss_start = .;
       *(.bss.stack_aligned)
       *(.bss.page_aligned*)
       . = ALIGN(PAGE_SIZE);
       __per_cpu_start = .;
       *(.bss.percpu.page_aligned)
       *(.bss.percpu)
       . = ALIGN(SMP_CACHE_BYTES);
       *(.bss.percpu.read_mostly)
       . = ALIGN(SMP_CACHE_BYTES);
       __per_cpu_data_end = .;
       *(.bss)
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
  /*
   * Explicitly list debug section for the PE output so that they don't end
   * up at VA 0 which is below image base and thus invalid. Also use the
   * NOLOAD directive, despite currently ignored by ld for PE output, in
   * order to record that we'd prefer these sections to not be loaded into
   * memory.
   *
   * Note that we're past _end here, so if these sections get loaded they'll
   * be discarded at runtime anyway.
   */
  .debug_abbrev ALIGN(1) (NOLOAD) : {
     *(.debug_abbrev)
  }
  .debug_info ALIGN(1) (NOLOAD) : {
    *(.debug_info)
    *(.gnu.linkonce.wi.*)
  }
  .debug_types ALIGN(1) (NOLOAD) : {
    *(.debug_types)
  }
  .debug_str ALIGN(1) (NOLOAD) : {
    *(.debug_str)
  }
  .debug_line ALIGN(1) (NOLOAD) : {
    *(.debug_line)
    *(.debug_line.*)
  }
  .debug_line_str ALIGN(1) (NOLOAD) : {
    *(.debug_line_str)
  }
  .debug_names ALIGN(4) (NOLOAD) : {
    *(.debug_names)
  }
  .debug_frame ALIGN(4) (NOLOAD) : {
    *(.debug_frame)
  }
  .debug_loc ALIGN(1) (NOLOAD) : {
    *(.debug_loc)
  }
  .debug_loclists ALIGN(4) (NOLOAD) : {
    *(.debug_loclists)
  }
  .debug_ranges ALIGN(8) (NOLOAD) : {
    *(.debug_ranges)
  }
  .debug_rnglists ALIGN(4) (NOLOAD) : {
    *(.debug_rnglists)
  }
  .debug_addr ALIGN(8) (NOLOAD) : {
    *(.debug_addr)
  }
  .debug_aranges ALIGN(1) (NOLOAD) : {
    *(.debug_aranges)
  }
  .debug_pubnames ALIGN(1) (NOLOAD) : {
    *(.debug_pubnames)
  }
  .debug_pubtypes ALIGN(1) (NOLOAD) : {
    *(.debug_pubtypes)
  }
  /* Trick the linker into setting the image size to no less than 16Mb. */
  __image_end__ = .;
  .pad ALIGN(__section_alignment__) : {
    . = __image_end__ < __image_base__ + MB(16) ? ALIGN(MB(16)) : .;
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

#ifdef CONFIG_HYPERV_GUEST
  hv_hcall_page = ABSOLUTE(HV_HCALL_PAGE - XEN_VIRT_START + __XEN_VIRT_START);
#endif

  /* Sections to be discarded */
  /DISCARD/ : {
       *(.text.exit)
       *(.exit.text)
       *(.exit.data)
       *(.exitcall.exit)
       *(.discard)
       *(.discard.*)
       *(.eh_frame)
       *(.dtors)
       *(.dtors.*)
       *(.fini_array)
       *(.fini_array.*)
#ifdef EFI
       *(.comment)
       *(.comment.*)
       *(.note.Xen)
       *(.note.gnu.*)
#endif
  }

#ifndef EFI
  /* Stabs debugging sections.  */
  .stab 0 : { *(.stab) }
  .stabstr 0 : { *(.stabstr) }
  .stab.excl 0 : { *(.stab.excl) }
  .stab.exclstr 0 : { *(.stab.exclstr) }
  .stab.index 0 : { *(.stab.index) }
  .stab.indexstr 0 : { *(.stab.indexstr) }
  .comment 0 : { *(.comment) }
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

ASSERT((trampoline_end - trampoline_start) < TRAMPOLINE_SPACE - MBI_SPACE_MIN,
    "not enough room for trampoline and mbi data")
ASSERT((wakeup_stack - wakeup_stack_start) >= WAKEUP_STACK_MIN,
    "wakeup stack too small")

/* Plenty of boot code assumes that Xen isn't larger than 16M. */
ASSERT(_end - _start <= MB(16), "Xen too large for early-boot assumptions")
