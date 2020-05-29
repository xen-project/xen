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
#define DECL_SECTION(x) x : AT(ADDR(x) - __XEN_VIRT_START)

ENTRY(start_pa)

#endif /* EFI */

#if defined(CONFIG_XEN_ALIGN_2M) || defined(EFI)
# define SECTION_ALIGN MB(2)
#else
# define SECTION_ALIGN PAGE_SIZE
#endif

OUTPUT_FORMAT(FORMAT, FORMAT, FORMAT)

OUTPUT_ARCH(i386:x86-64)

PHDRS
{
  text PT_LOAD ;
#if (defined(BUILD_ID) || defined (CONFIG_PVH_GUEST)) && !defined(EFI)
  note PT_NOTE ;
#endif
}
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
       *(.text)
       *(.text.__x86_indirect_thunk_*)
       *(.text.page_aligned)

       . = ALIGN(PAGE_SIZE);
       _stextentry = .;
       *(.text.entry)
       . = ALIGN(PAGE_SIZE);
       _etextentry = .;

       *(.text.cold)
       *(.text.unlikely)
       *(.fixup)
       *(.text.kexec)
       *(.gnu.warning)
       _etext = .;             /* End of text section */
  } :text = 0x9090

  . = ALIGN(SECTION_ALIGN);
  __2M_text_end = .;

  __2M_rodata_start = .;       /* Start of 2M superpages, mapped RO. */
  DECL_SECTION(.rodata) {
       _srodata = .;
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
       . = ALIGN(8);
       /* Exception table */
       __start___ex_table = .;
       *(.ex_table)
       __stop___ex_table = .;

       /* Pre-exception table */
       __start___pre_ex_table = .;
       *(.ex_table.pre)
       __stop___pre_ex_table = .;

       . = ALIGN(POINTER_ALIGN);
       __param_start = .;
       *(.data.param)
       __param_end = .;

#if defined(CONFIG_HAS_VPCI) && defined(CONFIG_LATE_HWDOM)
       . = ALIGN(POINTER_ALIGN);
       __start_vpci_array = .;
       *(SORT(.data.vpci.*))
       __end_vpci_array = .;
#endif
  } :text

#if defined(CONFIG_PVH_GUEST) && !defined(EFI)
  DECL_SECTION(.note.Xen) {
      *(.note.Xen)
  } :note :text
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
  } :note :text
#elif defined(BUILD_ID_EFI)
  DECL_SECTION(.buildid) {
       __note_gnu_build_id_start = .;
       *(.buildid)
       __note_gnu_build_id_end = .;
  } :text
#endif
#endif

/*
 * ELF builds are linked to a fixed virtual address, and in principle
 * shouldn't have a .reloc section.  However, due to the way EFI support is
 * currently implemented, retaining the .reloc section is necessary.
 */
#if defined(XEN_BUILD_EFI) && !defined(EFI)
  . = ALIGN(4);
  DECL_SECTION(.reloc) {
    *(.reloc)
  } :text
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
       /*
        * Here are the replacement instructions. The linker sticks them
        * as binary blobs. The .altinstructions has enough data to get
        * the address and the length of them to patch the kernel safely.
        */
       *(.altinstr_replacement)
       _einittext = .;

#ifdef EFI /* EFI wants to merge all of .init.*  ELF doesn't. */
       . = ALIGN(SMP_CACHE_BYTES);
#else
  } :text
  DECL_SECTION(.init.data) {
#endif

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
       *(.ctors)
       *(.init_array)
       *(SORT(.init_array.*))
       __ctors_end = .;

#if defined(CONFIG_HAS_VPCI) && !defined(CONFIG_LATE_HWDOM)
       . = ALIGN(POINTER_ALIGN);
       __start_vpci_array = .;
       *(SORT(.data.vpci.*))
       __end_vpci_array = .;
#endif
  } :text

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
  } :text

  DECL_SECTION(.data) {
       *(.data.page_aligned)
       *(.data)
       *(.data.rel)
       *(.data.rel.*)
       CONSTRUCTORS
  } :text

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
  } :text
  _end = . ;

  . = ALIGN(SECTION_ALIGN);
  __2M_rwdata_end = .;

#ifdef EFI
  . = ALIGN(4);
  DECL_SECTION(.reloc) {
    *(.reloc)
  } :text
  /* Trick the linker into setting the image size to exactly 16Mb. */
  . = ALIGN(__section_alignment__);
  DECL_SECTION(.pad) {
    . = ALIGN(MB(16));
  } :text
#endif

#ifndef XEN_BUILD_EFI
  efi = .;
#endif

#ifdef CONFIG_HYPERV_GUEST
  hv_hcall_page = ABSOLUTE(HV_HCALL_PAGE - XEN_VIRT_START + __XEN_VIRT_START);
#endif

  /* Sections to be discarded */
  /DISCARD/ : {
       *(.exit.text)
       *(.exit.data)
       *(.exitcall.exit)
       *(.discard)
       *(.discard.*)
       *(.eh_frame)
#ifdef EFI
       *(.comment)
       *(.comment.*)
       *(.note.Xen)
#endif
  }

  /* Stabs debugging sections.  */
  .stab 0 : { *(.stab) }
  .stabstr 0 : { *(.stabstr) }
  .stab.excl 0 : { *(.stab.excl) }
  .stab.exclstr 0 : { *(.stab.exclstr) }
  .stab.index 0 : { *(.stab.index) }
  .stab.indexstr 0 : { *(.stab.indexstr) }
  .comment 0 : { *(.comment) }
}

ASSERT(__2M_rwdata_end <= XEN_VIRT_END - XEN_VIRT_START + __XEN_VIRT_START -
                          FIXADDR_X_SIZE -
                          NR_CPUS * PAGE_SIZE,
       "Xen image overlaps stubs area")

#ifdef CONFIG_KEXEC
ASSERT(kexec_reloc_size - kexec_reloc <= PAGE_SIZE, "kexec_reloc is too large")
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
