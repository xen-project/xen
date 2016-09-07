/* Excerpts written by Martin Mares <mj@atrey.karlin.mff.cuni.cz> */
/* Modified for i386/x86-64 Xen by Keir Fraser */

#include <xen/config.h>
#include <xen/cache.h>
#include <asm/page.h>
#include <asm/percpu.h>
#undef ENTRY
#undef ALIGN

#ifdef EFI

#define FORMAT "pei-x86-64"
#undef __XEN_VIRT_START
#define __XEN_VIRT_START __image_base__

ENTRY(efi_start)

#else /* !EFI */

#define FORMAT "elf64-x86-64"

ENTRY(start)

#endif /* EFI */

OUTPUT_FORMAT(FORMAT, FORMAT, FORMAT)

OUTPUT_ARCH(i386:x86-64)

PHDRS
{
  text PT_LOAD ;
#if defined(BUILD_ID) && !defined(EFI)
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

  . = __XEN_VIRT_START + MB(1);
  _start = .;
  .text : {
        _stext = .;            /* Text and read-only data */
       *(.text)
       *(.text.cold)
       *(.text.unlikely)
       *(.fixup)
       *(.text.kexec)
       *(.gnu.warning)
       _etext = .;             /* End of text section */
  } :text = 0x9090

#ifdef EFI
  . = ALIGN(MB(2));
#else
  . = ALIGN(PAGE_SIZE);
#endif
  __2M_text_end = .;

  __2M_rodata_start = .;       /* Start of 2M superpages, mapped RO. */
  .rodata : {
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

#ifdef CONFIG_LOCK_PROFILE
       . = ALIGN(POINTER_ALIGN);
       __lock_profile_start = .;
       *(.lockprofile.data)
       __lock_profile_end = .;
#endif
  } :text

#if defined(BUILD_ID)
#if !defined(EFI)
/*
 * What a strange section name. The reason is that on ELF builds this section
 * is extracted to notes.o (which then is ingested in the EFI file). But the
 * compiler may want to inject other things in the .note which we don't care
 * about - hence this unique name.
 */
  .note.gnu.build-id : {
       __note_gnu_build_id_start = .;
       *(.note.gnu.build-id)
       __note_gnu_build_id_end = .;
  } :note :text
#elif defined(BUILD_ID_EFI)
  .buildid : {
       __note_gnu_build_id_start = .;
       *(.buildid)
       __note_gnu_build_id_end = .;
  } :text
#endif
#endif
  _erodata = .;

#ifdef EFI
  . = ALIGN(MB(2));
#else
  . = ALIGN(PAGE_SIZE);
#endif
  __2M_rodata_end = .;

  __2M_init_start = .;         /* Start of 2M superpages, mapped RWX (boot only). */
  . = ALIGN(PAGE_SIZE);             /* Init code and data */
  __init_begin = .;
  .init.text : {
       _sinittext = .;
       *(.init.text)
       /*
        * Here are the replacement instructions. The linker sticks them
        * as binary blobs. The .altinstructions has enough data to get
        * the address and the length of them to patch the kernel safely.
        */
       *(.altinstr_replacement)
       _einittext = .;
  } :text
  .init.data : {
       *(.init.rodata)
       *(.init.rodata.rel)
       *(.init.rodata.str*)

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

       . = ALIGN(8);
       __ctors_start = .;
       *(.ctors)
       *(.init_array)
       *(SORT(.init_array.*))
       __ctors_end = .;
  } :text

#ifdef EFI
  . = ALIGN(MB(2));
#else
  . = ALIGN(PAGE_SIZE);
#endif
  __init_end = .;
  __2M_init_end = .;

  __2M_rwdata_start = .;       /* Start of 2M superpages, mapped RW. */
  . = ALIGN(SMP_CACHE_BYTES);
  .data.read_mostly : {
       *(.data.read_mostly)
       . = ALIGN(8);
       __start_schedulers_array = .;
       *(.data.schedulers)
       __end_schedulers_array = .;
       *(.data.rel.ro)
       *(.data.rel.ro.*)
  } :text

  .data : {                    /* Data */
       *(.data.page_aligned)
       *(.data)
       *(.data.rel)
       *(.data.rel.*)
       CONSTRUCTORS
  } :text

  .bss : {                     /* BSS */
       __bss_start = .;
       *(.bss.stack_aligned)
       *(.bss.page_aligned*)
       *(.bss)
       . = ALIGN(SMP_CACHE_BYTES);
       __per_cpu_start = .;
       *(.bss.percpu)
       . = ALIGN(SMP_CACHE_BYTES);
       *(.bss.percpu.read_mostly)
       . = ALIGN(SMP_CACHE_BYTES);
       __per_cpu_data_end = .;
       __bss_end = .;
  } :text
  _end = . ;

#ifdef EFI
  . = ALIGN(MB(2));
#else
  . = ALIGN(PAGE_SIZE);
#endif
  __2M_rwdata_end = .;

#ifdef EFI
  . = ALIGN(4);
  .reloc : {
    *(.reloc)
  } :text
  /* Trick the linker into setting the image size to exactly 16Mb. */
  . = ALIGN(__section_alignment__);
  .pad : {
    . = ALIGN(MB(16));
  } :text
#else
  efi = .;
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

ASSERT(__image_base__ > XEN_VIRT_START ||
       _end <= XEN_VIRT_END - NR_CPUS * PAGE_SIZE,
       "Xen image overlaps stubs area")

#ifdef CONFIG_KEXEC
ASSERT(kexec_reloc_size - kexec_reloc <= PAGE_SIZE, "kexec_reloc is too large")
#endif

#ifdef EFI
ASSERT(IS_ALIGNED(__2M_text_end,     MB(2)), "__2M_text_end misaligned")
ASSERT(IS_ALIGNED(__2M_rodata_start, MB(2)), "__2M_rodata_start misaligned")
ASSERT(IS_ALIGNED(__2M_rodata_end,   MB(2)), "__2M_rodata_end misaligned")
ASSERT(IS_ALIGNED(__2M_init_start,   MB(2)), "__2M_init_start misaligned")
ASSERT(IS_ALIGNED(__2M_init_end,     MB(2)), "__2M_init_end misaligned")
ASSERT(IS_ALIGNED(__2M_rwdata_start, MB(2)), "__2M_rwdata_start misaligned")
ASSERT(IS_ALIGNED(__2M_rwdata_end,   MB(2)), "__2M_rwdata_end misaligned")
#else
ASSERT(IS_ALIGNED(__2M_text_end,     PAGE_SIZE), "__2M_text_end misaligned")
ASSERT(IS_ALIGNED(__2M_rodata_start, PAGE_SIZE), "__2M_rodata_start misaligned")
ASSERT(IS_ALIGNED(__2M_rodata_end,   PAGE_SIZE), "__2M_rodata_end misaligned")
ASSERT(IS_ALIGNED(__2M_init_start,   PAGE_SIZE), "__2M_init_start misaligned")
ASSERT(IS_ALIGNED(__2M_init_end,     PAGE_SIZE), "__2M_init_end misaligned")
ASSERT(IS_ALIGNED(__2M_rwdata_start, PAGE_SIZE), "__2M_rwdata_start misaligned")
ASSERT(IS_ALIGNED(__2M_rwdata_end,   PAGE_SIZE), "__2M_rwdata_end misaligned")
#endif

ASSERT(IS_ALIGNED(cpu0_stack, STACK_SIZE), "cpu0_stack misaligned")

ASSERT(IS_ALIGNED(__init_begin, PAGE_SIZE), "__init_begin misaligned")
ASSERT(IS_ALIGNED(__init_end,   PAGE_SIZE), "__init_end misaligned")

ASSERT(IS_ALIGNED(trampoline_start, 4), "trampoline_start misaligned")
ASSERT(IS_ALIGNED(trampoline_end,   4), "trampoline_end misaligned")
ASSERT(IS_ALIGNED(__bss_start,      4), "__bss_start misaligned")
ASSERT(IS_ALIGNED(__bss_end,        4), "__bss_end misaligned")
