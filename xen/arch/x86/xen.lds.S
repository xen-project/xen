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
}
SECTIONS
{
#if !defined(EFI)
  . = __XEN_VIRT_START;
  __image_base__ = .;
#endif
  . = __XEN_VIRT_START + 0x100000;
  _start = .;
  .text : {
        _stext = .;            /* Text and read-only data */
       *(.text)
       *(.text.cold)
       *(.text.unlikely)
       *(.fixup)
       *(.gnu.warning)
       _etext = .;             /* End of text section */
  } :text = 0x9090

  .rodata : {
       /* Bug frames table */
       . = ALIGN(4);
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
  } :text

  . = ALIGN(SMP_CACHE_BYTES);
  .data.read_mostly : {
       /* Exception table */
       __start___ex_table = .;
       *(.ex_table)
       __stop___ex_table = .;

       /* Pre-exception table */
       __start___pre_ex_table = .;
       *(.ex_table.pre)
       __stop___pre_ex_table = .;

       *(.data.read_mostly)
       *(.data.rel.ro)
       *(.data.rel.ro.*)
  } :text

  .data : {                    /* Data */
       . = ALIGN(PAGE_SIZE);
       *(.data.page_aligned)
       *(.data)
       *(.data.rel)
       *(.data.rel.*)
       CONSTRUCTORS
  } :text

#ifdef LOCK_PROFILE
  . = ALIGN(32);
  __lock_profile_start = .;
  .lockprofile.data : { *(.lockprofile.data) } :text
  __lock_profile_end = .;
#endif

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
       *(.init.rodata.str*)
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
       __ctors_end = .;
  } :text
  . = ALIGN(32);
  .init.setup : {
       __setup_start = .;
       *(.init.setup)
       __setup_end = .;
  } :text
  .initcall.init : {
       __initcall_start = .;
       *(.initcallpresmp.init)
       __presmp_initcall_end = .;
       *(.initcall1.init)
       __initcall_end = .;
  } :text
  .xsm_initcall.init : {
       __xsm_initcall_start = .;
       *(.xsm_initcall.init)
       __xsm_initcall_end = .;
  } :text
  . = ALIGN(STACK_SIZE);
  __init_end = .;

  .bss : {                     /* BSS */
       __bss_start = .;
       *(.bss.stack_aligned)
       . = ALIGN(PAGE_SIZE);
       *(.bss.page_aligned)
       *(.bss)
       . = ALIGN(SMP_CACHE_BYTES);
       __per_cpu_start = .;
       *(.bss.percpu)
       . = ALIGN(SMP_CACHE_BYTES);
       *(.bss.percpu.read_mostly)
       . = ALIGN(SMP_CACHE_BYTES);
       __per_cpu_data_end = .;
  } :text
  _end = . ;

#ifdef EFI
  . = ALIGN(4);
  .reloc : {
    *(.reloc)
  } :text
  /* Trick the linker into setting the image size to exactly 16Mb. */
  . = ALIGN(__section_alignment__);
  .pad : {
    . = ALIGN(0x1000000);
  } :text
#else
  efi = .;
#endif

  /* Sections to be discarded */
  /DISCARD/ : {
       *(.exit.text)
       *(.exit.data)
       *(.exitcall.exit)
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

ASSERT(kexec_reloc_size - kexec_reloc <= PAGE_SIZE, "kexec_reloc is too large")
