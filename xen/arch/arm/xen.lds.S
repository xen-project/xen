/* Excerpts written by Martin Mares <mj@atrey.karlin.mff.cuni.cz> */
/* Modified for i386/x86-64 Xen by Keir Fraser */
/* Modified for ARM Xen by Ian Campbell */

#include <xen/cache.h>
#include <xen/lib.h>
#include <xen/xen.lds.h>
#include <asm/page.h>
#undef ENTRY
#undef ALIGN

ENTRY(start)

#if defined(__arm__)
#define FORMAT arm
#elif defined(__aarch64__)
#define FORMAT aarch64
#endif

OUTPUT_ARCH(FORMAT)

PHDRS
{
  text PT_LOAD ;
#if defined(BUILD_ID)
  note PT_NOTE ;
#endif
}
SECTIONS
{
  . = XEN_VIRT_START;
  _start = .;
  .text : {
       _stext = .;             /* Text section */
       _idmap_start = .;
       *(.text.header)
       _idmap_end = .;

       *(.text.cold)
       *(.text.unlikely .text.*_unlikely .text.unlikely.*)

       *(.text)
#ifdef CONFIG_CC_SPLIT_SECTIONS
       *(.text.*)
#endif

       *(.fixup)
       *(.gnu.warning)
       _etext = .;             /* End of text section */
  } :text = 0x9090

  . = ALIGN(PAGE_SIZE);
  .rodata : {
        _srodata = .;          /* Read-only data */
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

       __proc_info_start = .;
       *(.proc.info)
       __proc_info_end = .;

       VPCI_ARRAY
  } :text

#if defined(BUILD_ID)
  . = ALIGN(4);
  .note.gnu.build-id : {
       __note_gnu_build_id_start = .;
       *(.note.gnu.build-id)
       __note_gnu_build_id_end = .;
  } :note :text
#endif
  _erodata = .;                /* End of read-only data */

  . = ALIGN(PAGE_SIZE);
  .data.ro_after_init : {
      __ro_after_init_start = .;
      *(.data.ro_after_init)
      . = ALIGN(PAGE_SIZE);
      __ro_after_init_end = .;
  } : text

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
  } :text

  . = ALIGN(SMP_CACHE_BYTES);
  .data : {                    /* Data */
       *(.data.page_aligned)
       . = ALIGN(8);
       __start_schedulers_array = .;
       *(.data.schedulers)
       __end_schedulers_array = .;

       HYPFS_PARAM

       *(.data .data.*)
       CONSTRUCTORS
  } :text

  . = ALIGN(8);
  .arch.info : {
      _splatform = .;
      *(.arch.info)
      _eplatform = .;
  } :text

  . = ALIGN(8);
  .dev.info : {
      _sdevice = .;
      *(.dev.info)
      _edevice = .;
  } :text

  . = ALIGN(8);
  .adev.info : {
      _asdevice = .;
      *(.adev.info)
      _aedevice = .;
  } :text

  . = ALIGN(8);
  .teemediator.info : {
      _steemediator = .;
      *(.teemediator.info)
      _eteemediator = .;
  } :text

  . = ALIGN(PAGE_SIZE);             /* Init code and data */
  __init_begin = .;
  .init.text : {
       _sinittext = .;
       *(.init.text)
       _einittext = .;
       . = ALIGN(PAGE_SIZE);        /* Avoid mapping alt insns executable */
       *(.altinstr_replacement)
  } :text
  . = ALIGN(PAGE_SIZE);
  .init.data : {
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

       . = ALIGN(4);
       __alt_instructions = .;
       *(.altinstructions)
       __alt_instructions_end = .;

       LOCK_PROFILE_DATA

       *(.init.data)
       *(.init.data.rel)
       *(.init.data.rel.*)

       . = ALIGN(8);
       __ctors_start = .;
       *(.ctors)
       *(.init_array)
       *(SORT(.init_array.*))
       __ctors_end = .;
  } :text
  __init_end_efi = .;
  . = ALIGN(STACK_SIZE);
  __init_end = .;

  .bss : {                     /* BSS */
       __bss_start = .;
       *(.bss.stack_aligned)
       . = ALIGN(PAGE_SIZE);
       *(.bss.page_aligned)
       . = ALIGN(PAGE_SIZE);
       __per_cpu_start = .;
       *(.bss.percpu.page_aligned)
       *(.bss.percpu)
       . = ALIGN(SMP_CACHE_BYTES);
       *(.bss.percpu.read_mostly)
       . = ALIGN(SMP_CACHE_BYTES);
       __per_cpu_data_end = .;
       *(.bss .bss.*)
       . = ALIGN(POINTER_ALIGN);
       __bss_end = .;
  } :text
  _end = . ;

  /* Section for the device tree blob (if any). */
  .dtb : { *(.dtb) } :text

  DWARF2_DEBUG_SECTIONS

  DISCARD_SECTIONS

  STABS_DEBUG_SECTIONS

  ELF_DETAILS_SECTIONS
}

/*
 * We require that Xen is loaded at a page boundary, so this ensures that any
 * code running on the identity map cannot cross a section boundary.
 */
ASSERT(IS_ALIGNED(_idmap_start, PAGE_SIZE), "_idmap_start should be page-aligned")
ASSERT(_idmap_end - _idmap_start <= PAGE_SIZE, "Identity mapped code is larger than a page size")

/*
 * __init_[begin|end] MUST be at word size boundary otherwise we cannot
 * write fault instructions in the space properly.
 */
ASSERT(IS_ALIGNED(__init_begin,     4), "__init_begin is misaligned")
ASSERT(IS_ALIGNED(__init_end,       4), "__init_end is misaligned")
