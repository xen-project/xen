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
       *(.text.idmap)
       *(.rodata.idmap)
       *(.data.idmap)
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

        BUGFRAMES

       *(.rodata)
       *(.rodata.*)
       *(.data.rel.ro)
       *(.data.rel.ro.*)

       . = ALIGN(4);
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

  DT_DEV_INFO

#ifdef CONFIG_ACPI
  ACPI_DEV_INFO
#endif

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
  __init_data_begin = .;
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
       *(.bss.page_aligned)
       PERCPU_BSS
       *(.bss .bss.*)
       . = ALIGN(POINTER_ALIGN);
       __bss_end = .;
  } :text
  . = ALIGN(PAGE_SIZE);
  _end = . ;

  /* Section for the device tree blob (if any). */
  .dtb : { *(.dtb) } :text

  DWARF2_DEBUG_SECTIONS

  DISCARD_SECTIONS

  STABS_DEBUG_SECTIONS

  ELF_DETAILS_SECTIONS
}

/*
 * The assembly code use _start and XEN_VIRT_START interchangeably to
 * match the context.
 */
ASSERT(_start == XEN_VIRT_START, "_start != XEN_VIRT_START")
#ifdef CONFIG_MPU
/*
 * On MPU based platforms, the starting address is to be provided by user.
 * One need to check that it is 4KB aligned.
 */
ASSERT(IS_ALIGNED(_start,       4096), "starting address should be aligned to 4KB")
#endif

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
ASSERT(IS_ALIGNED(__bss_start,      POINTER_ALIGN), "__bss_start is misaligned")
ASSERT(IS_ALIGNED(__bss_end,        POINTER_ALIGN), "__bss_end is misaligned")
/* To simplify the logic in head.S, we want to _end to be page aligned */
ASSERT(IS_ALIGNED(_end,             PAGE_SIZE), "_end is not page aligned")
ASSERT((_end - _start) <= XEN_VIRT_SIZE, "Xen is too big")
