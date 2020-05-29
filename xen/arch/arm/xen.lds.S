/* Excerpts written by Martin Mares <mj@atrey.karlin.mff.cuni.cz> */
/* Modified for i386/x86-64 Xen by Keir Fraser */
/* Modified for ARM Xen by Ian Campbell */

#include <xen/cache.h>
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
        _stext = .;            /* Text section */
       *(.text)
       *(.text.cold)
       *(.text.unlikely)
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
       *(.rodata)
       *(.rodata.*)
       *(.data.rel.ro)
       *(.data.rel.ro.*)

       . = ALIGN(POINTER_ALIGN);
       __param_start = .;
       *(.data.param)
       __param_end = .;

       __proc_info_start = .;
       *(.proc.info)
       __proc_info_end = .;

#if defined(CONFIG_HAS_VPCI) && defined(CONFIG_LATE_HWDOM)
       . = ALIGN(POINTER_ALIGN);
       __start_vpci_array = .;
       *(SORT(.data.vpci.*))
       __end_vpci_array = .;
#endif
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

  .data : {                    /* Data */
       . = ALIGN(PAGE_SIZE);
       *(.data.page_aligned)
       *(.data)
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

       *(.data.rel)
       *(.data.rel.*)
       CONSTRUCTORS
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
       . = ALIGN(4);
       *(.altinstr_replacement)

#ifdef CONFIG_DEBUG_LOCK_PROFILE
       . = ALIGN(POINTER_ALIGN);
       __lock_profile_start = .;
       *(.lockprofile.data)
       __lock_profile_end = .;
#endif

       *(.init.data)
       *(.init.data.rel)
       *(.init.data.rel.*)

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
       *(.bss)
       . = ALIGN(POINTER_ALIGN);
       __bss_end = .;
  } :text
  _end = . ;

#ifdef CONFIG_DTB_FILE
  /* Section for the device tree blob (if any). */
  _sdtb = .;
  .dtb : { *(.dtb) } :text
#endif

  /* Sections to be discarded */
  /DISCARD/ : {
       *(.exit.text)
       *(.exit.data)
       *(.exitcall.exit)
       *(.eh_frame)
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

/*
 * We require that Xen is loaded at a 4K boundary, so this ensures that any
 * code running on the boot time identity map cannot cross a section boundary.
 */
ASSERT( _end_boot - start <= PAGE_SIZE, "Boot code is larger than 4K")
/*
 * __init_[begin|end] MUST be at word size boundary otherwise we cannot
 * write fault instructions in the space properly.
 */
ASSERT(IS_ALIGNED(__init_begin,     4), "__init_begin is misaligned")
ASSERT(IS_ALIGNED(__init_end,       4), "__init_end is misaligned")
