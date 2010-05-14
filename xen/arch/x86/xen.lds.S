/* Excerpts written by Martin Mares <mj@atrey.karlin.mff.cuni.cz> */
/* Modified for i386/x86-64 Xen by Keir Fraser */

#include <xen/config.h>
#include <xen/cache.h>
#include <asm/page.h>
#include <asm/percpu.h>
#undef ENTRY
#undef ALIGN

#ifdef __x86_64__
OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
#else
OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
#endif

ENTRY(start)
PHDRS
{
  text PT_LOAD ;
}
SECTIONS
{
  . = __XEN_VIRT_START + 0x100000;
  _start = .;
  .text : {
        _stext = .;            /* Text and read-only data */
       *(.text)
       *(.fixup)
       *(.gnu.warning)
       _etext = .;             /* End of text section */
  } :text = 0x9090

  .rodata : {
       *(.rodata)
       *(.rodata.*)
  } :text

  . = ALIGN(32);               /* Exception table */
  __ex_table : {
       __start___ex_table = .;
       *(__ex_table)
       __stop___ex_table = .;
  } :text

  . = ALIGN(32);               /* Pre-exception table */
  __pre_ex_table : {
       __start___pre_ex_table = .;
       *(__pre_ex_table)
       __stop___pre_ex_table = .;
  } :text

  .data : {                    /* Data */
       . = ALIGN(PAGE_SIZE);
       *(.data.page_aligned)
       *(.data)
       CONSTRUCTORS
  } :text

  . = ALIGN(128);
  .data.read_mostly : {
       *(.data.read_mostly)
  } :text

#ifdef LOCK_PROFILE
  . = ALIGN(32);
  __lock_profile_start = .;
  .lockprofile.data : { *(.lockprofile.data) } :text
  __lock_profile_end = .;
#endif

  . = ALIGN(4096);             /* Init code and data */
  __init_begin = .;
  .init.text : {
       _sinittext = .;
       *(.init.text)
       _einittext = .;
  } :text
  .init.data : {
       *(.init.data)
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
  . = ALIGN(PAGE_SIZE);
  __init_end = .;

  __per_cpu_shift = PERCPU_SHIFT; /* kdump assist */
  .data.percpu : {
       __per_cpu_start = .;
       *(.data.percpu)
       . = ALIGN(SMP_CACHE_BYTES);
       *(.data.percpu.read_mostly)
       . = ALIGN(PAGE_SIZE);
       __per_cpu_data_end = .;
  } :text
  . = __per_cpu_start + (NR_CPUS << PERCPU_SHIFT);
  . = ALIGN(PAGE_SIZE);

  /*
   * Do not insert anything here - the unused portion of .data.percpu
   * will be freed/unmapped up to __bss_start (defined below).
   */

  .bss : {                     /* BSS */
       . = ALIGN(STACK_SIZE);
       __bss_start = .;
       *(.bss.stack_aligned)
       . = ALIGN(PAGE_SIZE);
       *(.bss.page_aligned)
       *(.bss)
  } :text
  _end = . ;

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
