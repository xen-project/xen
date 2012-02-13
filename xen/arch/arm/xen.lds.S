/* Excerpts written by Martin Mares <mj@atrey.karlin.mff.cuni.cz> */
/* Modified for i386/x86-64 Xen by Keir Fraser */
/* Modified for ARM Xen by Ian Campbell */

#include <xen/config.h>
#include <xen/cache.h>
#include <asm/page.h>
#include <asm/percpu.h>
#undef ENTRY
#undef ALIGN

ENTRY(start)

OUTPUT_ARCH(arm)

PHDRS
{
  text PT_LOAD /* XXX should be AT ( XEN_PHYS_START ) */ ;
}
SECTIONS
{
  . = XEN_VIRT_START;
  _start = .;
  .text : /* XXX should be AT ( XEN_PHYS_START ) */ {
        _stext = .;            /* Text section */
       *(.text)
       *(.fixup)
       *(.gnu.warning)
       _etext = .;             /* End of text section */
  } :text = 0x9090

  . = ALIGN(PAGE_SIZE);
  .rodata : {
        _srodata = .;          /* Read-only data */
       *(.rodata)
       *(.rodata.*)
        _erodata = .;          /* End of read-only data */
  } :text

  .data : {                    /* Data */
       . = ALIGN(PAGE_SIZE);
       *(.data.page_aligned)
       *(.data)
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
       *(.data.rel.ro)
       *(.data.rel.ro.*)
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
       _einittext = .;
  } :text
  . = ALIGN(PAGE_SIZE);
  .init.data : {
       *(.init.rodata)
       *(.init.rodata.str*)
       *(.init.data)
       *(.init.data.rel)
       *(.init.data.rel.*)
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

  /* Section for the device tree blob (if any). */
  _sdtb = .;
  .dtb : { *(.dtb) } :text

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
