#include <asm/config.h>
#include <asm/page.h>
#include <asm/percpu.h>

/* Script for -z combreloc: combine and sort reloc sections */
OUTPUT_FORMAT("elf64-powerpc", "elf64-powerpc",
	      "elf64-powerpc")
OUTPUT_ARCH(powerpc:common64)
ENTRY(_start)
PHDRS
{
  text PT_LOAD;
}   
SECTIONS
{
  /* This is the address that we are linking at */  	
  . = 0x00400000;
  PROVIDE(_text = .);
  PROVIDE(_stext = .);
  /* Read-only sections, merged into text segment: */
  .text           :
  {
    *(.text)
    /* .gnu.warning sections are handled specially by elf32.em.  */
    *(.gnu.warning)
  } : text
  /* end of text */
  PROVIDE (__etext = .);
  PROVIDE (_etext = .);
  PROVIDE (etext = .);

  /* read only data */
  .rodata         : { *(.rodata .rodata.*) } : text
  .rodata1        : { *(.rodata1) } : text
  .sdata2         : { *(.sdata2 .sdata2.*) } : text
  .sbss2          : { *(.sbss2 .sbss2.*) } : text

  . = ALIGN(64);
  __start___ex_table = .;
  __ex_table : { *(__ex_table) } : text
  __stop___ex_table = .;
  . = ALIGN(64);

  .data           :
  {
    *(.data .gnu.linkonce.d.*)
    SORT(CONSTRUCTORS)
  } : text
  .data1          : { *(.data1) } : text
  .tdata	  : { *(.tdata .tdata.* .gnu.linkonce.td.*) } : text
  .tbss		  : { *(.tbss .tbss.* .gnu.linkonce.tb.*) *(.tcommon) } : text
  .toc1		 ALIGN(8) : { *(.toc1) } : text
  .opd		 ALIGN(8) : { KEEP (*(.opd)) } : text
  .got		ALIGN(8) : { *(.got .toc) } : text
  /* We want the small data sections together, so single-instruction offsets
     can access them all, and initialized data all before uninitialized, so
     we can shorten the on-disk segment size.  */
  .sdata          :
  {
    *(.sdata .sdata.* .gnu.linkonce.s.*)
  } : text
  _edata = .;
  PROVIDE (edata = .);

  . = ALIGN(4096);		/* Init code and data */
  __init_begin = .;
  _sinittext = .;
  .init.text : { *(.init.text) } : text
  _einittext = .;
  .init.data : { *(.init.data) } : text
  . = ALIGN(32);
  __setup_start = .;
  .init.setup : { *(.init.setup) } : text
  __setup_end = .;
  __initcall_start = .;
  .initcall.init : { *(.initcall1.init) } : text
  __initcall_end = .;
  __init_hcall_start = .;
  .init_hcall.init : { *(.init_hcall.init) } : text
  __init_hcall_end = .;
  __builtin_cmdline : { *(__builtin_cmdline) } : text
  . = ALIGN(4096);
  __init_end = .;
	
  __per_cpu_start = .;
  .data.percpu : { *(.data.percpu) } :text
  __per_cpu_data_end = .;
  . = __per_cpu_start + (NR_CPUS << PERCPU_SHIFT);
  . = ALIGN(STACK_SIZE);
  __per_cpu_end = .;
	
  __bss_start = .;
  .tocbss	 ALIGN(8) : { *(.tocbss) } : text
  .sbss           :
  {
    PROVIDE (__sbss_start = .);
    PROVIDE (___sbss_start = .);
    *(.sbss .sbss.* .gnu.linkonce.sb.*)
    *(.scommon)
    PROVIDE (__sbss_end = .);
    PROVIDE (___sbss_end = .);
  } : text
  .bss            :
  {
   *(.bss .bss.* .gnu.linkonce.b.*)
   *(COMMON)
   /* Align here to ensure that the .bss section occupies space up to
      _end.  Align after .bss to ensure correct alignment even if the
      .bss section disappears because there are no input sections.  */
   . = ALIGN(64 / 8);
  } : text
  . = ALIGN(64 / 8);
  _end = .;
  PROVIDE (end = .);

  /* Stabs debugging sections.  */
  .stab          0 : { *(.stab) }
  .stabstr       0 : { *(.stabstr) }
  .stab.excl     0 : { *(.stab.excl) }
  .stab.exclstr  0 : { *(.stab.exclstr) }
  .stab.index    0 : { *(.stab.index) }
  .stab.indexstr 0 : { *(.stab.indexstr) }
  .comment       0 : { *(.comment) }
  /* DWARF debug sections.
     Symbols in the DWARF debugging sections are relative to the beginning
     of the section so we begin them at 0.  */
  /* DWARF 1 */
  .debug          0 : { *(.debug) }
  .line           0 : { *(.line) }
  /* GNU DWARF 1 extensions */
  .debug_srcinfo  0 : { *(.debug_srcinfo) }
  .debug_sfnames  0 : { *(.debug_sfnames) }
  /* DWARF 1.1 and DWARF 2 */
  .debug_aranges  0 : { *(.debug_aranges) }
  .debug_pubnames 0 : { *(.debug_pubnames) }
  /* DWARF 2 */
  .debug_info     0 : { *(.debug_info .gnu.linkonce.wi.*) }
  .debug_abbrev   0 : { *(.debug_abbrev) }
  .debug_line     0 : { *(.debug_line) }
  .debug_frame    0 : { *(.debug_frame) }
  .debug_str      0 : { *(.debug_str) }
  .debug_loc      0 : { *(.debug_loc) }
  .debug_macinfo  0 : { *(.debug_macinfo) }
  /* SGI/MIPS DWARF 2 extensions */
  .debug_weaknames 0 : { *(.debug_weaknames) }
  .debug_funcnames 0 : { *(.debug_funcnames) }
  .debug_typenames 0 : { *(.debug_typenames) }
  .debug_varnames  0 : { *(.debug_varnames) }
  /DISCARD/ : { *(.note.GNU-stack) }
}
