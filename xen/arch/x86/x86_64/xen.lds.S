/* Excerpts written by Martin Mares <mj@atrey.karlin.mff.cuni.cz> */
/* Modified for x86-64 Xen by Keir Fraser */

#include <xen/config.h>
#include <asm/page.h>
#include <asm/percpu.h>
#undef ENTRY
#undef ALIGN

OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(start)
PHDRS
{
  text PT_LOAD ;
}
SECTIONS
{
  . = 0xFFFF830000100000;
  _start = .;
  _stext = .;			/* Text and read-only data */
  .text : {
	*(.text)
	*(.fixup)
	*(.gnu.warning)
	} :text = 0x9090
  .text.lock : { *(.text.lock) } :text	/* out-of-line lock text */

  _etext = .;			/* End of text section */

  .rodata : { *(.rodata) *(.rodata.*) } :text

  . = ALIGN(32);		/* Exception table */
  __start___ex_table = .;
  __ex_table : { *(__ex_table) } :text
  __stop___ex_table = .;

  . = ALIGN(32);                /* Pre-exception table */
  __start___pre_ex_table = .;
  __pre_ex_table : { *(__pre_ex_table) } :text
  __stop___pre_ex_table = .;

  .data : {			/* Data */
	*(.data)
	CONSTRUCTORS
	} :text

  . = ALIGN(128);
  .data.read_mostly : { *(.data.read_mostly) } :text

  . = ALIGN(4096);		/* Init code and data */
  __init_begin = .;
  _sinittext = .;
  .init.text : { *(.init.text) } :text
  _einittext = .;
  .init.data : { *(.init.data) } :text
  . = ALIGN(32);
  __setup_start = .;
  .init.setup : { *(.init.setup) } :text
  __setup_end = .;
  __initcall_start = .;
  .initcall.init : { *(.initcall1.init) } :text
  __initcall_end = .;
  . = ALIGN(PAGE_SIZE);
  __init_end = .;

  __per_cpu_start = .;
  .data.percpu : { *(.data.percpu) } :text
  __per_cpu_data_end = .;
  . = __per_cpu_start + (NR_CPUS << PERCPU_SHIFT);
  . = ALIGN(STACK_SIZE);
  __per_cpu_end = .;

  __bss_start = .;		/* BSS */
  .bss : {
	*(.bss.stack_aligned)
	*(.bss.page_aligned)
	*(.bss)
	} :text
  _end = . ;

  /* Sections to be discarded */
  /DISCARD/ : {
	*(.exit.text)
	*(.exit.data)
	*(.exitcall.exit)
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
