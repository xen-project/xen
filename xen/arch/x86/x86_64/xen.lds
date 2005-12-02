/* Excerpts written by Martin Mares <mj@atrey.karlin.mff.cuni.cz> */
/* Modified for x86-64 Xen by Keir Fraser */
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
  _text = .;			/* Text and read-only data */
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

  . = ALIGN(4096);		/* Init code and data */
  __init_begin = .;
  .text.init : { *(.text.init) } :text
  .data.init : { *(.data.init) } :text
  . = ALIGN(32);
  __setup_start = .;
  .setup.init : { *(.setup.init) } :text
  __setup_end = .;
  __initcall_start = .;
  .initcall.init : { *(.initcall.init) } :text
  __initcall_end = .;
  . = ALIGN(8192);
  __init_end = .;

  __bss_start = .;		/* BSS */
  .bss : {
	*(.bss.twopage_aligned)
	*(.bss.page_aligned)
	*(.bss)
	} :text
  _end = . ;

  /* Sections to be discarded */
  /DISCARD/ : {
	*(.text.exit)
	*(.data.exit)
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
