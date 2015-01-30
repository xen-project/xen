OUTPUT_ARCH(arm)
ENTRY(_start)
SECTIONS
{
  /* Note: we currently assume that Xen will load the kernel image
   * at start-of-RAM + 0x8000. We use this initial 32 KB for the stack
   * and translation tables.
   */
  _boot_stack 	 = 0x400000;	/* 16 KB boot stack */
  _boot_stack_end = 0x404000;
  _page_dir      = 0x404000;	/* 16 KB translation table */
  .		 = 0x408000;
  _text = .;			/* Text and read-only data */
  .text : {
	*(.text)
	*(.gnu.warning)
	} = 0x9090

  _etext = .;			/* End of text section */

  .rodata : { *(.rodata) *(.rodata.*) }
  . = ALIGN(4096);
  _erodata = .;

  /* newlib initialization functions */
  . = ALIGN(32 / 8);
  PROVIDE (__preinit_array_start = .);
  .preinit_array     : { *(.preinit_array) }
  PROVIDE (__preinit_array_end = .);
  PROVIDE (__init_array_start = .);
  .init_array     : { *(.init_array) }
  PROVIDE (__init_array_end = .);
  PROVIDE (__fini_array_start = .);
  .fini_array     : { *(.fini_array) }
  PROVIDE (__fini_array_end = .);

  .ctors : {
        __CTOR_LIST__ = .;
        *(.ctors)
	CONSTRUCTORS
        LONG(0)
        __CTOR_END__ = .;
        }

  .dtors : {
        __DTOR_LIST__ = .;
        *(.dtors)
        LONG(0)
        __DTOR_END__ = .;
        }

  .data : {			/* Data */
	*(.data)
	}

  /* Note: linker will insert any extra sections here, just before .bss */

  .bss : {
	_edata = .;			/* End of data included in image */
	/* Nothing after here is included in the zImage's size */

	__bss_start = .;
	*(.bss)
        *(.app.bss)
	}
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
