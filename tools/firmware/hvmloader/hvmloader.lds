ENTRY(_start)

SECTIONS
{
  . = 0x100000;
  /*
   * NB: there's no need to use the AT keyword in order to set the LMA, by
   * default the linker will use VMA = LMA unless specified otherwise.
   */
  .text : { *(.text) *(.text.*) }
  .rodata : { *(.rodata) *(.rodata.*) }
  .data : { *(.data) *(.data.*) }
  .bss : { *(.bss) *(.bss.*) }
  _end = .;
}
