OUTPUT_FORMAT("elf64-ia64-little")
OUTPUT_ARCH(ia64)

ENTRY(phys_start)

PHDRS
{
  code PT_LOAD;
  data PT_LOAD;
}

SECTIONS
{

  phys_start = _start - (((5<<(61))+0x100000000) - (1 << 20));

  code : { } :code
  . = ((5<<(61))+0x100000000);

  _text = .;

  .text : AT(ADDR(.text) - (((5<<(61))+0x100000000) - (1 << 20)))
  {
    *(.text)
  }

  _etext = .;

  data : { } :data
  .data : AT(ADDR(.data) - (((5<<(61))+0x100000000) - (1 << 20)))
  { *(.data) 
  }

  .sdata : AT(ADDR(.sdata) - (((5<<(61))+0x100000000) - (1 << 20)))
        { *(.sdata) *(.sdata1) *(.srdata) }

  .rodata : AT(ADDR(.rodata) - (((5<<(61))+0x100000000) - (1 << 20)))
  { *(.rodata) }

  .rodata.str1.8 : AT(ADDR(.rodata.str1.8) - (((5<<(61))+0x100000000) - (1 << 20)))
  { *(.rodata.str1.8) }

  .IA_64.unwind_info : AT(ADDR(.IA_64.unwind_info) - (((5<<(61))+0x100000000) - (1 << 20)))
  { *(.IA_64.unwind_info) }

  .IA_64.unwind : AT(ADDR(.IA_64.unwind) - (((5<<(61))+0x100000000) - (1 << 20)))
  { *(.IA_64.unwind) }

  .bss : AT(ADDR(.bss) - (((5<<(61))+0x100000000) - (1 << 20)))
  { *(.bss) }

  _end = .;

}
