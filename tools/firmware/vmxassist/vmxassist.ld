/*
 * vmxassist.ld
 */
OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
ENTRY(_start)

SECTIONS
{
	_btext = .;
	.text TEXTADDR : 
	{
		*(.text)
		*(.rodata)
		*(.rodata.*)
	}
	_etext = .;

	_bdata = .;
	.data :
	{
		*(.data)
	}
	_edata = .;

	_bbss = .;
	.bss :
	{
		*(.bss)
	}
	_ebss = .;
}

