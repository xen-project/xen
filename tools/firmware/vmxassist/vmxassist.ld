/*
 * vmxassist.ld
 */
OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
ENTRY(_start)

SECTIONS
{
	.text TEXTADDR : 
	{
		_btext = .;
		*(.text)
		*(.rodata)
		*(.rodata.*)
		_etext = .;
	}

	.data :
	{
		_bdata = .;
		*(.data)
		_edata = .;
	}

	.bss :
	{
		_bbss = .;
		*(.bss)
		_ebss = .;
	}
}

