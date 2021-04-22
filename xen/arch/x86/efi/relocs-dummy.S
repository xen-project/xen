
	.section .reloc, "a", @progbits
	.balign 4
	.long 0
	.long 8

	.globl VIRT_START, ALT_START
	.equ VIRT_START, XEN_VIRT_START
	.equ ALT_START, XEN_VIRT_END
