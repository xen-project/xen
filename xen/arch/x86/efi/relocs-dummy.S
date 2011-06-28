#include <xen/config.h>

	.section .reloc, "a", @progbits
	.balign 4
	.globl __base_relocs_start, __base_relocs_end
__base_relocs_start:
	.long 0
	.long 8
__base_relocs_end:

	.globl VIRT_START, ALT_START
	.equ VIRT_START, XEN_VIRT_START
	.equ ALT_START, XEN_VIRT_END
