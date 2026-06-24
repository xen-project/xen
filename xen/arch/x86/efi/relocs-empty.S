/*
 * Empty .reloc section, simply to indicate to GNU ld that the output .reloc
 * section in xen.efi should not be marked IMAGE_SCN_MEM_DISCARDABLE.  This
 * requires GNU ld 2.46 or newer to actually be understood in the intended way.
 */

	.section .reloc, "a", @progbits
	.balign 4
