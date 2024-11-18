/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Declarations for helper functions compiled for both 32bit and 64bit.
 *
 * The 32bit forms are only used from assembly, so no declarations are
 * provided.
 */
#ifndef X86_BOOT_HELPERS_H
#define X86_BOOT_HELPERS_H

void reloc_trampoline64(void);

#endif /* X86_BOOT_HELPERS_H */
