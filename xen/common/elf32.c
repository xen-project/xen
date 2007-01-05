/******************************************************************************
 * elf32.c
 *
 * Stub to support 32-bit ELF images on 64-bit platforms.
 */

#include <xen/config.h>
#undef ELFSIZE
#define ELFSIZE 32
#include <xen/types.h>
#include <xen/elf.h>

#define xen_elfnote_string xen_elf32note_string
#define xen_elfnote_numeric xen_elf32note_numeric
#define parseelfimage parseelf32image
#define loadelfimage loadelf32image
#define elf_sanity_check elf32_sanity_check

#include "elf.c"
