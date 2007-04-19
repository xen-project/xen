/*
 * 32bitbios_support.c - relocation of 32bit BIOS implementation
 *
 * Stefan Berger, stefanb@us.ibm.com
 * Copyright (c) 2006, International Business Machines Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <inttypes.h>
#include <elf.h>
#ifdef __sun__
#include <sys/machelf.h>
#endif

#include "util.h"
#include "config.h"

#include "../rombios/32bit/32bitbios_flat.h"
#include "../rombios/32bit/jumptable.h"

/* Relocate ELF file of type ET_REL */
static void relocate_elf(char *elfarray)
{
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elfarray;
    Elf32_Shdr *shdr = (Elf32_Shdr *)&elfarray[ehdr->e_shoff];
    Elf32_Sym  *syms, *sym;
    Elf32_Rel  *rels;
    char       *code;
    uint32_t   *loc, fix;
    int i, j;

    for ( i = 0; i < ehdr->e_shnum; i++ )
        shdr[i].sh_addr = (Elf32_Addr)&elfarray[shdr[i].sh_offset];

    for ( i = 0; i < ehdr->e_shnum; i++ )
    {
        if ( shdr[i].sh_type == SHT_RELA )
            printf("Unsupported section type SHT_RELA\n");

        if ( shdr[i].sh_type != SHT_REL )
            continue;

        syms = (Elf32_Sym *)shdr[shdr[i].sh_link].sh_addr;
        rels = (Elf32_Rel *)shdr[i].sh_addr;
        code = (char      *)shdr[shdr[i].sh_info].sh_addr;

        for ( j = 0; j < shdr[i].sh_size / sizeof(Elf32_Rel); j++ )
        {
            sym = &syms[ELF32_R_SYM(rels[j].r_info)];
            loc = (uint32_t *)&code[rels[j].r_offset];
            fix = shdr[sym->st_shndx].sh_addr + sym->st_value;

            switch ( ELF32_R_TYPE(rels[j].r_info) )
            {
            case R_386_PC32:
                *loc += fix - (uint32_t)loc;
                break;

            case R_386_32:
                *loc += fix;
                break;
            }
        }
    }
}

/* Scan the rombios for the destination of the jump table. */
static char *get_jump_table_start(void)
{
    char *bios_mem;

    for ( bios_mem = (char *)ROMBIOS_BEGIN;
          bios_mem != (char *)ROMBIOS_END;
          bios_mem++ )
        if ( !strncmp(bios_mem, "___JMPT", 7) )
            return bios_mem;

    return NULL;
}

/* Copy relocated jumptable into the rombios. */
static void copy_jumptable(char *elfarray)
{
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elfarray;
    Elf32_Shdr *shdr = (Elf32_Shdr *)&elfarray[ehdr->e_shoff];
    char *secstrings = &elfarray[shdr[ehdr->e_shstrndx].sh_offset];
    char *jump_table = get_jump_table_start();
    int i;

    /* Find the section with the jump table and copy to lower BIOS memory. */
    for ( i = 0; i < ehdr->e_shnum; i++ )
        if ( !strcmp(JUMPTABLE_SECTION_NAME, secstrings + shdr[i].sh_name) )
            break;

    if ( i == ehdr->e_shnum )
    {
        printf("Could not find " JUMPTABLE_SECTION_NAME " section in file.\n");
        return;
    }

    if ( jump_table == NULL )
    {
        printf("Could not find jump table in file.\n");
        return;
    }

    memcpy(jump_table, (char *)shdr[i].sh_addr, shdr[i].sh_size);
}

static void relocate_32bitbios(char *elfarray, uint32_t elfarraysize)
{
    char *highbiosarea;

    highbiosarea = (char *)(long)e820_malloc(elfarraysize);
    if ( highbiosarea == NULL )
    {
        printf("No available memory for BIOS high memory area\n");
        return;
    }

    memcpy(highbiosarea, elfarray, elfarraysize);
    relocate_elf(highbiosarea);
    copy_jumptable(highbiosarea);
}

void highbios_setup(void)
{
    relocate_32bitbios((char *)highbios_array, sizeof(highbios_array));
}
