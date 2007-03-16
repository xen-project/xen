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
static int relocate_elf(char *elfarray)
{
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elfarray;
    Elf32_Shdr *shdr = (Elf32_Shdr *)&elfarray[ehdr->e_shoff];
    int i;

    if ( ehdr->e_type != ET_REL )
    {
        printf("Not a relocatable BIOS object file. Has type %d, need %d\n",
               ehdr->e_type, ET_REL);
        return -1;
    }

    for ( i = 0; i < ehdr->e_shnum; i++ )
        shdr[i].sh_addr = (Elf32_Addr)&elfarray[shdr[i].sh_offset];

    for ( i = 0; i < ehdr->e_shnum; i++ )
    {
        if ( shdr[i].sh_type == SHT_RELA )
            return -2;

        if ( shdr[i].sh_type == SHT_REL )
        {
            Elf32_Shdr *targetsec = (Elf32_Shdr *)&(shdr[shdr[i].sh_info]);
            Elf32_Shdr *symtabsec = (Elf32_Shdr *)&(shdr[shdr[i].sh_link]);
            Elf32_Sym  *syms      = (Elf32_Sym *)symtabsec->sh_addr;
            Elf32_Rel  *rels      = (Elf32_Rel *)shdr[i].sh_addr;
            char *code            = (char *)targetsec->sh_addr;
            int j;

            /* must not have been stripped */
            if ( shdr[i].sh_size == 0 )
                return -6;

            for ( j = 0; j < shdr[i].sh_size / sizeof(Elf32_Rel); j++ )
            {
                int idx           = ELF32_R_SYM(rels[j].r_info);
                Elf32_Sym *symbol = &syms[idx];
                uint32_t *loc     = (uint32_t *)&code[rels[j].r_offset];
                uint32_t fix      = shdr[symbol->st_shndx].sh_addr +
                                    symbol->st_value;

                switch ( ELF32_R_TYPE(rels[j].r_info) )
                {
                    case R_386_PC32:
                        *loc += (fix - (uint32_t)loc);
                    break;

                    case R_386_32:
                        *loc += fix;
                    break;
                }
            }
        }
    }
    return 0;
}

/* Scan the rombios for the destination of the jump table. */
static char *get_jump_table_start(void)
{
    char *bios_mem;

    for ( bios_mem = (char *)ROMBIOS_BEGIN;
          bios_mem != (char *)ROMBIOS_END;
          bios_mem++ )
    {
        if ( strncmp(bios_mem, "___JMPT", 7) == 0 )
            return bios_mem;
    }

    return NULL;
}

/* Copy relocated jumptable into the rombios. */
static int copy_jumptable(char *elfarray)
{
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elfarray;
    Elf32_Shdr *shdr = (Elf32_Shdr *)&elfarray[ehdr->e_shoff];
    Elf32_Shdr *shdr_strings = (Elf32_Shdr *)&shdr[ehdr->e_shstrndx];
    char *secstrings = (char *)&elfarray[shdr_strings->sh_offset];
    uint32_t *rombiosjumptable = (uint32_t *)get_jump_table_start();
    int i;

    if ( rombiosjumptable == NULL )
        return -3;

    /* Find the section with the jump table and copy to lower BIOS memory. */
    for ( i = 0; i < ehdr->e_shnum; i++ )
        if ( !strcmp(JUMPTABLE_SECTION_NAME, secstrings + shdr[i].sh_name) )
            break;

    if ( i == ehdr->e_shnum )
    {
        printf("Could not find " JUMPTABLE_SECTION_NAME " section in file.\n");
        return -4;
    }

    memcpy(rombiosjumptable, (uint32_t *)shdr[i].sh_addr, shdr[i].sh_size);

    return 0;
}

static int relocate_32bitbios(char *elfarray, uint32_t elfarraysize)
{
    uint32_t mask = (64 * 1024) - 1;
    char *highbiosarea;
    int rc;

    highbiosarea = (char *)(long)
        e820_malloc((elfarraysize + mask) & ~mask, /* round to 64kb */
                    E820_RESERVED,
                    (uint64_t)0xffffffff);

    if ( highbiosarea == NULL )
        return -5;

    memcpy(highbiosarea, elfarray, elfarraysize);
    rc = relocate_elf(highbiosarea);
    if ( rc == 0 )
        rc = copy_jumptable(highbiosarea);

    return rc;
}

int highbios_setup(void)
{
    return relocate_32bitbios((char *)highbios_array,
                              sizeof(highbios_array));
}
