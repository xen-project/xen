/*
 * 32bitbios_support.c - relocation of 32bit BIOS implementation
 *
 * Stefan Berger, stefanb@us.ibm.com
 * Copyright (c) 2006, International Business Machines Corporation.
 *
 * Keir Fraser, keir@xensource.com
 * Copyright (c) 2007, XenSource Inc.
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

static uint32_t relocate_32bitbios(char *elfarray, uint32_t elfarraysize)
{
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elfarray;
    Elf32_Shdr *shdr = (Elf32_Shdr *)&elfarray[ehdr->e_shoff];
    uint32_t reloc_off, reloc_size;
    char *highbiosarea;
    int i;

    /*
     * Step 1. General elf cleanup, and compute total relocation size.
     */
    reloc_off = 0;
    for ( i = 0; i < ehdr->e_shnum; i++ )
    {
        /* By default all section data points into elf image data array. */
        shdr[i].sh_addr = (Elf32_Addr)&elfarray[shdr[i].sh_offset];

        /* Fix up a corner case of address alignment. */
        if ( shdr[i].sh_addralign == 0 )
            shdr[i].sh_addralign = 1;

        /* Any section which contains run-time data must be relocated. */
        if ( shdr[i].sh_flags & SHF_ALLOC )
        {
            uint32_t mask = shdr[i].sh_addralign - 1;
            reloc_off = (reloc_off + mask) & ~mask;
            reloc_off += shdr[i].sh_size;
        }
    }

    /*
     * Step 2. Now we know the relocation size, allocate a chunk of high mem.
     */
    reloc_size = reloc_off;
    printf("%d bytes of ROMBIOS high-memory extensions:\n", reloc_size);
    highbiosarea = mem_alloc(reloc_size, 1024);
    BUG_ON(highbiosarea == NULL);
    printf("  Relocating to 0x%x-0x%x ... ",
           (uint32_t)&highbiosarea[0],
           (uint32_t)&highbiosarea[reloc_size]);

    /*
     * Step 3. Copy run-time data into the newly-allocated high-memory chunk.
     */
    reloc_off = 0;
    for ( i = 0; i < ehdr->e_shnum; i++ )
    {
        uint32_t mask = shdr[i].sh_addralign - 1;

        /* Nothing to do for non-run-time sections. */
        if ( !(shdr[i].sh_flags & SHF_ALLOC) )
            continue;

        /* Copy from old location. */
        reloc_off = (reloc_off + mask) & ~mask;
        if ( shdr[i].sh_type == SHT_NOBITS )
            memset(&highbiosarea[reloc_off], 0, shdr[i].sh_size);
        else
            memcpy(&highbiosarea[reloc_off], (void *)shdr[i].sh_addr,
                   shdr[i].sh_size);

        /* Update address to new location. */
        shdr[i].sh_addr = (Elf32_Addr)&highbiosarea[reloc_off];
        reloc_off += shdr[i].sh_size;
    }
    BUG_ON(reloc_off != reloc_size);

    /*
     * Step 4. Perform relocations in high memory.
     */
    for ( i = 0; i < ehdr->e_shnum; i++ )
    {
        Elf32_Sym  *syms, *sym;
        Elf32_Rel  *rels;
        char       *code;
        uint32_t   *loc, fix;
        int         j;

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

    printf("done\n");

    return (uint32_t)highbiosarea;
}

uint32_t rombios_highbios_setup(void)
{
    return relocate_32bitbios((char *)highbios_array, sizeof(highbios_array));
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
