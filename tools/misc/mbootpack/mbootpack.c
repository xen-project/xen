/*
 *  mbootpack.c
 *
 *  Takes a multiboot image, command-line and modules, and repackages
 *  them as if they were a linux kernel.   Only supports a subset of 
 *  the multiboot info page options (enough to boot the Xen hypervisor).
 *
 *  Copyright (C) 2003-2004  Tim Deegan (tjd21@cl.cam.ac.uk)
 * 
 *  Parts based on GNU GRUB, Copyright (C) 2000  Free Software Foundation, Inc
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 *  02111-1307, USA.
 *
 * $Id: mbootpack.c,v 1.3 2005/03/23 10:38:36 tjd21 Exp tjd21 $
 *
 */

#define _GNU_SOURCE
#include "mbootpack.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <elf.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <asm/page.h>

/* From GNU GRUB */
#include "mb_header.h"
#include "mb_info.h"


/*
 *  The plan: Marshal up the multiboot modules and strings as if we 
 *  were loading them into memory on a fresh ix86 PC.  Attach 
 *  a linux bzImage header to the front, which sets up the machine
 *  appropriately and then jumps to the kernel entry address.
 * 
 *  The memory map will be made up roughly like so:
 *
 *  =============
 *  multiboot information (mbi) struct
 *  -------
 *  kernel command line
 *  -------
 *  bootloader name
 *  -------
 *  module command lines
 *  -------
 *  module information structs
 *  =============
 *   (memory hole)
 *  =============
 *  kernel
 *  -------------
 *  module 1
 *  -------------
 *  module 2
 *  -------------
 *      .
 *      .
 *      .
 *
 *  ==============
 * 
 * 
 *  For allocation of memory we assume that the target machine has 'low'
 *  memory from 0 to 640K and 'high' memory starting at 1M.  We allocate
 *  the kernel first, wherever it wants to be.  After that, sections
 *  are added at the next available aligned address, always in the order
 *  given above, and skipping the memory hole at 640K.  Allocated sections 
 *  are stored in a linked list of buffers.
 * 
 *  Re-packaging as a bzImage file happens in buildimage.c
 *  
 */

/* Version */
static const char version_string[] = "mbootpack " MBOOTPACK_VERSION_STRING;

/* Flags */
int quiet = 0;

/* How much of the start of a kernel we read looking for headers.  
 * Must be >= MULTIBOOT_SEARCH */
#define HEADERBUF_SIZE MULTIBOOT_SEARCH


/* Linked list of loaded sections, and a pointer to the next 
 * available space (i.e. just above the highest allocation so far). */
static section_t *sections = NULL;
static section_t *last_section = NULL;
static address_t next_free_space = 0; 

static void usage(void)
/* If we don't understand the command-line options */ 
{
    printf(
"Usage: mbpack [OPTIONS] kernel-image\n\n"
"  -h --help                       Print this text.\n"
"  -q --quiet                      Only output errors and warnings.\n"
"  -o --output=filename            Output to filename (default \"bzImage\").\n"
"  -M --multiboot-output           Produce a multiboot kernel, not a bzImage\n"
"                                  (sets default output file to \"mbImage\").\n"
"  -c --command-line=STRING        Set the kernel command line (DEPRECATED!).\n"
"  -m --module=\"MOD arg1 arg2...\"  Load module MOD with arguments \"arg1...\"\n"
"                                  (can be used multiple times).\n"
"\n");
    exit(1);
}


static void place_kernel_section(address_t start, long int size)
/* Place the kernel in memory, checking for the memory hole. */
{
    if (start >= MEM_HOLE_END) {
        /* Above the memory hole: easy */
        next_free_space = MAX(next_free_space, start + size);
        if (!quiet) {
            printf("Placed kernel section (%p+%p)\n", start, size);
        }
        return;
    }
    
    if (start >= MEM_HOLE_START) {
        /* In the memory hole.  Not so good */
        printf("Fatal: kernel load address (%p) is in the memory hole.\n",
               start);
        exit(1);
    }
    
    if (start + size > MEM_HOLE_START) {
        /* Too big for low memory */
        printf("Fatal: kernel (%p+%p) runs into the memory hole.\n",
               start, size);
        exit(1);
    }	
    
    /* Kernel loads below the memory hole */
    next_free_space = MAX(next_free_space, start + size);

    if (!quiet) {
        printf("Placed kernel section (%p+%p)\n", start, size);
    }
}


static address_t place_section(long int size, int align)
/* Find the next available place for this section.  
 * "align" must be a power of 2 */
{
    address_t start;
    assert(next_free_space != 0);
    assert(((~align + 1) & align) == align);

    start = ROUNDUP_P2(next_free_space, align);

    /* Check that we don't hit the memory hole */
    if (start < MEM_HOLE_END && (start + size) > MEM_HOLE_START) 
        start = ROUNDUP_P2(MEM_HOLE_END, align);

    next_free_space = start + size;

    if (!quiet) {
        printf("Placed section (%p+%p), align=%p\n", 
               start, size, align);
    }
    return start;
}




static address_t load_kernel(const char *filename)
/* Load an elf32/multiboot kernel from this file 
 * Returns the entry address for the kernel. */
{
    unsigned int i;
    address_t start;
    size_t len;
    long int size, loadsize;
    FILE *fp;    
    char *buffer;
    section_t *sec, *s;
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    struct multiboot_header *mbh;
    struct stat sb;

    static char headerbuf[HEADERBUF_SIZE];

    /* Stat and open the file */
    if (stat(filename, &sb) != 0) {
        printf("Fatal: cannot stat %s: %s\n", filename, strerror(errno));
        exit(1);
    }
    if ((fp = fopen(filename, "r")) == NULL) {
        printf("Fatal: cannot open %s: %s\n", filename, strerror(errno));
        exit(1);
    }
    
    /* Load the first 8k of the file */
    if (fseek(fp, 0, SEEK_SET) < 0) {
        printf("Fatal: seek error in %s: %s\n", filename, strerror(errno));
        exit(1);
    }
    if ((len = fread(headerbuf, 1, HEADERBUF_SIZE, fp))
        < HEADERBUF_SIZE)
    {
        if (feof(fp))   /* Short file */
        {
            if (len < 12) {
                printf("Fatal: %s is too short to be a multiboot file.", 
                       filename);
                exit(1);
            }
        } else {
            printf("Fatal: read error in %s: %s\n", filename, strerror(errno));
            exit(1);
        }
    }

    /* Sanity-check: is this file compressed? */
    if ((headerbuf[0] == '\037' && 
         (headerbuf[1] == '\235' /* .Z */ ||
          headerbuf[1] == '\213' /* .gz */)) ||
        (headerbuf[0] == 'B' && headerbuf[1] == 'Z') /* .bz[2] */) {
        printf("Warning: %s looks like a compressed file.\n"
               "         You should uncompress it first!\n", filename);
    }
    
    /* Now look for a multiboot header */
    for (i = 0; i <= MIN(len - 12, MULTIBOOT_SEARCH - 12); i += 4)
    {
        mbh = (struct multiboot_header *)(headerbuf + i);
        if (mbh->magic != MULTIBOOT_MAGIC 
            || ((mbh->magic+mbh->flags+mbh->checksum) & 0xffffffff))
        {
            /* Not a multiboot header */
            continue;
        }
        if (mbh->flags & MULTIBOOT_UNSUPPORTED) {
            /* Requires options we don't support */
            printf("Fatal: found a multiboot header, but it "
                    "requires multiboot options that I\n"
                    "don't understand.  Sorry.\n");
            exit(1);
        } 
        if (mbh->flags & MULTIBOOT_VIDEO_MODE) { 
            /* Asked for screen mode information */
            /* XXX carry on regardless */
            printf("Warning: found a multiboot header which asks "
                   "for screen mode information.\n"
                   "         This kernel will NOT be given valid"
                   "screen mode information at boot time.\n");
        }
        /* This kernel will do: place and load it */

        if (mbh->flags & MULTIBOOT_AOUT_KLUDGE) {

            /* Load using the offsets in the multiboot header */
            if(!quiet) 
                printf("Loading %s using multiboot header.\n", filename);

            /* How much is there? */
            start = mbh->load_addr;            
            if (mbh->load_end_addr != 0) 
                loadsize = mbh->load_end_addr - mbh->load_addr;
            else 
                loadsize = sb.st_size;
            
            /* How much memory will it take up? */ 
            if (mbh->bss_end_addr != 0)
                size = mbh->bss_end_addr - mbh->load_addr;
            else
                size = loadsize;
            
            if (loadsize > size) {
                printf("Fatal: can't load %i bytes of kernel into %i bytes " 
                       "of memory.\n", loadsize, size);
                exit(1);
            }

            /* Does it fit where it wants to be? */
            place_kernel_section(start, size);            
            
            /* Load the kernel */
            if ((buffer = malloc(size)) == NULL) {
                printf("Fatal: malloc() for kernel load failed: %s\n",
                       strerror(errno));
                exit(1);
            }
            if ((fread(buffer, loadsize, 1, fp)) != 1) { 
                printf("Fatal: cannot read %s: %s\n", 
                       filename, strerror(errno));
                exit(1);
            }
            fclose(fp);
            
            /* Clear the kernel BSS */
            memset(buffer + loadsize, 0, size - loadsize);

            /* Start off the linked list of sections */
            if ((sec = (section_t *)malloc(sizeof (section_t))) == NULL) {
                printf("Fatal: malloc() for section_t failed: %s\n",
                       strerror(errno));
                exit(1);
            }
            sec->buffer = buffer;
            sec->start = start;
            sec->size = size;
            sec->next = NULL;
            sec->prev = NULL;
            sections = sec;
            last_section = sec;
            
            /* Done. */
            if (!quiet) printf("Loaded kernel from %s\n", filename);
            return mbh->entry_addr;
            
        } else {

            /* Now look for an ELF32 header */    
            ehdr = (Elf32_Ehdr *)headerbuf;
            if (*(unsigned long *)ehdr != 0x464c457f 
                || ehdr->e_ident[EI_DATA] != ELFDATA2LSB
                || ehdr->e_ident[EI_CLASS] != ELFCLASS32
                || ehdr->e_machine != EM_386)
            {
                printf("Fatal: kernel has neither ELF32/x86 nor multiboot load"
                       " headers.\n");
                exit(1);
            }
            if (ehdr->e_phoff + ehdr->e_phnum*sizeof(*phdr) > HEADERBUF_SIZE) {
                /* Don't expect this will happen with sane kernels */
                printf("Fatal: too much ELF for me.  Try increasing "
                       "HEADERBUF_SIZE in mbootpack.\n");
                exit(1);
            }
            if (ehdr->e_phoff + ehdr->e_phnum*sizeof (*phdr) > len) {
                printf("Fatal: malformed ELF header overruns EOF.\n");
                exit(1);
            }
            if (ehdr->e_phnum <= 0) {
                printf("Fatal: ELF kernel has no program headers.\n");
                exit(1);
            }

            if(!quiet) 
                printf("Loading %s using ELF header.\n", filename);

            if (ehdr->e_type != ET_EXEC 
                || ehdr->e_version != EV_CURRENT
                || ehdr->e_phentsize != sizeof (Elf32_Phdr)) {
                printf("Warning: funny-looking ELF header.\n");
            }
            phdr = (Elf32_Phdr *)(headerbuf + ehdr->e_phoff);

            /* Obey the program headers to load the kernel */
            for(i = 0; i < ehdr->e_phnum; i++) {

                start = phdr[i].p_paddr;
                size = phdr[i].p_memsz;
                if (phdr[i].p_type != PT_LOAD) 
                    loadsize = 0;
                else 
                    loadsize = MIN((long int)phdr[i].p_filesz, size);

                if ((buffer = malloc(size)) == NULL) {
                    printf("Fatal: malloc() for kernel load failed: %s\n",
                           strerror(errno));
                    exit(1);
                }

                /* Place the section where it wants to be */
                place_kernel_section(start, size);            

                /* Load section from file */ 
                if (loadsize > 0) {
                    if (fseek(fp, phdr[i].p_offset, SEEK_SET) != 0) {
                        printf("Fatal: seek failed in %s\n",
                                strerror(errno));
                        exit(1);
                    }
                    if ((fread(buffer, loadsize, 1, fp)) != 1) { 
                        printf("Fatal: cannot read %s: %s\n", 
                               filename, strerror(errno));
                        exit(1);
                    }
                }

                /* Clear the rest of the buffer */
                memset(buffer + loadsize, 0, size - loadsize);

                /* Add this section to the list (keeping it ordered) */
                if ((sec = (section_t *)malloc(sizeof (section_t))) == NULL) {
                    printf("Fatal: malloc() for section_t failed: %s\n",
                           strerror(errno));
                    exit(1);
                }
                sec->buffer = buffer;
                sec->start = start;
                sec->size = size;

                for(s = sections; s; s = s->next) {
                    if (s->start > start) {
                        sec->next = s;
                        if (s->prev == NULL) {
                            /* sec becomes the new first item */
                            s->prev = sec;
                            sections = sec;
                        } else {
                            /* sec goes between s->prev and s */
                            sec->prev = s->prev;
                            sec->prev->next = sec;
                            s->prev = sec;
                        }
                        break;
                    }
                }
                if (s == NULL) {
                    /* sec becomes the new last item */
                    sec->next = NULL;
                    sec->prev = last_section;
                    if (last_section) {
                        last_section->next = sec;
                    } else {
                        sections = sec;
                    }
                    last_section = sec;
                }
            }
         
            /* Done! */
            if (!quiet) printf("Loaded kernel from %s\n", filename);
            return ehdr->e_entry;
        }

    }

    /* This is not a multiboot kernel */
    printf("Fatal: %s is not a multiboot kernel.\n", filename);
    exit(1);
}




int main(int argc, char **argv) 
{
    char *buffer, *imagename, *command_line, *p;
    char *mod_filename, *mod_command_line, *mod_clp;
    char *out_filename;
    section_t *sec;
    FILE *fp;
    struct stat sb;
    struct multiboot_info *mbi;
    struct mod_list *modp;
    address_t start, kernel_entry;
    long int size, mod_command_line_space, command_line_len;
    int modules, opt, mbi_reloc_offset, make_multiboot;

    static const char short_options[] = "hc:m:o:qM";
    static const struct option options[] = {
        { "help",		0, 0, 'h' },
        { "command-line",	1, 0, 'c' },
        { "append",	       	1, 0, 'c' },
        { "module",		1, 0, 'm' },
        { "output",		1, 0, 'o' },
        { "quiet",		0, 0, 'q' },
        { 0, 		       	0, 0, 0 },
    };

    /* Parse the command line */
    out_filename = NULL;
    command_line = "";
    command_line_len = 0;
    modules = 0;
    mod_command_line_space = 0;
    while((opt = getopt_long(argc, argv, short_options, options, 0)) != -1)
    {
        switch(opt) {
        case 'c':
            command_line = optarg;
            break;
        case 'm':
            modules++;
            mod_command_line_space += strlen(optarg) + 1;
            break;
        case 'o':
            out_filename = optarg;
            break;
        case 'q':
            quiet = 1;
            break;
        case 'h':
        case '?':
        default:
            usage();
        }
    }
    imagename = argv[optind];
    if (!imagename || strlen(imagename) == 0) usage();
    command_line_len = strlen(command_line) + strlen(imagename) + 2;
    /* Leave space to overwritethe command-line at boot time */
    command_line_len = MAX(command_line_len, CMD_LINE_SPACE); 
    if (!out_filename) out_filename = "bzImage";

    /* Place and load the kernel */
    kernel_entry = load_kernel(imagename);
    assert(sections != NULL);
    assert(last_section != NULL);
    assert(next_free_space != 0);
    
    /* Next section is all the metadata between kernel and modules */
    size = ((((sizeof (struct multiboot_info)
               + command_line_len
               + strlen(version_string) + 1
               + mod_command_line_space) 
              + 3 ) & ~3)
            + modules * sizeof (struct mod_list));
    /* Locate this section after the setup sectors, in *low* memory */
    start = place_mbi(size);

    if ((buffer = malloc(size)) == NULL) {
        printf("Fatal: malloc() for boot metadata failed: %s\n",
               strerror(errno));
        exit(1);
    }

    if ((sec = (section_t *)malloc(sizeof (section_t))) == NULL) {
        printf("Fatal: malloc() for section_t failed: %s\n",
               strerror(errno));
        exit(1);
    }
    sec->buffer = buffer;
    sec->start = start;
    sec->size = size;
    sec->next = NULL;
    sec->prev = last_section;
    last_section->next = sec;
    last_section = sec;

    /* Multiboot info struct */
    mbi = (struct multiboot_info *)buffer;
    memset(buffer, 0, sizeof (struct multiboot_info));
    mbi_reloc_offset = start - (address_t)buffer;
    
    /* Command line */
    p = (char *)(mbi + 1);
    sprintf(p, "%s %s", imagename, command_line);
    mbi->cmdline = ((address_t)p) + mbi_reloc_offset;
    p += command_line_len;

    /* Bootloader ID */
    sprintf(p, version_string);
    mbi->boot_loader_name = ((address_t)p) + mbi_reloc_offset;
    p += strlen(version_string) + 1;

    /* Next is space for the module command lines */
    mod_clp = p;

    /* Last come the module info structs */
    modp = (struct mod_list *)
        ((((address_t)p + mod_command_line_space) + 3) & ~3);
    mbi->mods_count = modules;
    mbi->mods_addr = ((address_t)modp) + mbi_reloc_offset;

    /* Memory information will be added at boot time, by setup.S 
     * or trampoline.S. */
    mbi->flags = MB_INFO_CMDLINE | MB_INFO_BOOT_LOADER_NAME;


    /* Load the modules */
    if (modules) {
        mbi->flags |= MB_INFO_MODS;
                
        /* Go back and parse the module command lines */
        optind = opterr = 1;
        while((opt = getopt_long(argc, argv, 
                                 short_options, options, 0)) != -1)
        {
            if (opt != 'm') continue;

            /* Split module filename from command line */
            mod_command_line = mod_filename = optarg;
            if ((p = strchr(mod_filename, ' ')) != NULL) {
                /* See as I discard the 'const' modifier */
                *p = '\0';
            }

            /* Find space for it */
            if (stat(mod_filename, &sb) != 0) {
                printf("Fatal: cannot stat %s: %s\n",
                       mod_filename, strerror(errno));
                exit(1);
            }
            size = sb.st_size;
            start = place_section(size, X86_PAGE_SIZE);
            /* XXX should be place_section(size, 4) if the MBH hasn't got
             * XXX MULTIBOOT_PAGE_ALIGN set, but that breaks Xen */

            /* Load it */ 
            if ((buffer = malloc(sb.st_size)) == NULL) {
                printf("Fatal: malloc failed for module load: %s\n",
                       strerror(errno));
                exit(1);
            }
            if ((fp = fopen(mod_filename, "r")) == NULL) {
                printf("Fatal: cannot open %s: %s\n",
                       mod_filename, strerror(errno));
                exit(1);
            }
            if ((fread(buffer, sb.st_size, 1, fp)) != 1) { 
                printf("Fatal: cannot read %s: %s\n",
                       mod_filename, strerror(errno));
                exit(1);
            }
            fclose(fp);
            
            /* Sanity-check: is this file compressed? */
            if ((buffer[0] == '\037' && 
                 (buffer[1] == '\235' /* .Z */ ||
                  buffer[1] == '\213' /* .gz */)) ||
                (buffer[0] == 'B' && buffer[1] == 'Z') /* .bz[2] */) {
                printf("Warning: %s looks like a compressed file.\n",
                       mod_filename);
            }

            if (!quiet) printf("Loaded module from %s\n", mod_filename);

            /* Restore the command line to its former glory */
            if (p != NULL) *p = ' ';

            /* Fill in the module info struct */
            modp->mod_start = start;
            modp->mod_end = start + size;
            modp->cmdline = (address_t)mod_clp + mbi_reloc_offset;
            modp->pad = 0;
            modp++;

            /* Store the module command line */
            sprintf(mod_clp, "%s", mod_command_line);
            mod_clp += strlen(mod_clp) + 1;

            /* Add the section to the list */
            if ((sec = (section_t *)malloc(sizeof (section_t))) == NULL) {
                printf("Fatal: malloc() for section_t failed: %s\n",
                       strerror(errno));
                exit(1);
            }
            sec->buffer = buffer;
            sec->start = start;
            sec->size = size;
            sec->next = NULL;
            sec->prev = last_section;
            last_section->next = sec;
            last_section = sec;

        }
		
    }
    
    /* Everything is placed and loaded.  Now we package it all up 
     * as a bzImage */
    if ((fp = fopen(out_filename, "w")) == NULL) {
        printf("Fatal: cannot open %s: %s\n", out_filename, strerror(errno));
        exit(1);
    }
    make_bzImage(sections, 
                 kernel_entry, 
                 ((address_t)mbi) + mbi_reloc_offset,
                 fp);
    fclose(fp);

    /* Success! */
    if(!quiet) printf("Finished.\n");
    return 0;
}

/*
 *  EOF (mbootpack.c)
 */

