/******************************************************************************
 * elf-reloc.c
 * 
 * Usage: elf-reloc <old base> <new base> <image>
 * 
 * Relocates <image> from <old base> address to <new base> address by
 * frobbing the Elf headers. Segment contents are unmodified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long  Elf32_Addr;
typedef unsigned short Elf32_Half;
typedef unsigned long  Elf32_Off;
typedef unsigned long  Elf32_Word;

typedef struct {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    Elf32_Word    p_type;
    Elf32_Off     p_offset;
    Elf32_Addr    p_vaddr;
    Elf32_Addr    p_paddr;
    Elf32_Word    p_filesz;
    Elf32_Word    p_memsz;
    Elf32_Word    p_flags;
    Elf32_Word    p_align;
} Elf32_Phdr;

#define offsetof(_f,_p) ((unsigned long)&(((_p *)0)->_f))


/* Add @reloc_distance to address at offset @off in file @fp. */
void reloc(FILE *fp, long off, unsigned long reloc_distance)
{
    unsigned long base;
    fseek(fp, off, SEEK_SET);
    fread(&base, sizeof(base), 1, fp);
    base += reloc_distance;
    fseek(fp, off, SEEK_SET);
    fwrite(&base, sizeof(base), 1, fp);

}


int main(int argc, char **argv)
{
    unsigned long old_base, new_base, reloc_distance;
    long virt_section, phys_section;
    char *image_name;
    FILE *fp;
    Elf32_Off phoff;
    Elf32_Half phnum, phentsz;
    int i;

    if ( argc != 4 )
    {
        fprintf(stderr, "Usage: elf-reloc <old base> <new base> <image>\n");
        return(1);
    }

    old_base = strtoul(argv[1], NULL, 16);
    new_base = strtoul(argv[2], NULL, 16);
    image_name = argv[3];

    printf("Relocating `%s' from 0x%08lX to 0x%08lX\n",
           image_name, old_base, new_base);

    fp = fopen(image_name, "rb+");
    if ( !fp )
    {
        fprintf(stderr, "Failed to load image!\n");
        return(1);
    }

    reloc_distance = new_base - old_base;

    /* First frob the entry address. */
    reloc(fp, offsetof(e_entry, Elf32_Ehdr), reloc_distance);

    fseek(fp, offsetof(e_phoff, Elf32_Ehdr), SEEK_SET);
    fread(&phoff, sizeof(phoff), 1, fp);
    fseek(fp, offsetof(e_phnum, Elf32_Ehdr), SEEK_SET);
    fread(&phnum, sizeof(phnum), 1, fp);
    fseek(fp, offsetof(e_phentsize, Elf32_Ehdr), SEEK_SET);
    fread(&phentsz, sizeof(phentsz), 1, fp);

    virt_section = (long)phoff + offsetof(p_vaddr, Elf32_Phdr);
    phys_section = (long)phoff + offsetof(p_paddr, Elf32_Phdr);
    for ( i = 0; i < phnum; i++ )
    {
        reloc(fp, phys_section, reloc_distance);
        reloc(fp, virt_section, reloc_distance);
        phys_section += phentsz;
        virt_section += phentsz;
    }

    fclose(fp);

    return(0);
}
