/******************************************************************************
 * mkelf32.c
 * 
 * Usage: elf-prefix <in-image> <out-image> <load-base>
 * 
 * Converts an Elf32 or Elf64 executable binary <in-image> into a simple Elf32
 * image <out-image> comprising a single chunk to be loaded at <load-base>. 
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>

#define u8  uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t
#define s8  int8_t
#define s16 int16_t
#define s32 int32_t
#define s64 int64_t
#include "../../../include/xen/elfstructs.h"

#define DYNAMICALLY_FILLED   0
#define RAW_OFFSET         128

static Elf32_Ehdr out_ehdr = {
    { ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,    /* EI_MAG{0-3} */
      ELFCLASS32,                            /* EI_CLASS */
      ELFDATA2LSB,                           /* EI_DATA */
      EV_CURRENT,                            /* EI_VERSION */
      0, 0, 0, 0, 0, 0, 0, 0, 0 },           /* e_ident */
    ET_EXEC,                                 /* e_type */
    EM_386,                                  /* e_machine */
    EV_CURRENT,                              /* e_version */
    DYNAMICALLY_FILLED,                      /* e_entry */
    sizeof(Elf32_Ehdr),                      /* e_phoff */
    DYNAMICALLY_FILLED,                      /* e_shoff */
    0,                                       /* e_flags */
    sizeof(Elf32_Ehdr),                      /* e_ehsize */
    sizeof(Elf32_Phdr),                      /* e_phentsize */
    1,                                       /* e_phnum */
    sizeof(Elf32_Shdr),                      /* e_shentsize */
    3,                                       /* e_shnum */
    2                                        /* e_shstrndx */
};

static Elf32_Phdr out_phdr = {
    PT_LOAD,                                 /* p_type */
    RAW_OFFSET,                              /* p_offset */
    DYNAMICALLY_FILLED,                      /* p_vaddr */
    DYNAMICALLY_FILLED,                      /* p_paddr */
    DYNAMICALLY_FILLED,                      /* p_filesz */
    DYNAMICALLY_FILLED,                      /* p_memsz */
    PF_R|PF_W|PF_X,                          /* p_flags */
    64                                       /* p_align */
};

static u8 out_shstrtab[] = "\0.text\0.shstrtab";

static Elf32_Shdr out_shdr[] = {
    { 0 },
    { 1,                                     /* sh_name */
      SHT_PROGBITS,                          /* sh_type */
      SHF_WRITE|SHF_ALLOC|SHF_EXECINSTR,     /* sh_flags */
      DYNAMICALLY_FILLED,                    /* sh_addr */
      RAW_OFFSET,                            /* sh_offset */
      DYNAMICALLY_FILLED,                    /* sh_size */
      0,                                     /* sh_link */
      0,                                     /* sh_info */
      64,                                    /* sh_addralign */
      0                                      /* sh_entsize */
    },
    { 7,                                     /* sh_name */
      SHT_STRTAB,                            /* sh_type */
      0,                                     /* sh_flags */
      0,                                     /* sh_addr */
      DYNAMICALLY_FILLED,                    /* sh_offset */
      sizeof(out_shstrtab),                  /* sh_size */
      0,                                     /* sh_link */
      0,                                     /* sh_info */
      1,                                     /* sh_addralign */
      0                                      /* sh_entsize */
    }
};

/* Some system header files define these macros and pollute our namespace. */
#undef swap16
#undef swap32
#undef swap64

#define swap16(_v) ((((u16)(_v)>>8)&0xff)|(((u16)(_v)&0xff)<<8))
#define swap32(_v) (((u32)swap16((u16)(_v))<<16)|(u32)swap16((u32)((_v)>>16)))
#define swap64(_v) (((u64)swap32((u32)(_v))<<32)|(u64)swap32((u32)((_v)>>32)))

static int big_endian;

static void endianadjust_ehdr32(Elf32_Ehdr *eh)
{
    if ( !big_endian )
        return;
    eh->e_type      = swap16(eh->e_type);
    eh->e_machine   = swap16(eh->e_machine);
    eh->e_version   = swap32(eh->e_version);
    eh->e_entry     = swap32(eh->e_entry);
    eh->e_phoff     = swap32(eh->e_phoff);
    eh->e_shoff     = swap32(eh->e_shoff);
    eh->e_flags     = swap32(eh->e_flags);
    eh->e_ehsize    = swap16(eh->e_ehsize);
    eh->e_phentsize = swap16(eh->e_phentsize);
    eh->e_phnum     = swap16(eh->e_phnum);
    eh->e_shentsize = swap16(eh->e_shentsize);
    eh->e_shnum     = swap16(eh->e_shnum);
    eh->e_shstrndx  = swap16(eh->e_shstrndx);
}

static void endianadjust_ehdr64(Elf64_Ehdr *eh)
{
    if ( !big_endian )
        return;
    eh->e_type      = swap16(eh->e_type);
    eh->e_machine   = swap16(eh->e_machine);
    eh->e_version   = swap32(eh->e_version);
    eh->e_entry     = swap64(eh->e_entry);
    eh->e_phoff     = swap64(eh->e_phoff);
    eh->e_shoff     = swap64(eh->e_shoff);
    eh->e_flags     = swap32(eh->e_flags);
    eh->e_ehsize    = swap16(eh->e_ehsize);
    eh->e_phentsize = swap16(eh->e_phentsize);
    eh->e_phnum     = swap16(eh->e_phnum);
    eh->e_shentsize = swap16(eh->e_shentsize);
    eh->e_shnum     = swap16(eh->e_shnum);
    eh->e_shstrndx  = swap16(eh->e_shstrndx);
}

static void endianadjust_phdr32(Elf32_Phdr *ph)
{
    if ( !big_endian )
        return;
    ph->p_type      = swap32(ph->p_type);
    ph->p_offset    = swap32(ph->p_offset);
    ph->p_vaddr     = swap32(ph->p_vaddr);
    ph->p_paddr     = swap32(ph->p_paddr);
    ph->p_filesz    = swap32(ph->p_filesz);
    ph->p_memsz     = swap32(ph->p_memsz);
    ph->p_flags     = swap32(ph->p_flags);
    ph->p_align     = swap32(ph->p_align);       
}

static void endianadjust_phdr64(Elf64_Phdr *ph)
{
    if ( !big_endian )
        return;
    ph->p_type      = swap32(ph->p_type);
    ph->p_flags     = swap32(ph->p_flags);
    ph->p_offset    = swap64(ph->p_offset);
    ph->p_vaddr     = swap64(ph->p_vaddr);
    ph->p_paddr     = swap64(ph->p_paddr);
    ph->p_filesz    = swap64(ph->p_filesz);
    ph->p_memsz     = swap64(ph->p_memsz);
    ph->p_align     = swap64(ph->p_align);       
}

static void endianadjust_shdr32(Elf32_Shdr *sh)
{
    if ( !big_endian )
        return;
    sh->sh_name     = swap32(sh->sh_name);
    sh->sh_type     = swap32(sh->sh_type);
    sh->sh_flags    = swap32(sh->sh_flags);
    sh->sh_addr     = swap32(sh->sh_addr);
    sh->sh_offset   = swap32(sh->sh_offset);
    sh->sh_size     = swap32(sh->sh_size);
    sh->sh_link     = swap32(sh->sh_link);
    sh->sh_info     = swap32(sh->sh_info);
    sh->sh_addralign = swap32(sh->sh_addralign);
    sh->sh_entsize  = swap32(sh->sh_entsize);
}

static void do_write(int fd, void *data, int len)
{
    int   done, left = len;
    char *p = data;

    while ( left != 0 )
    {
        if ( (done = write(fd, p, left)) == -1 )
        {
            if ( errno == EINTR )
                continue;
            fprintf(stderr, "Error writing output image: %d (%s).\n",
                    errno, strerror(errno));
            exit(1);
        }

        left -= done;
        p    += done;
    }
}

static void do_read(int fd, void *data, int len)
{
    int   done, left = len;
    char *p = data;

    while ( left != 0 )
    {
        if ( (done = read(fd, p, left)) == -1 )
        {
            if ( errno == EINTR )
                continue;
            fprintf(stderr, "Error reading input image: %d (%s).\n",
                    errno, strerror(errno));
            exit(1);
        }

        left -= done;
        p    += done;
    }
}

int main(int argc, char **argv)
{
    u64        final_exec_addr;
    u32        loadbase, dat_siz, mem_siz;
    char      *inimage, *outimage;
    int        infd, outfd;
    char       buffer[1024];
    int        bytes, todo, i;

    Elf32_Ehdr in32_ehdr;
    Elf32_Phdr in32_phdr;

    Elf64_Ehdr in64_ehdr;
    Elf64_Phdr in64_phdr;

    if ( argc != 5 )
    {
        fprintf(stderr, "Usage: mkelf32 <in-image> <out-image> "
                "<load-base> <final-exec-addr>\n");
        return 1;
    }

    inimage  = argv[1];
    outimage = argv[2];
    loadbase = strtoul(argv[3], NULL, 16);
    final_exec_addr = strtoull(argv[4], NULL, 16);

    infd = open(inimage, O_RDONLY);
    if ( infd == -1 )
    {
        fprintf(stderr, "Failed to open input image '%s': %d (%s).\n",
                inimage, errno, strerror(errno));
        return 1;
    }

    do_read(infd, &in32_ehdr, sizeof(in32_ehdr));
    if ( !IS_ELF(in32_ehdr) ||
         (in32_ehdr.e_ident[EI_DATA] != ELFDATA2LSB) )
    {
        fprintf(stderr, "Input image must be a little-endian Elf image.\n");
        return 1;
    }

    big_endian = (*(u16 *)in32_ehdr.e_ident == ((ELFMAG0 << 8) | ELFMAG1));

    endianadjust_ehdr32(&in32_ehdr);
    switch ( in32_ehdr.e_ident[EI_CLASS] )
    {
    case ELFCLASS32:
        if ( in32_ehdr.e_phentsize != sizeof(in32_phdr) )
        {
            fprintf(stderr, "Bad program header size (%d != %d).\n",
                    (int)in32_ehdr.e_phentsize, (int)sizeof(in32_phdr));
            return 1;
        }

        if ( in32_ehdr.e_phnum != 1 )
        {
            fprintf(stderr, "Expect precisely 1 program header; found %d.\n",
                    (int)in32_ehdr.e_phnum);
            return 1;
        }

        (void)lseek(infd, in32_ehdr.e_phoff, SEEK_SET);
        do_read(infd, &in32_phdr, sizeof(in32_phdr));
        endianadjust_phdr32(&in32_phdr);

        (void)lseek(infd, in32_phdr.p_offset, SEEK_SET);
        dat_siz = (u32)in32_phdr.p_filesz;

        /* Do not use p_memsz: it does not include BSS alignment padding. */
        /*mem_siz = (u32)in32_phdr.p_memsz;*/
        mem_siz = (u32)(final_exec_addr - in32_phdr.p_vaddr);
        break;

    case ELFCLASS64:
        (void)lseek(infd, 0, SEEK_SET);
        do_read(infd, &in64_ehdr, sizeof(in64_ehdr));
        endianadjust_ehdr64(&in64_ehdr);

        if ( in64_ehdr.e_phentsize != sizeof(in64_phdr) )
        {
            fprintf(stderr, "Bad program header size (%d != %d).\n",
                    (int)in64_ehdr.e_phentsize, (int)sizeof(in64_phdr));
            return 1;
        }

        if ( in64_ehdr.e_phnum != 1 )
        {
            fprintf(stderr, "Expect precisly 1 program header; found %d.\n",
                    (int)in64_ehdr.e_phnum);
            return 1;
        }

        (void)lseek(infd, in64_ehdr.e_phoff, SEEK_SET);
        do_read(infd, &in64_phdr, sizeof(in64_phdr));
        endianadjust_phdr64(&in64_phdr);

        (void)lseek(infd, in64_phdr.p_offset, SEEK_SET);
        dat_siz = (u32)in64_phdr.p_filesz;

        /* Do not use p_memsz: it does not include BSS alignment padding. */
        /*mem_siz = (u32)in64_phdr.p_memsz;*/
        mem_siz = (u32)(final_exec_addr - in64_phdr.p_vaddr);
        break;

    default:
        fprintf(stderr, "Input image must be a 32- or 64-bit Elf image.\n");
        return 1;
    }

    /*
     * End the image on a page boundary. This gets round alignment bugs
     * in the boot- or chain-loader (e.g., kexec on the XenoBoot CD).
     */
    mem_siz += -(loadbase + mem_siz) & 0xfff;

    out_ehdr.e_entry = loadbase;
    out_ehdr.e_shoff = RAW_OFFSET + dat_siz;

    out_phdr.p_vaddr  = loadbase;
    out_phdr.p_paddr  = loadbase;
    out_phdr.p_filesz = dat_siz;
    out_phdr.p_memsz  = mem_siz;

    out_shdr[1].sh_addr   = loadbase;
    out_shdr[1].sh_size   = dat_siz;
    out_shdr[2].sh_offset = RAW_OFFSET + dat_siz + sizeof(out_shdr);

    outfd = open(outimage, O_WRONLY|O_CREAT|O_TRUNC, 0775);
    if ( outfd == -1 )
    {
        fprintf(stderr, "Failed to open output image '%s': %d (%s).\n",
                outimage, errno, strerror(errno));
        return 1;
    }

    endianadjust_ehdr32(&out_ehdr);
    do_write(outfd, &out_ehdr, sizeof(out_ehdr));

    endianadjust_phdr32(&out_phdr);
    do_write(outfd, &out_phdr, sizeof(out_phdr));
    
    if ( (bytes = RAW_OFFSET - sizeof(out_ehdr) - sizeof(out_phdr)) < 0 )
    {
        fprintf(stderr, "Header overflow.\n");
        return 1;
    }
    do_write(outfd, buffer, bytes);

    for ( bytes = 0; bytes < dat_siz; bytes += todo )
    {
        todo = ((dat_siz - bytes) > sizeof(buffer)) ? 
            sizeof(buffer) : (dat_siz - bytes);
        do_read(infd, buffer, todo);
        do_write(outfd, buffer, todo);
    }

    for ( i = 0; i < (sizeof(out_shdr) / sizeof(out_shdr[0])); i++ )
        endianadjust_shdr32(&out_shdr[i]);
    do_write(outfd, &out_shdr[0], sizeof(out_shdr));

    do_write(outfd, out_shstrtab, sizeof(out_shstrtab));
    do_write(outfd, buffer, 4-((sizeof(out_shstrtab)+dat_siz)&3));

    close(infd);
    close(outfd);

    return 0;
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
