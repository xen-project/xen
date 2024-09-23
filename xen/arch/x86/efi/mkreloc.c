#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <efi/pe.h>

#define PE_PAGE_SIZE 0x1000

#define PE_BASE_RELOC_ABS      0
#define PE_BASE_RELOC_HIGHLOW  3
#define PE_BASE_RELOC_DIR64   10

static void usage(const char *cmd, int rc)
{
    fprintf(rc ? stderr : stdout,
            "Usage: %s <image1> <image2>\n",
            cmd);
    exit(rc);
}

static unsigned int load(const char *name, int *handle,
                         struct section_header **sections,
                         uint_fast64_t *image_base,
                         uint32_t *image_size,
                         unsigned int *width)
{
    int in = open(name, O_RDONLY);
    struct mz_hdr mz_hdr;
    struct pe_hdr pe_hdr;
    struct pe32_opt_hdr pe32_opt_hdr;
    uint32_t base;

    if ( in < 0 ||
         read(in, &mz_hdr, sizeof(mz_hdr)) != sizeof(mz_hdr) )
    {
        perror(name);
        exit(2);
    }

    if ( mz_hdr.magic != MZ_MAGIC ||
         mz_hdr.reloc_table_offset < sizeof(mz_hdr) ||
         !mz_hdr.peaddr )
    {
        fprintf(stderr, "%s: Wrong DOS file format\n", name);
        exit(2);
    }

    if ( lseek(in, mz_hdr.peaddr, SEEK_SET) < 0 ||
         read(in, &pe_hdr, sizeof(pe_hdr)) != sizeof(pe_hdr) ||
         read(in, &pe32_opt_hdr, sizeof(pe32_opt_hdr)) != sizeof(pe32_opt_hdr) ||
         read(in, &base, sizeof(base)) != sizeof(base) ||
         /*
          * Luckily the image size field lives at the
          * same offset for both formats.
          */
         lseek(in, 24, SEEK_CUR) < 0 ||
         read(in, image_size, sizeof(*image_size)) != sizeof(*image_size) )
    {
        perror(name);
        exit(3);
    }

    switch ( (pe_hdr.magic == PE_MAGIC &&
              pe_hdr.opt_hdr_size > sizeof(pe32_opt_hdr)) *
              pe32_opt_hdr.magic )
    {
    case PE_OPT_MAGIC_PE32:
        *width = 32;
        *image_base = base;
        break;
    case PE_OPT_MAGIC_PE32PLUS:
        *width = 64;
        *image_base = ((uint64_t)base << 32) | pe32_opt_hdr.data_base;
        break;
    default:
        fprintf(stderr, "%s: Wrong PE file format\n", name);
        exit(3);
    }

    *sections = malloc(pe_hdr.sections * sizeof(**sections));
    if ( !*sections )
    {
        perror(NULL);
        exit(4);
    }

    if ( lseek(in, mz_hdr.peaddr + sizeof(pe_hdr) + pe_hdr.opt_hdr_size,
               SEEK_SET) < 0 ||
         read(in, *sections, pe_hdr.sections * sizeof(**sections)) !=
             pe_hdr.sections * sizeof(**sections) )
    {
        perror(name);
        exit(4);
    }

    *handle = in;

    return pe_hdr.sections;
}

static long page_size;

static const void *map_section(const struct section_header *sec, int in,
                               const char *name)
{
    const char *ptr;
    unsigned long offs;

    if ( !page_size )
        page_size = sysconf(_SC_PAGESIZE);
    offs = sec->data_addr & (page_size - 1);

    ptr = mmap(0, offs + sec->raw_data_size, PROT_READ, MAP_PRIVATE, in,
               sec->data_addr - offs);
    if ( ptr == MAP_FAILED )
    {
        perror(name);
        exit(6);
    }

    return ptr + offs;
}

static void unmap_section(const void *ptr, const struct section_header *sec)
{
    unsigned long offs = sec->data_addr & (page_size - 1);

    munmap((char *)ptr - offs, offs + sec->raw_data_size);
}

static void diff_sections(const unsigned char *ptr1, const unsigned char *ptr2,
                          const struct section_header *sec,
                          int_fast64_t diff, unsigned int width,
                          uint_fast64_t base, uint_fast64_t end)
{
    static uint_fast32_t cur_rva, reloc_size;
    unsigned int disp = 0;
    uint_fast32_t i;

    if ( !sec )
    {
        reloc_size += reloc_size & 2;
        if ( reloc_size )
            printf("\t.balign 4\n"
                   "\t.equ rva_%08" PRIxFAST32 "_relocs, %#08" PRIxFAST32 "\n",
                   cur_rva, reloc_size);
        return;
    }

    while ( !(diff & (((int_fast64_t)1 << ((disp + 1) * CHAR_BIT)) - 1)) )
        ++disp;

    for ( i = 0; i < sec->raw_data_size; ++i )
    {
        uint_fast32_t rva;
        union {
            uint32_t u32;
            uint64_t u64;
        } val1, val2;
        int_fast64_t delta;
        unsigned int reloc = (width == 4 ? PE_BASE_RELOC_HIGHLOW :
                                           PE_BASE_RELOC_DIR64);

        if ( ptr1[i] == ptr2[i] )
            continue;

        if ( i < disp || i + width - disp > sec->raw_data_size )
        {
            fprintf(stderr,
                    "Bogus difference at %.8s:%08" PRIxFAST32 "\n",
                    sec->name, i);
            exit(3);
        }

        memcpy(&val1, ptr1 + i - disp, width);
        memcpy(&val2, ptr2 + i - disp, width);
        delta = width == 4 ? val2.u32 - val1.u32 : val2.u64 - val1.u64;
        if ( delta != diff )
        {
            fprintf(stderr,
                    "Difference at %.8s:%08" PRIxFAST32 " is %#" PRIxFAST64
                    " (expected %#" PRIxFAST64 ")\n",
                    sec->name, i - disp, delta, diff);
            continue;
        }
        if ( width == 8 && (val1.u64 < base || val1.u64 > end) )
            reloc = PE_BASE_RELOC_HIGHLOW;

        rva = (sec->rva + i - disp) & ~(PE_PAGE_SIZE - 1);
        if ( rva > cur_rva )
        {
            reloc_size += reloc_size & 2;
            if ( reloc_size )
                printf("\t.equ rva_%08" PRIxFAST32 "_relocs,"
                       " %#08" PRIxFAST32 "\n",
                       cur_rva, reloc_size);
            printf("\t.balign 4\n"
                   "\t.long %#08" PRIxFAST32 ","
                   " rva_%08" PRIxFAST32 "_relocs\n",
                   rva, rva);
            cur_rva = rva;
            reloc_size = 8;
        }
        else if ( rva != cur_rva )
        {
            fprintf(stderr,
                    "Cannot handle decreasing RVA (at %.8s:%08" PRIxFAST32 ")\n",
                    sec->name, i - disp);
            exit(3);
        }

        if ( !(sec->flags & IMAGE_SCN_MEM_WRITE) )
            fprintf(stderr,
                    "Warning: relocation to r/o section %.8s:%08" PRIxFAST32 "\n",
                    sec->name, i - disp);

        printf("\t.word (%u << 12) | 0x%03" PRIxFAST32 "\n",
               reloc, sec->rva + i - disp - rva);
        reloc_size += 2;
        i += width - disp - 1;
    }
}

int main(int argc, char *argv[])
{
    int in1, in2;
    unsigned int i, nsec, width1, width2;
    uint_fast64_t base1, base2;
    uint32_t size1, size2;
    struct section_header *sec1, *sec2;

    if ( argc == 1 ||
         !strcmp(argv[1], "-?") ||
         !strcmp(argv[1], "-h") ||
         !strcmp(argv[1], "--help") )
        usage(*argv, argc == 1);

    if ( argc != 3 )
        usage(*argv, 1);

    nsec = load(argv[1], &in1, &sec1, &base1, &size1, &width1);
    if ( nsec != load(argv[2], &in2, &sec2, &base2, &size2, &width2) )
    {
        fputs("Mismatched section counts\n", stderr);
        return 5;
    }
    if ( width1 != width2 )
    {
        fputs("Mismatched image types\n", stderr);
        return 5;
    }
    width1 >>= 3;
    if ( base1 == base2 )
    {
        fputs("Images must have different base addresses\n", stderr);
        return 5;
    }
    if ( size1 != size2 )
    {
        fputs("Images must have identical sizes\n", stderr);
        return 5;
    }

    puts("\t.section .reloc, \"a\", @progbits\n"
         "\t.balign 4");

    for ( i = 0; i < nsec; ++i )
    {
        const void *ptr1, *ptr2;

        if ( memcmp(sec1[i].name, sec2[i].name, sizeof(sec1[i].name)) ||
             sec1[i].rva != sec2[i].rva ||
             sec1[i].virtual_size != sec2[i].virtual_size ||
             sec1[i].raw_data_size != sec2[i].raw_data_size ||
             sec1[i].flags != sec2[i].flags )
        {
            fprintf(stderr, "Mismatched section %u parameters\n", i);
            return 5;
        }

        if ( !sec1[i].virtual_size ||
             (sec1[i].flags & (IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_CNT_UNINITIALIZED_DATA)) )
            continue;

        /*
         * Don't generate relocations for sections that definitely
         * aren't used by the boot loader code.
         */
        if ( memcmp(sec1[i].name, ".buildid", sizeof(sec1[i].name)) == 0 ||
             memcmp(sec1[i].name, ".lockpro", sizeof(sec1[i].name)) == 0 )
            continue;

        if ( !sec1[i].rva )
        {
            fprintf(stderr, "Can't handle section %u with zero RVA\n", i);
            return 3;
        }

        if ( sec1[i].raw_data_size > sec1[i].virtual_size )
        {
            sec1[i].raw_data_size = sec1[i].virtual_size;
            sec2[i].raw_data_size = sec2[i].virtual_size;
        }
        ptr1 = map_section(sec1 + i, in1, argv[1]);
        ptr2 = map_section(sec2 + i, in2, argv[2]);

        diff_sections(ptr1, ptr2, sec1 + i, base2 - base1, width1,
                      base1, base1 + size1);

        unmap_section(ptr1, sec1 + i);
        unmap_section(ptr2, sec2 + i);
    }

    diff_sections(NULL, NULL, NULL, 0, 0, 0, 0);

    close(in1);
    close(in2);

    return 0;
}
