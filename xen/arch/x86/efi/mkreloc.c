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

struct mz_hdr {
    uint16_t signature;
#define MZ_SIGNATURE 0x5a4d
    uint16_t last_page_size;
    uint16_t page_count;
    uint16_t relocation_count;
    uint16_t header_paras;
    uint16_t min_paras;
    uint16_t max_paras;
    uint16_t entry_ss;
    uint16_t entry_sp;
    uint16_t checksum;
    uint16_t entry_ip;
    uint16_t entry_cs;
    uint16_t relocations;
    uint16_t overlay;
    uint8_t reserved[32];
    uint32_t extended_header_base;
};

struct pe_hdr {
    uint32_t signature;
#define PE_SIGNATURE 0x00004550
    uint16_t cpu;
    uint16_t section_count;
    int32_t timestamp;
    uint32_t symbols_file_offset;
    uint32_t symbol_count;
    uint16_t opt_hdr_size;
    uint16_t flags;
    struct {
        uint16_t magic;
#define PE_MAGIC_EXE32     0x010b
#define PE_MAGIC_EXE32PLUS 0x020b
        uint8_t linker_major, linker_minor;
        uint32_t code_size, data_size, bss_size;
        uint32_t entry_rva, code_rva, data_rva;
    } opt_hdr;
};

#define PE_PAGE_SIZE 0x1000

#define PE_BASE_RELOC_ABS      0
#define PE_BASE_RELOC_HIGHLOW  3
#define PE_BASE_RELOC_DIR64   10

struct coff_section {
    char name[8];
    uint32_t size;
    uint32_t rva;
    uint32_t file_size;
    uint32_t file_offset;
    uint32_t relocation_file_offset;
    uint32_t line_number_file_offset;
    uint16_t relocation_count;
    uint16_t line_number_count;
    uint32_t flags;
#define COFF_SECTION_BSS         0x00000080
#define COFF_SECTION_DISCARDABLE 0x02000000
};

static void usage(const char *cmd, int rc)
{
    fprintf(rc ? stderr : stdout,
            "Usage: %s <image1> <image2>\n",
            cmd);
    exit(rc);
}

static unsigned int load(const char *name, int *handle,
                         struct coff_section **sections,
                         uint_fast64_t *image_base,
                         uint32_t *image_size,
                         unsigned int *width)
{
    int in = open(name, O_RDONLY);
    struct mz_hdr mz_hdr;
    struct pe_hdr pe_hdr;
    uint32_t base;

    if ( in < 0 ||
         read(in, &mz_hdr, sizeof(mz_hdr)) != sizeof(mz_hdr) )
    {
        perror(name);
        exit(2);
    }
    if ( mz_hdr.signature != MZ_SIGNATURE ||
         mz_hdr.relocations < sizeof(mz_hdr) ||
         !mz_hdr.extended_header_base )
    {
        fprintf(stderr, "%s: Wrong DOS file format\n", name);
        exit(2);
    }

    if ( lseek(in, mz_hdr.extended_header_base, SEEK_SET) < 0 ||
         read(in, &pe_hdr, sizeof(pe_hdr)) != sizeof(pe_hdr) ||
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
    switch ( (pe_hdr.signature == PE_SIGNATURE &&
              pe_hdr.opt_hdr_size > sizeof(pe_hdr.opt_hdr)) *
             pe_hdr.opt_hdr.magic )
    {
    case PE_MAGIC_EXE32:
        *width = 32;
        *image_base = base;
        break;
    case PE_MAGIC_EXE32PLUS:
        *width = 64;
        *image_base = ((uint64_t)base << 32) | pe_hdr.opt_hdr.data_rva;
        break;
    default:
        fprintf(stderr, "%s: Wrong PE file format\n", name);
        exit(3);
    }

    *sections = malloc(pe_hdr.section_count * sizeof(**sections));
    if ( !*sections )
    {
        perror(NULL);
        exit(4);
    }
    if ( lseek(in,
               mz_hdr.extended_header_base + offsetof(struct pe_hdr, opt_hdr) +
                  pe_hdr.opt_hdr_size,
               SEEK_SET) < 0 ||
         read(in, *sections, pe_hdr.section_count * sizeof(**sections)) !=
             pe_hdr.section_count * sizeof(**sections) )
    {
        perror(name);
        exit(4);
    }

    *handle = in;

    return pe_hdr.section_count;
}

static long page_size;

static const void *map_section(const struct coff_section *sec, int in,
                               const char *name)
{
    const char *ptr;
    unsigned long offs;

    if ( !page_size )
        page_size = sysconf(_SC_PAGESIZE);
    offs = sec->file_offset & (page_size - 1);

    ptr = mmap(0, offs + sec->file_size, PROT_READ, MAP_PRIVATE, in,
               sec->file_offset - offs);
    if ( ptr == MAP_FAILED )
    {
        perror(name);
        exit(6);
    }

    return ptr + offs;
}

static void unmap_section(const void *ptr, const struct coff_section *sec)
{
    unsigned long offs = sec->file_offset & (page_size - 1);

    munmap((char *)ptr - offs, offs + sec->file_size);
}

static void diff_sections(const unsigned char *ptr1, const unsigned char *ptr2,
                          const struct coff_section *sec,
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

    for ( i = 0; i < sec->file_size; ++i )
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

        if ( i < disp || i + width - disp > sec->file_size )
        {
            fprintf(stderr,
                    "Bogus difference at %s:%08" PRIxFAST32 "\n",
                    sec->name, i);
            exit(3);
        }

        memcpy(&val1, ptr1 + i - disp, width);
        memcpy(&val2, ptr2 + i - disp, width);
        delta = width == 4 ? val2.u32 - val1.u32 : val2.u64 - val1.u64;
        if ( delta != diff )
        {
            fprintf(stderr,
                    "Difference at %s:%08" PRIxFAST32 " is %#" PRIxFAST64
                    " (expected %#" PRIxFAST64 ")\n",
                    sec->name, i, delta, diff);
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
                    "Cannot handle decreasing RVA (at %s:%08" PRIxFAST32 ")\n",
                    sec->name, i);
            exit(3);
        }

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
    struct coff_section *sec1, *sec2;

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
         "\t.balign 4\n"
         "\t.globl __base_relocs_start, __base_relocs_end\n"
         "__base_relocs_start:");

    for ( i = 0; i < nsec; ++i )
    {
        const void *ptr1, *ptr2;

        if ( memcmp(sec1[i].name, sec2[i].name, sizeof(sec1[i].name)) ||
             sec1[i].rva != sec2[i].rva ||
             sec1[i].size != sec2[i].size ||
             sec1[i].file_size != sec2[i].file_size ||
             sec1[i].flags != sec2[i].flags )
        {
            fprintf(stderr, "Mismatched section %u parameters\n", i);
            return 5;
        }

        if ( !sec1[i].size ||
             (sec1[i].flags & (COFF_SECTION_DISCARDABLE|COFF_SECTION_BSS)) )
            continue;

        /*
         * Don't generate relocations for sections that definitely
         * aren't used by the boot loader code.
         */
        if ( memcmp(sec1[i].name, ".initcal", sizeof(sec1[i].name)) == 0 ||
             memcmp(sec1[i].name, ".init.se", sizeof(sec1[i].name)) == 0 ||
             memcmp(sec1[i].name, ".lockpro", sizeof(sec1[i].name)) == 0 )
            continue;

        if ( !sec1[i].rva )
        {
            fprintf(stderr, "Can't handle section %u with zero RVA\n", i);
            return 3;
        }

        if ( sec1[i].file_size > sec1[i].size )
        {
            sec1[i].file_size = sec1[i].size;
            sec2[i].file_size = sec2[i].size;
        }
        ptr1 = map_section(sec1 + i, in1, argv[1]);
        ptr2 = map_section(sec2 + i, in2, argv[2]);

        diff_sections(ptr1, ptr2, sec1 + i, base2 - base1, width1,
                      base1, base1 + size1);

        unmap_section(ptr1, sec1 + i);
        unmap_section(ptr2, sec2 + i);
    }

    diff_sections(NULL, NULL, NULL, 0, 0, 0, 0);

    puts("__base_relocs_end:");

    close(in1);
    close(in2);

    return 0;
}
