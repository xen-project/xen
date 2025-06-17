/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for PDX compression.
 *
 * Copyright (C) 2025 Cloud Software Group
 */

#include "harness.h"

#include "../../xen/common/pdx.c"

struct range {
    /* Ranges are defined as [start, end). */
    unsigned long start, end;
};

static void print_ranges(const struct range *r)
{
    unsigned int i;

    printf("Ranges:\n");

    for ( i = 0; i < MAX_RANGES; i++ )
    {
        if ( !r[i].start && !r[i].end )
            break;

        printf(" %013lx-%013lx\n", r[i].start, r[i].end);
    }
}

int main(int argc, char **argv)
{
    static const struct {
        struct range ranges[MAX_RANGES];
        bool compress;
    } tests[] = {
#ifdef __LP64__
        /*
         * Only for targets where unsigned long is 64bits, otherwise compiler
         * will complain about truncation from 'long long' -> 'long' conversion.
         *
         * Real memory map from a 4s Intel GNR.  Not compressible using PDX
         * mask compression.
         */
        {
            .ranges = {
                { .start =           0,   .end =     0x80000UL },
                { .start =   0x0100000UL, .end =   0x8080000UL },
                { .start =  0x63e80000UL, .end =  0x6be80000UL },
                { .start =  0xc7e80000UL, .end =  0xcfe80000UL },
                { .start = 0x12be80000UL, .end = 0x133e80000UL },
            },
            .compress = false,
        },
        /* Simple hole. */
        {
            .ranges = {
                { .start =                                                 0,
                  .end   =                            (1UL << MAX_ORDER) * 1 },
                { .start = (1UL << (MAX_ORDER * 2)) |                      0,
                  .end   = (1UL << (MAX_ORDER * 2)) | (1UL << MAX_ORDER) * 1 },
            },
            .compress = true,
        },
        /* Simple hole, unsorted ranges. */
        {
            .ranges = {
                { .start = (1UL << (MAX_ORDER * 2)) |                      0,
                  .end   = (1UL << (MAX_ORDER * 2)) | (1UL << MAX_ORDER) * 1 },
                { .start =                                                 0,
                  .end   =                            (1UL << MAX_ORDER) * 1 },
            },
            .compress = true,
        },
        /* PDX compression, 2 ranges covered by the lower mask. */
        {
            .ranges = {
                { .start =                    0,
                  .end   = (1 << MAX_ORDER) * 1 },
                { .start = (1 << MAX_ORDER) * 2,
                  .end   = (1 << MAX_ORDER) * 3 },
                { .start = (1 << MAX_ORDER) * 20,
                  .end   = (1 << MAX_ORDER) * 22 },
            },
            .compress = true,
        },
        /* Single range not starting at 0. */
        {
            .ranges = {
                { .start = (1 << MAX_ORDER) * 10,
                  .end   = (1 << MAX_ORDER) * 11 },
            },
            .compress = true,
        },
        /* Resulting PDX region size leads to no compression. */
        {
            .ranges = {
                { .start =                    0,
                  .end   = (1 << MAX_ORDER) * 1 },
                { .start = (1 << MAX_ORDER) * 2,
                  .end   = (1 << MAX_ORDER) * 3 },
                { .start = (1 << MAX_ORDER) * 4,
                  .end   = (1 << MAX_ORDER) * 7 },
                { .start = (1 << MAX_ORDER) * 8,
                  .end   = (1 << MAX_ORDER) * 12 },
            },
            .compress = false,
        },
        /* AMD Versal Gen 2 ARM board. */
        {
            .ranges = {
                { .start =          0,   .end =    0x80000UL },
                { .start =   0x800000UL, .end =   0x880000UL },
                { .start = 0x50000000UL, .end = 0x50080000UL },
                { .start = 0x60000000UL, .end = 0x60080000UL },
                { .start = 0x70000000UL, .end = 0x70080000UL },
            },
            .compress = true,
        },
        /* Unsorted ranges, lower one not starting at 0. */
        {
        .ranges = {
                { .start = (1UL << (35 - PAGE_SHIFT)) + (1 << MAX_ORDER) * 2,
                  .end =   (1UL << (35 - PAGE_SHIFT)) + (1 << MAX_ORDER) * 3 },
                { .start = (1 << MAX_ORDER) * 2,
                  .end =   (1 << MAX_ORDER) * 3 },
            },
            .compress = true,
        },
        /* Two ranges with the same high bit set. */
        {
        .ranges = {
                { .start = (1UL << (51 - PAGE_SHIFT)) + (1 << MAX_ORDER) * 0,
                  .end =   (1UL << (51 - PAGE_SHIFT)) + (1 << MAX_ORDER) * 1 },
                { .start = (1UL << (51 - PAGE_SHIFT)) + (1 << MAX_ORDER) * 3,
                  .end =   (1UL << (51 - PAGE_SHIFT)) + (1 << MAX_ORDER) * 4 },
            },
            .compress = true,
        },
#endif
        /* AMD Naples Epyc 7281 2 sockets, 8 NUMA nodes. */
        {
            .ranges = {
                { .start =         0,   .end =      0xa0UL },
                { .start =     0x100UL, .end =   0xb0000UL },
                { .start =  0x100000UL, .end =  0x430000UL },
                { .start =  0x430000UL, .end =  0x830000UL },
                { .start =  0x830000UL, .end =  0xc30000UL },
                { .start =  0xc30000UL, .end = 0x1030000UL },
                { .start = 0x1030000UL, .end = 0x1430000UL },
                { .start = 0x1430000UL, .end = 0x1830000UL },
                { .start = 0x1830000UL, .end = 0x1c30000UL },
                { .start = 0x1c30000UL, .end = 0x2030000UL },
            },
            .compress = false,
        },
        /* 2-node 2GB per-node QEMU layout. */
        {
            .ranges = {
                { .start =        0,   .end =  0x80000UL },
                { .start = 0x100000UL, .end = 0x180000UL },
            },
            .compress = true,
        },
        /* Not compressible, smaller than MAX_ORDER. */
        {
            .ranges = {
                { .start =     0,   .end =     1   },
                { .start = 0x100UL, .end = 0x101UL },
            },
            .compress = false,
        },
        /* Compressible, requires adjusting size to (1 << MAX_ORDER). */
        {
            .ranges = {
                { .start =        0,   .end =        1   },
                { .start = 0x100000UL, .end = 0x100001UL },
            },
            .compress = true,
        },
        /* 2s Intel CLX with contiguous ranges, no compression. */
        {
            .ranges = {
                { .start =        0  , .end =  0x180000UL },
                { .start = 0x180000UL, .end = 0x3040000UL },
            },
            .compress = false,
        },
    };
    int ret_code = EXIT_SUCCESS;

    for ( unsigned int i = 0 ; i < ARRAY_SIZE(tests); i++ )
    {
        unsigned int j;

        pfn_pdx_compression_reset();

        for ( j = 0; j < ARRAY_SIZE(tests[i].ranges); j++ )
        {
            unsigned long size = tests[i].ranges[j].end -
                                 tests[i].ranges[j].start;

            if ( !tests[i].ranges[j].start && !tests[i].ranges[j].end )
                break;

            pfn_pdx_add_region(tests[i].ranges[j].start << PAGE_SHIFT,
                               size << PAGE_SHIFT);
        }

        if ( pfn_pdx_compression_setup(0) != tests[i].compress )
        {
            printf("PFN compression diverge, expected %scompressible\n",
                   tests[i].compress ? "" : "un");
            print_ranges(tests[i].ranges);

            ret_code = EXIT_FAILURE;
            continue;
        }

        if ( !tests[i].compress )
            continue;

        for ( j = 0; j < ARRAY_SIZE(tests[i].ranges); j++ )
        {
            unsigned long start = tests[i].ranges[j].start;
            unsigned long end = tests[i].ranges[j].end;

            if ( !start && !end )
                break;

            if ( !pdx_is_region_compressible(start << PAGE_SHIFT, 1) ||
                 !pdx_is_region_compressible((end - 1) << PAGE_SHIFT, 1) )
            {
                printf(
    "PFN compression invalid, pages %#lx and %#lx should be compressible\n",
                       start, end - 1);
                print_ranges(tests[i].ranges);
                ret_code = EXIT_FAILURE;
            }

            if ( start != pdx_to_pfn(pfn_to_pdx(start)) ||
                 end - 1 != pdx_to_pfn(pfn_to_pdx(end - 1)) )
            {
                printf("Compression is not bi-directional:\n");
                printf(" PFN %#lx -> PDX %#lx -> PFN %#lx\n",
                       start, pfn_to_pdx(start), pdx_to_pfn(pfn_to_pdx(start)));
                printf(" PFN %#lx -> PDX %#lx -> PFN %#lx\n",
                       end - 1, pfn_to_pdx(end - 1),
                       pdx_to_pfn(pfn_to_pdx(end - 1)));
                print_ranges(tests[i].ranges);
                ret_code = EXIT_FAILURE;
            }
        }
    }

    return ret_code;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
