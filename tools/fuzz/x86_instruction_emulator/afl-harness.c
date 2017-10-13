#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "fuzz-emul.h"

static uint8_t input[INPUT_SIZE];

int main(int argc, char **argv)
{
    size_t size;
    FILE *fp = NULL;
    int max, count;

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    while ( 1 )
    {
        enum {
            OPT_MIN_SIZE,
        };
        static const struct option lopts[] = {
            { "min-input-size", no_argument, NULL, OPT_MIN_SIZE },
            { 0, 0, 0, 0 }
        };
        int c = getopt_long_only(argc, argv, "", lopts, NULL);

        if ( c == -1 )
            break;

        switch ( c )
        {
        case OPT_MIN_SIZE:
            printf("%u\n", fuzz_minimal_input_size());
            exit(0);
            break;

        case '?':
            printf("Usage: %s $FILE [$FILE...] | [--min-input-size]\n", argv[0]);
            exit(-1);
            break;

        default:
            printf("Bad getopt return %d (%c)\n", c, c);
            exit(-1);
            break;
        }
    }

    max = argc - optind;

    if ( !max ) /* No positional parameters.  Use stdin. */
    {
        max = 1;
        fp = stdin;
    }

    if ( LLVMFuzzerInitialize(&argc, &argv) )
        exit(-1);

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();

    for( count = 0; __AFL_LOOP(1000); )
#else
    for( count = 0; count < max; count++ )
#endif
    {
        if ( fp != stdin ) /* If not using stdin, open the provided file. */
        {
            printf("Opening file %s\n", argv[optind + count]);
            fp = fopen(argv[optind + count], "rb");
            if ( fp == NULL )
            {
                perror("fopen");
                exit(-1);
            }
        }
#ifdef __AFL_HAVE_MANUAL_CONTROL
        else
        {
            /* 
             * This will ensure we're dealing with a clean stream
             * state after the afl-fuzz process messes with the open
             * file handle.
             */
            fseek(fp, 0, SEEK_SET);
        }
#endif

        size = fread(input, 1, INPUT_SIZE, fp);

        if ( ferror(fp) )
        {
            perror("fread");
            exit(-1);
        }

        /* Only run the test if the input file was smaller than INPUT_SIZE */
        if ( feof(fp) )
        {
            LLVMFuzzerTestOneInput(input, size);
        }
        else
        {
            printf("Input too large\n");
            /* Don't exit if we're doing batch processing */
            if ( max == 1 )
                exit(-1);
        }

        if ( fp != stdin )
        {
            fclose(fp);
            fp = NULL;
        }
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
