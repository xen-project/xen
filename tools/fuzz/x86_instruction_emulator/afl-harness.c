#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

extern int LLVMFuzzerInitialize(int *argc, char ***argv);
extern int LLVMFuzzerTestOneInput(const uint8_t *data_p, size_t size);
extern unsigned int fuzz_minimal_input_size(void);

#define INPUT_SIZE  4096
static uint8_t input[INPUT_SIZE];

int main(int argc, char **argv)
{
    size_t size;
    FILE *fp = NULL;

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
        usage:
            printf("Usage: %s $FILE | [--min-input-size]\n", argv[0]);
            exit(-1);
            break;

        default:
            printf("Bad getopt return %d (%c)\n", c, c);
            exit(-1);
            break;
        }
    }

    if ( optind == argc ) /* No positional parameters.  Use stdin. */
        fp = stdin;
    else if ( optind != (argc - 1) )
        goto usage;

    if ( LLVMFuzzerInitialize(&argc, &argv) )
        exit(-1);

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();

    while ( __AFL_LOOP(1000) )
#endif
    {
        if ( fp != stdin ) /* If not using stdin, open the provided file. */
        {
            fp = fopen(argv[optind], "rb");
            if ( fp == NULL )
            {
                perror("fopen");
                exit(-1);
            }
        }

        size = fread(input, 1, INPUT_SIZE, fp);

        if ( ferror(fp) )
        {
            perror("fread");
            exit(-1);
        }

        if ( !feof(fp) )
        {
            printf("Input too large\n");
            exit(-1);
        }

        if ( fp != stdin )
        {
            fclose(fp);
            fp = NULL;
        }

        LLVMFuzzerTestOneInput(input, size);
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
