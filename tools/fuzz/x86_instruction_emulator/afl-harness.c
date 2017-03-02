#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data_p, size_t size);
extern unsigned int fuzz_minimal_input_size(void);

#define INPUT_SIZE  4096
static uint8_t input[INPUT_SIZE];

int main(int argc, char **argv)
{
    size_t size;
    FILE *fp;

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
            printf("Usage: %s $FILE | [--min-input-size]\n", argv[0]);
            exit(-1);
            break;

        default:
            printf("Bad getopt return %d (%c)\n", c, c);
            exit(-1);
            break;
        }
    }

    if ( optind != (argc - 1) )
    {
        printf("Expecting only one argument\n");
        exit(-1);
    }

    fp = fopen(argv[1], "rb");
    if ( fp == NULL )
    {
        perror("fopen");
        exit(-1);
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

    fclose(fp);

    LLVMFuzzerTestOneInput(input, size);

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
