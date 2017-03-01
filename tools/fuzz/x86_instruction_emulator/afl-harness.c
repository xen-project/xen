#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data_p, size_t size);
extern unsigned int fuzz_minimal_input_size(void);

#define INPUT_SIZE  4096
static uint8_t input[INPUT_SIZE];

int main(int argc, char **argv)
{
    size_t size;
    FILE *fp;

    setbuf(stdout, NULL);

    if ( argc != 2 )
    {
        printf("Expecting only one argument\n");
        exit(-1);
    }

    if ( !strcmp(argv[1], "--min-input-size") )
    {
        printf("%u\n", fuzz_minimal_input_size());
        exit(0);
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
