#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <getopt.h>

#include <xen-tools/common-macros.h>
#include <xen/lib/x86/cpu-policy.h>
#include <xen/domctl.h>

static bool debug;

#define EMPTY_LEAF ((struct cpuid_leaf){})

static void check_policy(struct cpu_policy *cp)
{
    struct cpu_policy new = {};
    size_t data_end;
    xen_cpuid_leaf_t *leaves = malloc(CPUID_MAX_SERIALISED_LEAVES *
                                      sizeof(xen_cpuid_leaf_t));
    xen_msr_entry_t *msrs = malloc(MSR_MAX_SERIALISED_ENTRIES *
                                   sizeof(xen_cpuid_leaf_t));
    unsigned int nr_leaves = CPUID_MAX_SERIALISED_LEAVES;
    unsigned int nr_msrs = MSR_MAX_SERIALISED_ENTRIES;
    int rc;

    if ( !leaves || !msrs )
        return;

    /*
     * Clean unusable leaves.  These can't be accessed via architectural
     * means, but may be filled by the fread() across the entire structure.
     * Also zero the trailing padding (if any).
     */
    cp->basic.raw[4] = EMPTY_LEAF;
    cp->basic.raw[7] = EMPTY_LEAF;
    cp->basic.raw[0xb] = EMPTY_LEAF;
    cp->basic.raw[0xd] = EMPTY_LEAF;
    data_end = offsetof(typeof(*cp), x86_vendor) + sizeof(cp->x86_vendor);
    if ( data_end < sizeof(*cp) )
        memset((void *)cp + data_end, 0, sizeof(*cp) - data_end);

    /*
     * Fix up the data in the source policy which isn't expected to survive
     * serialisation.
     */
    x86_cpu_policy_clear_out_of_range_leaves(cp);
    x86_cpu_policy_recalc_synth(cp);

    /* Serialise... */
    rc = x86_cpuid_copy_to_buffer(cp, leaves, &nr_leaves);
    assert(rc == 0);
    assert(nr_leaves <= CPUID_MAX_SERIALISED_LEAVES);

    rc = x86_msr_copy_to_buffer(cp, msrs, &nr_msrs);
    assert(rc == 0);
    assert(nr_msrs <= MSR_MAX_SERIALISED_ENTRIES);

    /* ... and deserialise. */
    rc = x86_cpuid_copy_from_buffer(&new, leaves, nr_leaves, NULL, NULL);
    assert(rc == 0);

    rc = x86_msr_copy_from_buffer(&new, msrs, nr_msrs, NULL);
    assert(rc == 0);

    /* The result after serialisation/deserialisaion should be identical... */
    if ( memcmp(cp, &new, sizeof(*cp)) != 0 )
    {
        if ( debug )
        {
            unsigned char *l = (void *)cp, *r = (void *)&new;

            for ( size_t i = 0; i < sizeof(*cp); ++i )
                if ( l[i] != r[i] )
                    printf("Differ at offset %zu: %u vs %u\n",
                           i, l[i], r[i]);
        }

        abort();
    }

    free(leaves);
}

int main(int argc, char **argv)
{
    FILE *fp = NULL;

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    while ( true )
    {
        static const struct option opts[] = {
            { "debug", no_argument, NULL, 'd' },
            { "help", no_argument, NULL, 'h' },
            {},
        };
        int c = getopt_long(argc, argv, "hd", opts, NULL);

        if ( c == -1 )
            break;

        switch ( c )
        {
        case 'd':
            printf("Enabling debug\n");
            debug = true;
            break;

        case '?':
        case 'h':
            printf("Usage: %s [--debug] <FILE>\n", argv[0]);
        default:
            exit(-(c != 'h'));
            break;
        }
    }

    if ( optind == argc ) /* No positional parameters.  Use stdin. */
    {
        printf("Using stdin\n");
        fp = stdin;
    }

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    while ( __AFL_LOOP(1000) )
#endif
    {
        struct cpu_policy *cp = NULL;

        if ( fp != stdin )
        {
            printf("Opening file '%s'\n", argv[optind]);
            fp = fopen(argv[optind], "rb");

            if ( !fp )
            {
                perror("fopen");
                exit(-1);
            }
        }

        cp = calloc(1, sizeof(*cp));
        if ( !cp )
            goto skip;

        fread(cp, sizeof(*cp), 1, fp);

        if ( !feof(fp) )
            goto skip;

        check_policy(cp);

    skip:
        free(cp);

        if ( fp != stdin )
        {
            fclose(fp);
            fp = NULL;
        }
    }

    return 0;
}
