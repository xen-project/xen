#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <getopt.h>

#include <xen-tools/libs.h>
#include <xen/lib/x86/cpuid.h>
#include <xen/lib/x86/msr.h>
#include <xen/domctl.h>

static bool debug;

#define EMPTY_LEAF ((struct cpuid_leaf){})

static void check_cpuid(struct cpuid_policy *cp)
{
    struct cpuid_policy new = {};
    size_t data_end;
    xen_cpuid_leaf_t *leaves = malloc(CPUID_MAX_SERIALISED_LEAVES *
                                      sizeof(xen_cpuid_leaf_t));
    unsigned int nr = CPUID_MAX_SERIALISED_LEAVES;
    int rc;

    if ( !leaves )
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
    x86_cpuid_policy_clear_out_of_range_leaves(cp);
    x86_cpuid_policy_recalc_synth(cp);

    /* Serialise... */
    rc = x86_cpuid_copy_to_buffer(cp, leaves, &nr);
    assert(rc == 0);
    assert(nr <= CPUID_MAX_SERIALISED_LEAVES);

    /* ... and deserialise. */
    rc = x86_cpuid_copy_from_buffer(&new, leaves, nr, NULL, NULL);
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

static void check_msr(struct msr_policy *mp)
{
    struct msr_policy new = {};
    xen_msr_entry_t *msrs = malloc(MSR_MAX_SERIALISED_ENTRIES *
                                   sizeof(xen_msr_entry_t));
    unsigned int nr = MSR_MAX_SERIALISED_ENTRIES;
    int rc;

    if ( !msrs )
        return;

    rc = x86_msr_copy_to_buffer(mp, msrs, &nr);
    assert(rc == 0);
    assert(nr <= MSR_MAX_SERIALISED_ENTRIES);

    rc = x86_msr_copy_from_buffer(&new, msrs, nr, NULL);
    assert(rc == 0);
    assert(memcmp(mp, &new, sizeof(*mp)) == 0);

    free(msrs);
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
        struct cpuid_policy *cp = NULL;
        struct msr_policy *mp = NULL;

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
        mp = calloc(1, sizeof(*mp));
        if ( !cp || !mp )
            goto skip;

        fread(cp, sizeof(*cp), 1, fp);
        fread(mp, sizeof(*mp), 1, fp);

        if ( !feof(fp) )
            goto skip;

        check_cpuid(cp);
        check_msr(mp);

    skip:
        free(cp);
        free(mp);

        if ( fp != stdin )
        {
            fclose(fp);
            fp = NULL;
        }
    }

    return 0;
}
