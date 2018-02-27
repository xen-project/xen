#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <getopt.h>
#include <string.h>

#include <xenctrl.h>

#define ARRAY_SIZE(a) (sizeof a / sizeof *a)
static uint32_t nr_features;

static const char *str_1d[32] =
{
    [ 0] = "fpu",  [ 1] = "vme",
    [ 2] = "de",   [ 3] = "pse",
    [ 4] = "tsc",  [ 5] = "msr",
    [ 6] = "pae",  [ 7] = "mce",
    [ 8] = "cx8",  [ 9] = "apic",
    /* [10] */     [11] = "sysenter",
    [12] = "mtrr", [13] = "pge",
    [14] = "mca",  [15] = "cmov",
    [16] = "pat",  [17] = "pse36",
    [18] = "psn",  [19] = "clflush",
    /* [20] */     [21] = "ds",
    [22] = "acpi", [23] = "mmx",
    [24] = "fxsr", [25] = "sse",
    [26] = "sse2", [27] = "ss",
    [28] = "htt",  [29] = "tm",
    [30] = "ia64", [31] = "pbe",
};

static const char *str_1c[32] =
{
    [ 0] = "sse3",    [ 1] = "pclmulqdq",
    [ 2] = "dtes64",  [ 3] = "monitor",
    [ 4] = "ds-cpl",  [ 5] = "vmx",
    [ 6] = "smx",     [ 7] = "est",
    [ 8] = "tm2",     [ 9] = "ssse3",
    [10] = "cntx-id", [11] = "sdgb",
    [12] = "fma",     [13] = "cx16",
    [14] = "xtpr",    [15] = "pdcm",
    /* [16] */        [17] = "pcid",
    [18] = "dca",     [19] = "sse41",
    [20] = "sse42",   [21] = "x2apic",
    [22] = "movebe",  [23] = "popcnt",
    [24] = "tsc-dl",  [25] = "aesni",
    [26] = "xsave",   [27] = "osxsave",
    [28] = "avx",     [29] = "f16c",
    [30] = "rdrnd",   [31] = "hyper",
};

static const char *str_e1d[32] =
{
    [ 0] = "fpu",    [ 1] = "vme",
    [ 2] = "de",     [ 3] = "pse",
    [ 4] = "tsc",    [ 5] = "msr",
    [ 6] = "pae",    [ 7] = "mce",
    [ 8] = "cx8",    [ 9] = "apic",
    /* [10] */       [11] = "syscall",
    [12] = "mtrr",   [13] = "pge",
    [14] = "mca",    [15] = "cmov",
    [16] = "fcmov",  [17] = "pse36",
    /* [18] */       [19] = "mp",
    [20] = "nx",     /* [21] */
    [22] = "mmx+",   [23] = "mmx",
    [24] = "fxsr",   [25] = "fxsr+",
    [26] = "pg1g",   [27] = "rdtscp",
    /* [28] */       [29] = "lm",
    [30] = "3dnow+", [31] = "3dnow",
};

static const char *str_e1c[32] =
{
    [ 0] = "lahf_lm",    [ 1] = "cmp",
    [ 2] = "svm",        [ 3] = "extapic",
    [ 4] = "cr8d",       [ 5] = "lzcnt",
    [ 6] = "sse4a",      [ 7] = "msse",
    [ 8] = "3dnowpf",    [ 9] = "osvw",
    [10] = "ibs",        [11] = "xop",
    [12] = "skinit",     [13] = "wdt",
    /* [14] */           [15] = "lwp",
    [16] = "fma4",       [17] = "tce",
    /* [18] */           [19] = "nodeid",
    /* [20] */           [21] = "tbm",
    [22] = "topoext",    [23] = "perfctr_core",
    [24] = "perfctr_nb", /* [25] */
    [26] = "dbx",        [27] = "perftsc",
    [28] = "pcx_l2i",    [29] = "monitorx",
};

static const char *str_7b0[32] =
{
    [ 0] = "fsgsbase", [ 1] = "tsc-adj",
    [ 2] = "sgx",      [ 3] = "bmi1",
    [ 4] = "hle",      [ 5] = "avx2",
    [ 6] = "fdp_exn",  [ 7] = "smep",
    [ 8] = "bmi2",     [ 9] = "erms",
    [10] = "invpcid",  [11] = "rtm",
    [12] = "pqm",      [13] = "depfpp",
    [14] = "mpx",      [15] = "pqe",
    [16] = "avx512f",  [17] = "avx512dq",
    [18] = "rdseed",   [19] = "adx",
    [20] = "smap",     [21] = "avx512ifma",
    [22] = "pcomit",   [23] = "clflushopt",
    [24] = "clwb",     [25] = "pt",
    [26] = "avx512pf", [27] = "avx512er",
    [28] = "avx512cd", [29] = "sha",
    [30] = "avx512bw", [31] = "avx512vl",
};

static const char *str_Da1[32] =
{
    [ 0] = "xsaveopt", [ 1] = "xsavec",
    [ 2] = "xgetbv1",  [ 3] = "xsaves",
};

static const char *str_7c0[32] =
{
    [ 0] = "prechwt1", [ 1] = "avx512vbmi",
    [ 2] = "umip",     [ 3] = "pku",
    [ 4] = "ospke",

    [14] = "avx512_vpopcntdq",

    [22] = "rdpid",
};

static const char *str_e7d[32] =
{
    [ 8] = "itsc",
    [10] = "efro",
};

static const char *str_e8b[32] =
{
    [ 0] = "clzero",

    [12] = "ibpb",
};

static const char *str_7d0[32] =
{
    [ 2] = "avx512_4vnniw", [ 3] = "avx512_4fmaps",

    [26] = "ibrsb",         [27] = "stibp",
};

static struct {
    const char *name;
    const char *abbr;
    const char **strs;
} decodes[] =
{
    { "0x00000001.edx",   "1d",  str_1d },
    { "0x00000001.ecx",   "1c",  str_1c },
    { "0x80000001.edx",   "e1d", str_e1d },
    { "0x80000001.ecx",   "e1c", str_e1c },
    { "0x0000000d:1.eax", "Da1", str_Da1 },
    { "0x00000007:0.ebx", "7b0", str_7b0 },
    { "0x00000007:0.ecx", "7c0", str_7c0 },
    { "0x80000007.edx",   "e7d", str_e7d },
    { "0x80000008.ebx",   "e8b", str_e8b },
    { "0x00000007:0.edx", "7d0", str_7d0 },
};

#define COL_ALIGN "18"

static struct fsinfo {
    const char *name;
    uint32_t len;
    uint32_t *fs;
} featuresets[] =
{
    [XEN_SYSCTL_cpu_featureset_host] = { "Host", 0, NULL },
    [XEN_SYSCTL_cpu_featureset_raw]  = { "Raw",  0, NULL },
    [XEN_SYSCTL_cpu_featureset_pv]   = { "PV",   0, NULL },
    [XEN_SYSCTL_cpu_featureset_hvm]  = { "HVM",  0, NULL },
};

static void dump_leaf(uint32_t leaf, const char **strs)
{
    unsigned i;

    if ( !strs )
    {
        printf(" ???");
        return;
    }

    for ( i = 0; i < 32; ++i )
        if ( leaf & (1u << i) )
        {
            if ( strs[i] )
                printf(" %s", strs[i]);
            else
                printf(" <%u>", i);
        }
}

static void decode_featureset(const uint32_t *features,
                              const uint32_t length,
                              const char *name,
                              bool detail)
{
    unsigned int i;

    printf("%-"COL_ALIGN"s        ", name);
    for ( i = 0; i < length; ++i )
        printf("%08x%c", features[i],
               i < length - 1 ? ':' : '\n');

    if ( !detail )
        return;

    for ( i = 0; i < length && i < ARRAY_SIZE(decodes); ++i )
    {
        printf("  [%02u] %-"COL_ALIGN"s", i, decodes[i].name ?: "<UNKNOWN>");
        if ( decodes[i].name )
            dump_leaf(features[i], decodes[i].strs);
        printf("\n");
    }
}

static void get_featureset(xc_interface *xch, unsigned int idx)
{
    struct fsinfo *f = &featuresets[idx];

    f->len = xc_get_cpu_featureset_size();
    f->fs = calloc(nr_features, sizeof(*f->fs));

    if ( !f->fs )
        err(1, "calloc(, featureset)");

    if ( xc_get_cpu_featureset(xch, idx, &f->len, f->fs) )
        err(1, "xc_get_featureset()");
}

static void dump_info(xc_interface *xch, bool detail)
{
    unsigned int i;

    printf("nr_features: %u\n", nr_features);

    if ( !detail )
    {
        printf("       %"COL_ALIGN"s ", "KEY");
        for ( i = 0; i < ARRAY_SIZE(decodes); ++i )
            printf("%-8s ", decodes[i].abbr ?: "???");
        printf("\n");
    }

    printf("\nStatic sets:\n");
    decode_featureset(xc_get_static_cpu_featuremask(XC_FEATUREMASK_KNOWN),
                      nr_features, "Known", detail);
    decode_featureset(xc_get_static_cpu_featuremask(XC_FEATUREMASK_SPECIAL),
                      nr_features, "Special", detail);
    decode_featureset(xc_get_static_cpu_featuremask(XC_FEATUREMASK_PV),
                      nr_features, "PV Mask", detail);
    decode_featureset(xc_get_static_cpu_featuremask(XC_FEATUREMASK_HVM_SHADOW),
                      nr_features, "HVM Shadow Mask", detail);
    decode_featureset(xc_get_static_cpu_featuremask(XC_FEATUREMASK_HVM_HAP),
                      nr_features, "HVM Hap Mask", detail);

    printf("\nDynamic sets:\n");
    for ( i = 0; i < ARRAY_SIZE(featuresets); ++i )
    {
        get_featureset(xch, i);

        decode_featureset(featuresets[i].fs, featuresets[i].len,
                          featuresets[i].name, detail);
    }

    for ( i = 0; i < ARRAY_SIZE(featuresets); ++i )
        free(featuresets[i].fs);
}

int main(int argc, char **argv)
{
    enum { MODE_UNKNOWN, MODE_INFO, MODE_DETAIL, MODE_INTERPRET }
    mode = MODE_UNKNOWN;

    nr_features = xc_get_cpu_featureset_size();

    for ( ;; )
    {
        int option_index = 0, c;
        static struct option long_options[] =
        {
            { "help", no_argument, NULL, 'h' },
            { "info", no_argument, NULL, 'i' },
            { "detail", no_argument, NULL, 'd' },
            { "verbose", no_argument, NULL, 'v' },
            { NULL, 0, NULL, 0 },
        };

        c = getopt_long(argc, argv, "hidv", long_options, &option_index);

        if ( c == -1 )
            break;

        switch ( c )
        {
        default:
            printf("Bad option '%c'\n", c);
            /* Fallthough */
        case 'h':
            printf("Usage: %s [ info | detail | <featureset>* ]\n", argv[0]);
            return 0;

        case 'i':
            mode = MODE_INFO;
            break;

        case 'd':
        case 'v':
            mode = MODE_DETAIL;
            break;
        }
    }

    if ( mode == MODE_UNKNOWN )
    {
        if ( optind == argc )
            mode = MODE_INFO;
        else if ( optind < argc )
        {
            if ( !strcmp(argv[optind], "info") )
            {
                mode = MODE_INFO;
                optind++;
            }
            else if ( !strcmp(argv[optind], "detail") )
            {
                mode = MODE_DETAIL;
                optind++;
            }
            else
                mode = MODE_INTERPRET;
        }
        else
            mode = MODE_INTERPRET;
    }

    if ( mode == MODE_INFO || mode == MODE_DETAIL )
    {
        xc_interface *xch = xc_interface_open(0, 0, 0);

        if ( !xch )
            err(1, "xc_interface_open");

        if ( xc_get_cpu_featureset(xch, 0, &nr_features, NULL) )
            err(1, "xc_get_featureset(, NULL)");

        dump_info(xch, mode == MODE_DETAIL);

        xc_interface_close(xch);
    }
    else
    {
        uint32_t fs[nr_features + 1];

        while ( optind < argc )
        {
            char *ptr = argv[optind++];
            unsigned int i = 0;
            int offset;

            memset(fs, 0, sizeof(fs));

            while ( sscanf(ptr, "%x%n", &fs[i], &offset) == 1 )
            {
                i++;
                ptr += offset;

                if ( i == nr_features )
                    break;

                if ( *ptr == ':' )
                {
                    ptr++; continue;
                }
                break;
            }

            decode_featureset(fs, i, "Raw", true);
        }
    }

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
