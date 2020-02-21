#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>

#include <xenctrl.h>

#include <xen-tools/libs.h>

static uint32_t nr_features;

static const char *const str_1d[32] =
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

static const char *const str_1c[32] =
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

static const char *const str_e1d[32] =
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

static const char *const str_e1c[32] =
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

static const char *const str_7b0[32] =
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
    [20] = "smap",     [21] = "avx512-ifma",
    [22] = "pcommit",  [23] = "clflushopt",
    [24] = "clwb",     [25] = "pt",
    [26] = "avx512pf", [27] = "avx512er",
    [28] = "avx512cd", [29] = "sha",
    [30] = "avx512bw", [31] = "avx512vl",
};

static const char *const str_Da1[32] =
{
    [ 0] = "xsaveopt", [ 1] = "xsavec",
    [ 2] = "xgetbv1",  [ 3] = "xsaves",
};

static const char *const str_7c0[32] =
{
    [ 0] = "prefetchwt1",      [ 1] = "avx512_vbmi",
    [ 2] = "umip",             [ 3] = "pku",
    [ 4] = "ospke",            [ 5] = "waitpkg",
    [ 6] = "avx512_vbmi2",     [ 7] = "cet-ss",
    [ 8] = "gfni",             [ 9] = "vaes",
    [10] = "vpclmulqdq",       [11] = "avx512_vnni",
    [12] = "avx512_bitalg",
    [14] = "avx512_vpopcntdq",

    [22] = "rdpid",
    /* 24 */                   [25] = "cldemote",
    /* 26 */                   [27] = "movdiri",
    [28] = "movdir64b",
    [30] = "sgx_lc",
};

static const char *const str_e7d[32] =
{
    [ 8] = "itsc",
    [10] = "efro",
};

static const char *const str_e8b[32] =
{
    [ 0] = "clzero",
    [ 2] = "rstr-fp-err-ptrs",

    /* [ 8] */            [ 9] = "wbnoinvd",

    [12] = "ibpb",

    /* [22] */                 [23] = "ppin",
};

static const char *const str_7d0[32] =
{
    [ 2] = "avx512_4vnniw", [ 3] = "avx512_4fmaps",
    [ 4] = "fsrm",

    [10] = "md-clear",
    /* 12 */                [13] = "tsx-force-abort",

    [18] = "pconfig",
    [20] = "cet-ibt",

    [26] = "ibrsb",         [27] = "stibp",
    [28] = "l1d_flush",     [29] = "arch_caps",
    [30] = "core_caps",     [31] = "ssbd",
};

static const char *const str_7a1[32] =
{
    /* 4 */                 [ 5] = "avx512_bf16",
};

static const struct {
    const char *name;
    const char *abbr;
    const char *const *strs;
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
    { "0x00000007:1.eax", "7a1", str_7a1 },
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

static void dump_leaf(uint32_t leaf, const char *const *strs)
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

static int get_featureset(xc_interface *xch, unsigned int idx)
{
    struct fsinfo *f = &featuresets[idx];

    f->len = nr_features;
    f->fs = calloc(nr_features, sizeof(*f->fs));

    if ( !f->fs )
        err(1, "calloc(, featureset)");

    return xc_get_cpu_featureset(xch, idx, &f->len, f->fs);
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
    decode_featureset(xc_get_static_cpu_featuremask(XC_FEATUREMASK_PV_MAX),
                      nr_features, "PV Max", detail);
    decode_featureset(xc_get_static_cpu_featuremask(XC_FEATUREMASK_PV_DEF),
                      nr_features, "PV Default", detail);
    decode_featureset(xc_get_static_cpu_featuremask(XC_FEATUREMASK_HVM_SHADOW_MAX),
                      nr_features, "HVM Shadow Max", detail);
    decode_featureset(xc_get_static_cpu_featuremask(XC_FEATUREMASK_HVM_SHADOW_DEF),
                      nr_features, "HVM Shadow Default", detail);
    decode_featureset(xc_get_static_cpu_featuremask(XC_FEATUREMASK_HVM_HAP_MAX),
                      nr_features, "HVM Hap Max", detail);
    decode_featureset(xc_get_static_cpu_featuremask(XC_FEATUREMASK_HVM_HAP_DEF),
                      nr_features, "HVM Hap Default", detail);

    printf("\nDynamic sets:\n");
    for ( i = 0; i < ARRAY_SIZE(featuresets); ++i )
    {
        if ( get_featureset(xch, i) )
        {
            if ( errno == EOPNOTSUPP )
            {
                printf("%s featureset not supported by Xen\n",
                       featuresets[i].name);
                continue;
            }

            err(1, "xc_get_featureset()");
        }

        decode_featureset(featuresets[i].fs, featuresets[i].len,
                          featuresets[i].name, detail);
    }

    for ( i = 0; i < ARRAY_SIZE(featuresets); ++i )
        free(featuresets[i].fs);
}

static void print_policy(const char *name,
                         xen_cpuid_leaf_t *leaves, uint32_t nr_leaves,
                         xen_msr_entry_t *msrs, uint32_t nr_msrs)
{
    unsigned int l;

    printf("%s policy: %u leaves, %u MSRs\n", name, nr_leaves, nr_msrs);
    printf(" CPUID:\n");
    printf("  %-8s %-8s -> %-8s %-8s %-8s %-8s\n",
           "leaf", "subleaf", "eax", "ebx", "ecx", "edx");
    for ( l = 0; l < nr_leaves; ++l )
    {
        /* Skip empty leaves. */
        if ( !leaves[l].a && !leaves[l].b && !leaves[l].c && !leaves[l].d )
            continue;

        printf("  %08x:%08x -> %08x:%08x:%08x:%08x\n",
               leaves[l].leaf, leaves[l].subleaf,
               leaves[l].a, leaves[l].b, leaves[l].c, leaves[l].d);
    }

    printf(" MSRs:\n");
    printf("  %-8s -> %-16s\n", "index", "value");
    for ( l = 0; l < nr_msrs; ++l )
        printf("  %08x -> %016"PRIx64"\n",
               msrs[l].idx, msrs[l].val);
}

int main(int argc, char **argv)
{
    enum { MODE_UNKNOWN, MODE_INFO, MODE_DETAIL, MODE_INTERPRET, MODE_POLICY }
    mode = MODE_UNKNOWN;
    int domid = -1;

    nr_features = xc_get_cpu_featureset_size();

    for ( ;; )
    {
        const char *tmp_optarg;
        int option_index = 0, c;
        static const struct option long_options[] =
        {
            { "help", no_argument, NULL, 'h' },
            { "info", no_argument, NULL, 'i' },
            { "detail", no_argument, NULL, 'd' },
            { "verbose", no_argument, NULL, 'v' },
            { "policy", optional_argument, NULL, 'p' },
            { NULL, 0, NULL, 0 },
        };

        c = getopt_long(argc, argv, "hidvp::", long_options, &option_index);

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

        case 'p':
            mode = MODE_POLICY;

            tmp_optarg = optarg;

            /* Make "--policy $DOMID" and "-p $DOMID" work. */
            if ( !optarg && optind < argc &&
                 argv[optind] != NULL && argv[optind][0] != '\0' &&
                 argv[optind][0] != '-' )
                tmp_optarg = argv[optind++];

            if ( tmp_optarg )
            {
                char *endptr;

                errno = 0;
                domid = strtol(tmp_optarg, &endptr, 0);
                if ( errno || endptr == tmp_optarg )
                    err(1, "strtol(%s,,)", tmp_optarg);
            }
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

    if ( mode == MODE_POLICY )
    {
        static const char *const sys_policies[] = {
            [ XEN_SYSCTL_cpu_policy_raw ]          = "Raw",
            [ XEN_SYSCTL_cpu_policy_host ]         = "Host",
            [ XEN_SYSCTL_cpu_policy_pv_max ]       = "PV Max",
            [ XEN_SYSCTL_cpu_policy_hvm_max ]      = "HVM Max",
            [ XEN_SYSCTL_cpu_policy_pv_default ]   = "PV Default",
            [ XEN_SYSCTL_cpu_policy_hvm_default ]  = "HVM Default",
        };
        xen_cpuid_leaf_t *leaves;
        xen_msr_entry_t *msrs;
        uint32_t i, max_leaves, max_msrs;

        xc_interface *xch = xc_interface_open(0, 0, 0);

        if ( !xch )
            err(1, "xc_interface_open");

        if ( xc_get_cpu_policy_size(xch, &max_leaves, &max_msrs) )
            err(1, "xc_get_cpu_policy_size(...)");
        if ( domid == -1 )
            printf("Xen reports there are maximum %u leaves and %u MSRs\n",
                   max_leaves, max_msrs);

        leaves = calloc(max_leaves, sizeof(xen_cpuid_leaf_t));
        if ( !leaves )
            err(1, "calloc(max_leaves)");
        msrs = calloc(max_msrs, sizeof(xen_msr_entry_t));
        if ( !msrs )
            err(1, "calloc(max_msrs)");

        if ( domid != -1 )
        {
            char name[20];
            uint32_t nr_leaves = max_leaves;
            uint32_t nr_msrs = max_msrs;

            if ( xc_get_domain_cpu_policy(xch, domid, &nr_leaves, leaves,
                                          &nr_msrs, msrs) )
                err(1, "xc_get_domain_cpu_policy(, %d, %d,, %d,)",
                    domid, nr_leaves, nr_msrs);

            snprintf(name, sizeof(name), "Domain %d", domid);
            print_policy(name, leaves, nr_leaves, msrs, nr_msrs);
        }
        else
        {
            /* Get system policies */
            for ( i = 0; i < ARRAY_SIZE(sys_policies); ++i )
            {
                uint32_t nr_leaves = max_leaves;
                uint32_t nr_msrs = max_msrs;

                if ( xc_get_system_cpu_policy(xch, i, &nr_leaves, leaves,
                                              &nr_msrs, msrs) )
                {
                    if ( errno == EOPNOTSUPP )
                    {
                        printf("%s policy not supported by Xen\n",
                               sys_policies[i]);
                        continue;
                    }

                    err(1, "xc_get_system_cpu_policy(, %s,,)", sys_policies[i]);
                }

                print_policy(sys_policies[i], leaves, nr_leaves,
                             msrs, nr_msrs);
            }
        }

        free(leaves);
        free(msrs);
        xc_interface_close(xch);
    }
    else if ( mode == MODE_INFO || mode == MODE_DETAIL )
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

            if ( !i )
            {
                fprintf(stderr, "'%s' unrecognized - skipping\n", ptr);
                continue;
            }

            if ( *ptr )
                fprintf(stderr, "'%s' unrecognized - ignoring\n", ptr);

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
