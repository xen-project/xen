#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>

#include <xenctrl.h>
#include <xenguest.h>

#include <xen-tools/common-macros.h>
#include <xen/lib/x86/cpuid-autogen.h>

static uint32_t nr_features;

static const struct {
    const char *name;
    const char *abbr;
} leaf_info[] = {
    { "CPUID 0x00000001.edx",        "1d" },
    { "CPUID 0x00000001.ecx",        "1c" },
    { "CPUID 0x80000001.edx",       "e1d" },
    { "CPUID 0x80000001.ecx",       "e1c" },
    { "CPUID 0x0000000d:1.eax",     "Da1" },
    { "CPUID 0x00000007:0.ebx",     "7b0" },
    { "CPUID 0x00000007:0.ecx",     "7c0" },
    { "CPUID 0x80000007.edx",       "e7d" },
    { "CPUID 0x80000008.ebx",       "e8b" },
    { "CPUID 0x00000007:0.edx",     "7d0" },
    { "CPUID 0x00000007:1.eax",     "7a1" },
    { "CPUID 0x80000021.eax",      "e21a" },
    { "CPUID 0x00000007:1.ebx",     "7b1" },
    { "CPUID 0x00000007:2.edx",     "7d2" },
    { "CPUID 0x00000007:1.ecx",     "7c1" },
    { "CPUID 0x00000007:1.edx",     "7d1" },
    { "MSR_ARCH_CAPS.lo",         "m10Al" },
    { "MSR_ARCH_CAPS.hi",         "m10Ah" },
};

#define COL_ALIGN "24"

static const char *const feature_names[] = INIT_FEATURE_VAL_TO_NAME;

static const char *const fs_names[] = {
    [XEN_SYSCTL_cpu_featureset_raw]     = "Raw",
    [XEN_SYSCTL_cpu_featureset_host]    = "Host",
    [XEN_SYSCTL_cpu_featureset_pv]      = "PV Default",
    [XEN_SYSCTL_cpu_featureset_hvm]     = "HVM Default",
    [XEN_SYSCTL_cpu_featureset_pv_max]  = "PV Max",
    [XEN_SYSCTL_cpu_featureset_hvm_max] = "HVM Max",
};

static void dump_leaf(uint32_t leaf, const char *const *strs)
{
    unsigned i;

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

    /* If this trips, you probably need to extend leaf_info[] above. */
    BUILD_BUG_ON(ARRAY_SIZE(leaf_info) != FEATURESET_NR_ENTRIES);
    BUILD_BUG_ON(ARRAY_SIZE(feature_names) != FEATURESET_NR_ENTRIES * 32);

    printf("%-"COL_ALIGN"s        ", name);
    for ( i = 0; i < length; ++i )
        printf("%08x%c", features[i],
               i < length - 1 ? ':' : '\n');

    if ( !detail )
        return;

    for ( i = 0; i < length && i < ARRAY_SIZE(leaf_info); ++i )
    {
        printf("  [%02u] %-"COL_ALIGN"s", i, leaf_info[i].name ?: "<UNKNOWN>");
        dump_leaf(features[i], &feature_names[i * 32]);
        printf("\n");
    }
}

static void dump_info(xc_interface *xch, bool detail)
{
    unsigned int i;
    uint32_t *fs;

    printf("nr_features: %u\n", nr_features);

    if ( !detail )
    {
        printf("       %"COL_ALIGN"s ", "KEY");
        for ( i = 0; i < ARRAY_SIZE(leaf_info); ++i )
            printf("%-8s ", leaf_info[i].abbr ?: "???");
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

    fs = malloc(sizeof(*fs) * nr_features);
    if ( !fs )
        err(1, "malloc(featureset)");

    for ( i = 0; i < ARRAY_SIZE(fs_names); ++i )
    {
        uint32_t len = nr_features;
        int ret;

        memset(fs, 0, sizeof(*fs) * nr_features);

        ret = xc_get_cpu_featureset(xch, i, &len, fs);
        if ( ret )
        {
            if ( errno == EOPNOTSUPP )
            {
                printf("%s featureset not supported by Xen\n", fs_names[i]);
                continue;
            }

            err(1, "xc_get_featureset()");
        }

        decode_featureset(fs, len, fs_names[i], detail);
    }

    free(fs);
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
        xc_cpu_policy_t *policy = xc_cpu_policy_init();

        if ( !xch )
            err(1, "xc_interface_open");
        if ( !policy )
            err(1, "xc_cpu_policy_init");

        if ( xc_cpu_policy_get_size(xch, &max_leaves, &max_msrs) )
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

            if ( xc_cpu_policy_get_domain(xch, domid, policy) )
                err(1, "xc_cpu_policy_get_domain(, %d, )", domid);
            if ( xc_cpu_policy_serialise(xch, policy, leaves, &nr_leaves,
                                         msrs, &nr_msrs) )
                err(1, "xc_cpu_policy_serialise");

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

                if ( xc_cpu_policy_get_system(xch, i, policy) )
                {
                    if ( errno == EOPNOTSUPP )
                    {
                        printf("%s policy not supported by Xen\n",
                               sys_policies[i]);
                        continue;
                    }

                    err(1, "xc_cpu_policy_get_system(, %s, )", sys_policies[i]);
                }
                if ( xc_cpu_policy_serialise(xch, policy, leaves, &nr_leaves,
                                             msrs, &nr_msrs) )
                    err(1, "xc_cpu_policy_serialise");

                print_policy(sys_policies[i], leaves, nr_leaves,
                             msrs, nr_msrs);
            }
        }

        xc_cpu_policy_destroy(policy);
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

                if ( *ptr == ':' || *ptr == '-' )
                {
                    ptr++;
                    continue;
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
