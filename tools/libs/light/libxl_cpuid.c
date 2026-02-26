/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"

#include <xen/lib/x86/cpu-policy.h>

int libxl__cpuid_policy_is_empty(libxl_cpuid_policy_list *pl)
{
    return !*pl || (!libxl_cpuid_policy_list_length(pl) && !(*pl)->msr);
}

void libxl_cpuid_dispose(libxl_cpuid_policy_list *pl)
{
    libxl_cpuid_policy_list policy = *pl;

    if (policy == NULL)
        return;

    if (policy->cpuid) {
        unsigned int i, j;
        struct xc_xend_cpuid *cpuid_list = policy->cpuid;

        for (i = 0; cpuid_list[i].input[0] != XEN_CPUID_INPUT_UNUSED; i++) {
            for (j = 0; j < 4; j++) {
                if (cpuid_list[i].policy[j] != NULL) {
                    free(cpuid_list[i].policy[j]);
                }
            }
        }
        free(policy->cpuid);
    }

    free(policy->msr);

    free(policy);
    *pl = NULL;
    return;
}

#define CPUID_REG_INV 0
#define CPUID_REG_EAX 1
#define CPUID_REG_EBX 2
#define CPUID_REG_ECX 3
#define CPUID_REG_EDX 4

/* mapping CPUID features to names
 * holds a "name" for each feature, specified by the "leaf" number (and an
 * optional "subleaf" in ECX), the "reg"ister (EAX-EDX) used and a number of
 * bits starting with "bit" and being "length" bits long.
 * Used for the static structure describing all features.
 */
struct cpuid_flags {
    const char *name;
    uint32_t leaf;
    uint32_t subleaf;
    int reg;
    int bit;
    int length;
};

/* go through the dynamic array finding the entry for a specified leaf.
 * if no entry exists, allocate one and return that.
 */
static struct xc_xend_cpuid *cpuid_find_match(libxl_cpuid_policy_list *pl,
                                              uint32_t leaf, uint32_t subleaf)
{
    libxl_cpuid_policy_list policy = *pl;
    struct xc_xend_cpuid **list;
    int i = 0;

    if (policy == NULL)
        policy = *pl = calloc(1, sizeof(*policy));

    list = &policy->cpuid;
    if (*list != NULL) {
        for (i = 0; (*list)[i].input[0] != XEN_CPUID_INPUT_UNUSED; i++) {
            if ((*list)[i].input[0] == leaf && (*list)[i].input[1] == subleaf)
                return *list + i;
        }
    }
    *list = realloc(*list, sizeof((*list)[0]) * (i + 2));
    (*list)[i].input[0] = leaf;
    (*list)[i].input[1] = subleaf;
    memset((*list)[i].policy, 0, 4 * sizeof(char*));
    (*list)[i + 1].input[0] = XEN_CPUID_INPUT_UNUSED;
    return *list + i;
}

static int cpuid_add(libxl_cpuid_policy_list *policy,
                     const struct cpuid_flags *flag, const char *val)
{
    struct xc_xend_cpuid *entry = cpuid_find_match(policy, flag->leaf,
                                                   flag->subleaf);
    unsigned long num;
    char flags[33], *resstr, *endptr;
    unsigned int i;

    resstr = entry->policy[flag->reg - 1];
    num = strtoul(val, &endptr, 0);
    flags[flag->length] = 0;
    if (endptr != val) {
        /* if this was a valid number, write the binary form into the string */
        for (i = 0; i < flag->length; i++) {
            flags[flag->length - 1 - i] = "01"[(num >> i) & 1];
        }
    } else {
        switch(val[0]) {
        case 'x': case 'k': case 's':
            memset(flags, val[0], flag->length);
            break;
        default:
            return 3;
        }
    }

    if (resstr == NULL) {
        resstr = strdup("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    }

    /* the family and model entry is potentially split up across
     * two fields in Fn0000_0001_EAX, so handle them here separately.
     */
    if (!strcmp(flag->name, "family")) {
        if (num < 16) {
            memcpy(resstr + (32 - 4) - flag->bit, flags + 4, 4);
            memcpy(resstr + (32 - 8) - 20, "00000000", 8);
        } else {
            num -= 15;
            memcpy(resstr + (32 - 4) - flag->bit, "1111", 4);
            for (i = 0; i < 7; i++) {
                flags[7 - i] = "01"[num & 1];
                num >>= 1;
            }
            memcpy(resstr + (32 - 8) - 20, flags, 8);
        }
    } else if (!strcmp(flag->name, "model")) {
        memcpy(resstr + (32 - 4) - 16, flags, 4);
        memcpy(resstr + (32 - 4) - flag->bit, flags + 4, 4);
    } else {
        memcpy(resstr + (32 - flag->length) - flag->bit, flags,
               flag->length);
    }
    entry->policy[flag->reg - 1] = resstr;

    return 0;
}

static struct xc_msr *msr_find_match(libxl_cpuid_policy_list *pl, uint32_t idx)
{
    unsigned int i = 0;
    libxl_cpuid_policy_list policy = *pl;

    if (policy == NULL)
        policy = *pl = calloc(1, sizeof(*policy));

    if (policy->msr != NULL) {
        for (i = 0; policy->msr[i].index != XC_MSR_INPUT_UNUSED; i++) {
            if (policy->msr[i].index == idx) {
                return &policy->msr[i];
            }
        }
    }

    policy->msr = realloc(policy->msr, sizeof(struct xc_msr) * (i + 2));
    policy->msr[i].index = idx;
    memset(policy->msr[i].policy, 'x', ARRAY_SIZE(policy->msr[0].policy) - 1);
    policy->msr[i].policy[ARRAY_SIZE(policy->msr[0].policy) - 1] = '\0';
    policy->msr[i + 1].index = XC_MSR_INPUT_UNUSED;

    return &policy->msr[i];
}

static int msr_add(libxl_cpuid_policy_list *policy, uint32_t idx,
                   unsigned int bit, const char *val)
{
    struct xc_msr *entry = msr_find_match(policy, idx);

    /* Only allow options taking a character for MSRs, no values allowed. */
    if (strlen(val) != 1)
        return 3;

    switch (val[0]) {
    case '0':
    case '1':
    case 'x':
    case 'k':
        entry->policy[63 - bit] = val[0];
        break;

    case 's':
        /* Translate s -> k as xc_msr doesn't support the deprecated 's'. */
        entry->policy[63 - bit] = 'k';
        break;

    default:
        return 3;
    }

    return 0;
}

struct feature_name {
    const char *name;
    unsigned int bit;
};

static int search_feature(const void *a, const void *b)
{
    const char *key = a;
    const char *feat = ((const struct feature_name *)b)->name;

    return strcmp(key, feat);
}

/* parse a single key=value pair and translate it into the libxc
 * used interface using 32-characters strings for each register.
 * Will overwrite earlier entries and thus can be called multiple
 * times.
 */
int libxl_cpuid_parse_config(libxl_cpuid_policy_list *policy, const char* str)
{
#define NA XEN_CPUID_INPUT_UNUSED
    static const struct cpuid_flags cpuid_flags[] = {
        {"maxleaf",      0x00000000, NA, CPUID_REG_EAX,  0, 32},
      /* the following two entries are subject to tweaking later in the code */
        {"stepping",     0x00000001, NA, CPUID_REG_EAX,  0,  4},
        {"model",        0x00000001, NA, CPUID_REG_EAX,  4,  8},
        {"family",       0x00000001, NA, CPUID_REG_EAX,  8,  8},

        {"brandid",      0x00000001, NA, CPUID_REG_EBX,  0,  8},
        {"clflush",      0x00000001, NA, CPUID_REG_EBX,  8,  8},
        {"proccount",    0x00000001, NA, CPUID_REG_EBX, 16,  8},
        {"localapicid",  0x00000001, NA, CPUID_REG_EBX, 24,  8},

        {"est",          0x00000001, NA, CPUID_REG_ECX,  7,  1},
        {"cntxid",       0x00000001, NA, CPUID_REG_ECX, 10,  1},
        {"cmpxchg16",    0x00000001, NA, CPUID_REG_ECX, 13,  1},
        /* Linux uses sse4_{1,2}.  Keep sse4.{1,2} for compatibility */
        {"sse4_1",       0x00000001, NA, CPUID_REG_ECX, 19,  1},
        {"sse4.1",       0x00000001, NA, CPUID_REG_ECX, 19,  1},
        {"sse4_2",       0x00000001, NA, CPUID_REG_ECX, 20,  1},
        {"sse4.2",       0x00000001, NA, CPUID_REG_ECX, 20,  1},
        {"aes",          0x00000001, NA, CPUID_REG_ECX, 25,  1},

        {"cmpxchg8",     0x00000001, NA, CPUID_REG_EDX,  8,  1},
        {"sysenter",     0x00000001, NA, CPUID_REG_EDX, 11,  1},
        {"psn",          0x00000001, NA, CPUID_REG_EDX, 18,  1},
        {"clfsh",        0x00000001, NA, CPUID_REG_EDX, 19,  1},
        {"tm",           0x00000001, NA, CPUID_REG_EDX, 29,  1},
        {"ia64",         0x00000001, NA, CPUID_REG_EDX, 30,  1},

        {"arat",         0x00000006, NA, CPUID_REG_EAX,  2,  1},

        {"tsc_adjust",   0x00000007,  0, CPUID_REG_EBX,  1,  1},
        {"cmt",          0x00000007,  0, CPUID_REG_EBX, 12,  1},

        {"lahfsahf",     0x80000001, NA, CPUID_REG_ECX,  0,  1},
        {"cmplegacy",    0x80000001, NA, CPUID_REG_ECX,  1,  1},
        {"altmovcr8",    0x80000001, NA, CPUID_REG_ECX,  4,  1},
        {"nodeid",       0x80000001, NA, CPUID_REG_ECX, 19,  1},
        {"perfctr_core", 0x80000001, NA, CPUID_REG_ECX, 23,  1},
        {"perfctr_nb",   0x80000001, NA, CPUID_REG_ECX, 24,  1},

        {"procpkg",      0x00000004,  0, CPUID_REG_EAX, 26,  6},

        {"invtsc",       0x80000007, NA, CPUID_REG_EDX,  8,  1},

        {"ppin",         0x80000008, NA, CPUID_REG_EBX, 23,  1},

        {"nc",           0x80000008, NA, CPUID_REG_ECX,  0,  8},
        {"apicidsize",   0x80000008, NA, CPUID_REG_ECX, 12,  4},

        {"svm_npt",      0x8000000a, NA, CPUID_REG_EDX,  0,  1},
        {"svm_lbrv",     0x8000000a, NA, CPUID_REG_EDX,  1,  1},
        {"svm_nrips",    0x8000000a, NA, CPUID_REG_EDX,  3,  1},
        {"svm_tscrate",  0x8000000a, NA, CPUID_REG_EDX,  4,  1},
        {"svm_vmcbclean",0x8000000a, NA, CPUID_REG_EDX,  5,  1},
        {"svm_decode",   0x8000000a, NA, CPUID_REG_EDX,  7,  1},
        {"svm_pausefilt",0x8000000a, NA, CPUID_REG_EDX, 10,  1},

        {"lfence+",      0x80000021, NA, CPUID_REG_EAX,  2,  1},

        {"maxhvleaf",    0x40000000, NA, CPUID_REG_EAX,  0,  8},

        {NULL, 0, NA, CPUID_REG_INV, 0, 0}
    };
    static const struct feature_name features[] = INIT_FEATURE_NAME_TO_VAL;
    /*
     * NB: if we switch to using a cpu_policy derived object instead of a
     * libxl_cpuid_policy_list we could get rid of the featureset -> cpuid leaf
     * conversion table and use a featureset directly as we have conversions
     * to/from featureset and cpu_policy.
     */
    static const struct {
        enum { FEAT_CPUID, FEAT_MSR } type;
        union {
            struct {
                uint32_t leaf, subleaf;
                unsigned int reg;
            } cpuid;
            struct {
                uint32_t index;
                unsigned int reg;
            } msr;
        } u;
    } feature_to_policy[] = {
#define CPUID_ENTRY(l, s, r) \
    { .type = FEAT_CPUID, \
      .u = { .cpuid.leaf = l, .cpuid.subleaf = s, .cpuid.reg = r } \
    }
#define MSR_ENTRY(i, r) \
    { .type = FEAT_MSR, \
      .u = { .msr.index = i, .msr.reg = r } \
    }
        CPUID_ENTRY(0x00000001, NA, CPUID_REG_EDX),
        CPUID_ENTRY(0x00000001, NA, CPUID_REG_ECX),
        CPUID_ENTRY(0x80000001, NA, CPUID_REG_EDX),
        CPUID_ENTRY(0x80000001, NA, CPUID_REG_ECX),
        CPUID_ENTRY(0x0000000D,  1, CPUID_REG_EAX),
        CPUID_ENTRY(0x00000007,  0, CPUID_REG_EBX),
        CPUID_ENTRY(0x00000007,  0, CPUID_REG_ECX),
        CPUID_ENTRY(0x80000007, NA, CPUID_REG_EDX),
        CPUID_ENTRY(0x80000008, NA, CPUID_REG_EBX),
        CPUID_ENTRY(0x00000007,  0, CPUID_REG_EDX),
        CPUID_ENTRY(0x00000007,  1, CPUID_REG_EAX),
        CPUID_ENTRY(0x80000021, NA, CPUID_REG_EAX),
        CPUID_ENTRY(0x00000007,  1, CPUID_REG_EBX),
        CPUID_ENTRY(0x00000007,  2, CPUID_REG_EDX),
        CPUID_ENTRY(0x00000007,  1, CPUID_REG_ECX),
        CPUID_ENTRY(0x00000007,  1, CPUID_REG_EDX),
        MSR_ENTRY(0x10a, CPUID_REG_EAX),
        MSR_ENTRY(0x10a, CPUID_REG_EDX),
        CPUID_ENTRY(0x80000021, NA, CPUID_REG_ECX),
#undef MSR_ENTRY
#undef CPUID_ENTRY
    };
#undef NA
    const char *sep, *val;
    char *name;
    const struct cpuid_flags *flag;
    const struct feature_name *feat;

    BUILD_BUG_ON(ARRAY_SIZE(feature_to_policy) != FEATURESET_NR_ENTRIES);

    sep = strchr(str, '=');
    if (sep == NULL) {
        return 1;
    } else {
        val = sep + 1;
    }
    for (flag = cpuid_flags; flag->name != NULL; flag++) {
        if(!strncmp(str, flag->name, sep - str) && flag->name[sep - str] == 0)
            return cpuid_add(policy, flag, val);
    }

    /* Provide a NUL terminated feature name to the search helper. */
    name = strndup(str, sep - str);
    if (name == NULL)
        return ERROR_NOMEM;

    feat = bsearch(name, features, ARRAY_SIZE(features), sizeof(features[0]),
                   search_feature);
    free(name);

    if (feat == NULL)
        return 2;

    switch (feature_to_policy[feat->bit / 32].type) {
    case FEAT_CPUID:
    {
        struct cpuid_flags f;

        f.name = feat->name;
        f.leaf = feature_to_policy[feat->bit / 32].u.cpuid.leaf;
        f.subleaf = feature_to_policy[feat->bit / 32].u.cpuid.subleaf;
        f.reg = feature_to_policy[feat->bit / 32].u.cpuid.reg;
        f.bit = feat->bit % 32;
        f.length = 1;

        return cpuid_add(policy, &f, val);
    }

    case FEAT_MSR:
    {
        unsigned int bit = feat->bit % 32;

        if (feature_to_policy[feat->bit / 32].u.msr.reg == CPUID_REG_EDX)
            bit += 32;

        return msr_add(policy, feature_to_policy[feat->bit / 32].u.msr.index,
                       bit, val);
    }
    }

    return 2;
}

/* parse a single list item from the legacy Python xend syntax, where
 * the strings for each register were directly exposed to the user.
 * Used for maintaining compatibility with older config files
 */
int libxl_cpuid_parse_config_xend(libxl_cpuid_policy_list *policy,
                                  const char* str)
{
    char *endptr;
    unsigned long value;
    uint32_t leaf, subleaf = XEN_CPUID_INPUT_UNUSED;
    struct xc_xend_cpuid *entry;

    /* parse the leaf number */
    value = strtoul(str, &endptr, 0);
    if (str == endptr) {
        return 1;
    }
    leaf = value;
    /* check for an optional subleaf number */
    if (*endptr == ',') {
        str = endptr + 1;
        value = strtoul(str, &endptr, 0);
        if (str == endptr) {
            return 2;
        }
        subleaf = value;
    }
    if (*endptr != ':') {
        return 3;
    }
    str = endptr + 1;
    entry = cpuid_find_match(policy, leaf, subleaf);
    for (str = endptr + 1; *str != 0;) {
        const char *endptrc;

        if (str[0] != 'e' || str[2] != 'x') {
            return 4;
        }
        value = str[1] - 'a';
        endptrc = strchr(str, '=');
        if (value > 3 || endptrc == NULL) {
            return 4;
        }
        str = endptrc + 1;
        endptrc = strchr(str, ',');
        if (endptrc == NULL) {
            endptrc = strchr(str, 0);
        }
        if (endptrc - str != 32) {
            return 5;
        }
        entry->policy[value] = calloc(32 + 1, 1);
        strncpy(entry->policy[value], str, 32);
        entry->policy[value][32] = 0;
        if (*endptrc == 0) {
            break;
        }
        for (str = endptrc + 1; *str == ' ' || *str == '\n'; str++)
            ;
    }
    return 0;
}

int libxl__cpuid_legacy(libxl_ctx *ctx, uint32_t domid, bool restore,
                        libxl_domain_build_info *info)
{
    GC_INIT(ctx);
    bool pae = true;
    bool itsc;
    int r;

    /*
     * Gross hack.  Using libxl_defbool_val() here causes libvirt to crash in
     * __vfscanf_internal(), which is probably collateral damage from a side
     * effect of the assert().
     *
     * Unblock things for now by opencoding without the assert.
     */
    bool nested_virt = info->nested_hvm.val > 0;

    /*
     * For PV guests, PAE is Xen-controlled (it is the 'p' that differentiates
     * the xen-3.0-x86_32 and xen-3.0-x86_32p ABIs).  It is mandatory as Xen
     * is 64bit only these days.
     *
     * For PVH guests, there is no top-level PAE control in the domain config,
     * so is treated as always available.
     *
     * HVM guests get a top-level choice of whether PAE is available.
     */
    if (info->type == LIBXL_DOMAIN_TYPE_HVM)
        pae = libxl_defbool_val(info->u.hvm.pae);

    /*
     * Advertising Invariant TSC to a guest means that the TSC frequency won't
     * change at any point in the future.
     *
     * We do not have enough information about potential migration
     * destinations to know whether advertising ITSC is safe, but if the guest
     * isn't going to migrate, then the current hardware is all that matters.
     *
     * Alternatively, an internal property of vTSC is that the values read are
     * invariant.  Advertise ITSC when we know the domain will have emulated
     * TSC everywhere it goes.
     */
    itsc = (libxl_defbool_val(info->disable_migrate) ||
            info->tsc_mode == LIBXL_TSC_MODE_ALWAYS_EMULATE);

    r = xc_cpuid_apply_policy(ctx->xch, domid, restore, NULL, 0,
                              pae, itsc, nested_virt,
                              info->cpuid ? info->cpuid->cpuid : NULL,
                              info->cpuid ? info->cpuid->msr : NULL);
    if (r)
        LOGEVD(ERROR, -r, domid, "Failed to apply CPUID policy");

    GC_FREE;
    return r ? ERROR_FAIL : 0;
}

static const char *input_names[2] = { "leaf", "subleaf" };
static const char *policy_names[4] = { "eax", "ebx", "ecx", "edx" };
/*
 * Aiming for:
 * {   'cpuid': [
 *              { 'leaf':    'val-eax',
 *                'subleaf': 'val-ecx',
 *                'eax':     'filter',
 *                'ebx':     'filter',
 *                'ecx':     'filter',
 *                'edx':     'filter' },
 *              { 'leaf':    'val-eax', ..., 'eax': 'filter', ... },
 *              ... etc ...
 *     ],
 *     'msr': [
 *            { 'index': 'val-index',
 *              'policy': 'filter', },
 *              ... etc ...
 *     ],
 * }
 */

#ifdef HAVE_LIBJSONC
int libxl_cpuid_policy_list_gen_jso(json_object **jso_r, libxl_cpuid_policy_list *pl)
{
    libxl_cpuid_policy_list policy = *pl;
    struct xc_xend_cpuid *cpuid;
    const struct xc_msr *msr;
    json_object *jso_outer;
    json_object *jso_array;
    int i, j;
    int r;
    int rc = ERROR_FAIL;

    jso_outer = json_object_new_object();
    if (!jso_outer) goto out;

    jso_array = json_object_new_array();
    if (!jso_array) goto out;

    r = json_object_object_add(jso_outer, "cpuid", jso_array);
    if (r < 0) {
        json_object_put(jso_array);
        goto out;
    }

    if (policy == NULL || policy->cpuid == NULL) goto empty;
    cpuid = policy->cpuid;

    for (i = 0; cpuid[i].input[0] != XEN_CPUID_INPUT_UNUSED; i++) {
        json_object *jso_inner;
        jso_inner = json_object_new_object();
        if (!jso_inner) goto out;

        r = json_object_array_add(jso_array, jso_inner);
        if (r < 0) {
            json_object_put(jso_inner);
            goto out;
        }

        for (j = 0; j < 2; j++) {
            if (cpuid[i].input[j] != XEN_CPUID_INPUT_UNUSED) {
                json_object *jso_value = json_object_new_int(cpuid[i].input[j]);
                if (!jso_value) goto out;
                r = json_object_object_add(jso_inner, input_names[j], jso_value);
                if (r < 0) {
                    json_object_put(jso_value);
                    goto out;
                }
            }
        }

        for (j = 0; j < 4; j++) {
            if (cpuid[i].policy[j] != NULL) {
                json_object *jso_value = json_object_new_string_len(cpuid[i].policy[j], 32);
                if (!jso_value) goto out;
                r = json_object_object_add(jso_inner, policy_names[j], jso_value);
                if (r < 0) {
                    json_object_put(jso_value);
                    goto out;
                }
            }
        }
    }

empty:

    jso_array = json_object_new_array();
    if (!jso_array) goto out;

    r = json_object_object_add(jso_outer, "msr", jso_array);
    if (r < 0) {
        json_object_put(jso_array);
        goto out;
    }

    if (!policy || !policy->msr) goto done;
    msr = policy->msr;

    for (i = 0; msr[i].index != XC_MSR_INPUT_UNUSED; i++) {
        json_object *jso_inner;
        json_object *jso_value;

        jso_inner = json_object_new_object();
        if (!jso_inner) goto out;

        r = json_object_array_add(jso_array, jso_inner);
        if (r < 0) {
            json_object_put(jso_inner);
            goto out;
        }

        jso_value = json_object_new_int(msr[i].index);
        if (!jso_value) goto out;
        r = json_object_object_add(jso_inner, "index", jso_value);
        if (r < 0) {
            json_object_put(jso_value);
            goto out;
        }

        jso_value = json_object_new_string_len(msr[i].policy, 64);
        if (!jso_value) goto out;
        r = json_object_object_add(jso_inner, "policy", jso_value);
        if (r < 0) {
            json_object_put(jso_value);
            goto out;
        }
    }

done:
    *jso_r = jso_outer;
    jso_outer = NULL;
    rc = 0;
out:
    json_object_put(jso_outer);
    return rc;
}
#endif

#ifdef HAVE_LIBYAJL
yajl_gen_status libxl_cpuid_policy_list_gen_json(yajl_gen hand,
                                libxl_cpuid_policy_list *pl)
{
    libxl_cpuid_policy_list policy = *pl;
    struct xc_xend_cpuid *cpuid;
    const struct xc_msr *msr;
    yajl_gen_status s;
    int i, j;

    s = yajl_gen_map_open(hand);
    if (s != yajl_gen_status_ok) goto out;

    s = libxl__yajl_gen_asciiz(hand, "cpuid");
    if (s != yajl_gen_status_ok) goto out;

    s = yajl_gen_array_open(hand);
    if (s != yajl_gen_status_ok) goto out;

    if (policy == NULL || policy->cpuid == NULL) goto empty;
    cpuid = policy->cpuid;

    for (i = 0; cpuid[i].input[0] != XEN_CPUID_INPUT_UNUSED; i++) {
        s = yajl_gen_map_open(hand);
        if (s != yajl_gen_status_ok) goto out;

        for (j = 0; j < 2; j++) {
            if (cpuid[i].input[j] != XEN_CPUID_INPUT_UNUSED) {
                s = libxl__yajl_gen_asciiz(hand, input_names[j]);
                if (s != yajl_gen_status_ok) goto out;
                s = yajl_gen_integer(hand, cpuid[i].input[j]);
                if (s != yajl_gen_status_ok) goto out;
            }
        }

        for (j = 0; j < 4; j++) {
            if (cpuid[i].policy[j] != NULL) {
                s = libxl__yajl_gen_asciiz(hand, policy_names[j]);
                if (s != yajl_gen_status_ok) goto out;
                s = yajl_gen_string(hand,
                               (const unsigned char *)cpuid[i].policy[j], 32);
                if (s != yajl_gen_status_ok) goto out;
            }
        }
        s = yajl_gen_map_close(hand);
        if (s != yajl_gen_status_ok) goto out;
    }

empty:
    s = yajl_gen_array_close(hand);
    if (s != yajl_gen_status_ok) goto out;

    s = libxl__yajl_gen_asciiz(hand, "msr");
    if (s != yajl_gen_status_ok) goto out;

    s = yajl_gen_array_open(hand);
    if (s != yajl_gen_status_ok) goto out;

    if (!policy || !policy->msr) goto done;
    msr = policy->msr;

    for (i = 0; msr[i].index != XC_MSR_INPUT_UNUSED; i++) {
        s = yajl_gen_map_open(hand);
        if (s != yajl_gen_status_ok) goto out;

        s = libxl__yajl_gen_asciiz(hand, "index");
        if (s != yajl_gen_status_ok) goto out;
        s = yajl_gen_integer(hand, msr[i].index);
        if (s != yajl_gen_status_ok) goto out;
        s = libxl__yajl_gen_asciiz(hand, "policy");
        if (s != yajl_gen_status_ok) goto out;
        s = yajl_gen_string(hand,
                            (const unsigned char *)msr[i].policy, 64);
        if (s != yajl_gen_status_ok) goto out;

        s = yajl_gen_map_close(hand);
        if (s != yajl_gen_status_ok) goto out;
    }

done:
    s = yajl_gen_array_close(hand);
    if (s != yajl_gen_status_ok) goto out;
    s = yajl_gen_map_close(hand);
out:
    return s;
}
#endif

int libxl__cpuid_policy_list_parse_json(libxl__gc *gc,
                                        const libxl__json_object *o,
                                        libxl_cpuid_policy_list *p)
{
    int i, size;
    struct xc_xend_cpuid *l;
    struct xc_msr *msr;
    const libxl__json_object *co;
    flexarray_t *array;
    bool cpuid_only = false;

    /*
     * Old JSON field was an array with just the CPUID data.  With the addition
     * of MSRs the object is now a map with two array fields.
     *
     * Use the object format to detect whether the passed data contains just
     * CPUID leafs and thus is an array, or does also contain MSRs and is a
     * map.
     */
    if (libxl__json_object_is_array(o)) {
        co = o;
        cpuid_only = true;
        goto parse_cpuid;
    }

    if (!libxl__json_object_is_map(o))
        return ERROR_FAIL;

    co = libxl__json_map_get("cpuid", o, JSON_ARRAY);
    if (!libxl__json_object_is_array(co))
        return ERROR_FAIL;

parse_cpuid:
    *p = libxl__calloc(NOGC, 1, sizeof(**p));

    array = libxl__json_object_get_array(co);
    if (!array->count)
        goto cpuid_empty;

    size = array->count;
    /* need one extra slot as sentinel */
    l = (*p)->cpuid = libxl__calloc(NOGC, size + 1,
                                    sizeof(struct xc_xend_cpuid));

    l[size].input[0] = XEN_CPUID_INPUT_UNUSED;
    l[size].input[1] = XEN_CPUID_INPUT_UNUSED;

    for (i = 0; i < size; i++) {
        const libxl__json_object *t;
        int j;

        if (flexarray_get(array, i, (void**)&t) != 0)
            return ERROR_FAIL;

        if (!libxl__json_object_is_map(t))
            return ERROR_FAIL;

        for (j = 0; j < ARRAY_SIZE(l[0].input); j++) {
            const libxl__json_object *r;

            r = libxl__json_map_get(input_names[j], t, JSON_INTEGER);
            if (!r)
                l[i].input[j] = XEN_CPUID_INPUT_UNUSED;
            else
                l[i].input[j] = libxl__json_object_get_integer(r);
        }

        for (j = 0; j < ARRAY_SIZE(l[0].policy); j++) {
            const libxl__json_object *r;

            r = libxl__json_map_get(policy_names[j], t, JSON_STRING);
            if (!r)
                l[i].policy[j] = NULL;
            else
                l[i].policy[j] =
                    libxl__strdup(NOGC, libxl__json_object_get_string(r));
        }
    }

cpuid_empty:
    if (cpuid_only)
        return 0;

    co = libxl__json_map_get("msr", o, JSON_ARRAY);
    if (!libxl__json_object_is_array(co))
        return ERROR_FAIL;

    array = libxl__json_object_get_array(co);
    if (!array->count)
        return 0;
    size = array->count;
    /* need one extra slot as sentinel */
    msr = (*p)->msr = libxl__calloc(NOGC, size + 1, sizeof(struct xc_msr));

    msr[size].index = XC_MSR_INPUT_UNUSED;

    for (i = 0; i < size; i++) {
        const libxl__json_object *t, *r;

        if (flexarray_get(array, i, (void**)&t) != 0)
            return ERROR_FAIL;

        if (!libxl__json_object_is_map(t))
            return ERROR_FAIL;

        r = libxl__json_map_get("index", t, JSON_INTEGER);
        if (!r) return ERROR_FAIL;
        msr[i].index = libxl__json_object_get_integer(r);
        r = libxl__json_map_get("policy", t, JSON_STRING);
        if (!r) return ERROR_FAIL;
        if (strlen(libxl__json_object_get_string(r)) !=
            ARRAY_SIZE(msr[i].policy) - 1)
            return ERROR_FAIL;
        strcpy(msr[i].policy, libxl__json_object_get_string(r));
    }

    return 0;
}

int libxl_cpuid_policy_list_length(const libxl_cpuid_policy_list *pl)
{
    int i = 0;
    const struct xc_xend_cpuid *l;

    if (*pl == NULL)
        return 0;

    l = (*pl)->cpuid;
    if (l) {
        while (l[i].input[0] != XEN_CPUID_INPUT_UNUSED)
            i++;
    }

    return i;
}

void libxl_cpuid_policy_list_copy(libxl_ctx *ctx,
                                  libxl_cpuid_policy_list *pdst,
                                  const libxl_cpuid_policy_list *psrc)
{
    struct xc_xend_cpuid **dst;
    struct xc_xend_cpuid *const *src;
    GC_INIT(ctx);
    int i, j, len;

    if (*psrc == NULL) {
        *pdst = NULL;
        goto out;
    }

    *pdst = libxl__calloc(NOGC, 1, sizeof(**pdst));

    if (!(*psrc)->cpuid)
        goto copy_msr;

    dst = &(*pdst)->cpuid;
    src = &(*psrc)->cpuid;
    len = libxl_cpuid_policy_list_length(psrc);
    /* one extra slot for sentinel */
    *dst = libxl__calloc(NOGC, len + 1, sizeof(struct xc_xend_cpuid));
    (*dst)[len].input[0] = XEN_CPUID_INPUT_UNUSED;
    (*dst)[len].input[1] = XEN_CPUID_INPUT_UNUSED;

    for (i = 0; i < len; i++) {
        for (j = 0; j < 2; j++)
            (*dst)[i].input[j] = (*src)[i].input[j];
        for (j = 0; j < 4; j++)
            if ((*src)[i].policy[j])
                (*dst)[i].policy[j] =
                    libxl__strdup(NOGC, (*src)[i].policy[j]);
            else
                (*dst)[i].policy[j] = NULL;
    }

copy_msr:
    if ((*psrc)->msr) {
        const struct xc_msr *msr = (*psrc)->msr;

        for (i = 0; msr[i].index != XC_MSR_INPUT_UNUSED; i++)
            ;
        len = i;
        (*pdst)->msr = libxl__calloc(NOGC, len + 1, sizeof(struct xc_msr));
        (*pdst)->msr[len].index = XC_MSR_INPUT_UNUSED;

        for (i = 0; i < len; i++) {
            (*pdst)->msr[i].index = msr[i].index;
            strcpy((*pdst)->msr[i].policy, msr[i].policy);
        }
    }

out:
    GC_FREE;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
