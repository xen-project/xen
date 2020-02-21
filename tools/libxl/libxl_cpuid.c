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

int libxl__cpuid_policy_is_empty(libxl_cpuid_policy_list *pl)
{
    return !libxl_cpuid_policy_list_length(pl);
}

void libxl_cpuid_dispose(libxl_cpuid_policy_list *p_cpuid_list)
{
    int i, j;
    libxl_cpuid_policy_list cpuid_list = *p_cpuid_list;

    if (cpuid_list == NULL)
        return;
    for (i = 0; cpuid_list[i].input[0] != XEN_CPUID_INPUT_UNUSED; i++) {
        for (j = 0; j < 4; j++)
            if (cpuid_list[i].policy[j] != NULL) {
                free(cpuid_list[i].policy[j]);
                cpuid_list[i].policy[j] = NULL;
            }
    }
    free(cpuid_list);
    *p_cpuid_list = NULL;
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
    char* name;
    uint32_t leaf;
    uint32_t subleaf;
    int reg;
    int bit;
    int length;
};

/* go through the dynamic array finding the entry for a specified leaf.
 * if no entry exists, allocate one and return that.
 */
static libxl_cpuid_policy_list cpuid_find_match(libxl_cpuid_policy_list *list,
                                          uint32_t leaf, uint32_t subleaf)
{
    int i = 0;

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

/* parse a single key=value pair and translate it into the libxc
 * used interface using 32-characters strings for each register.
 * Will overwrite earlier entries and thus can be called multiple
 * times.
 */
int libxl_cpuid_parse_config(libxl_cpuid_policy_list *cpuid, const char* str)
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

        {"sse3",         0x00000001, NA, CPUID_REG_ECX,  0,  1},
        {"pclmulqdq",    0x00000001, NA, CPUID_REG_ECX,  1,  1},
        {"dtes64",       0x00000001, NA, CPUID_REG_ECX,  2,  1},
        {"monitor",      0x00000001, NA, CPUID_REG_ECX,  3,  1},
        {"dscpl",        0x00000001, NA, CPUID_REG_ECX,  4,  1},
        {"vmx",          0x00000001, NA, CPUID_REG_ECX,  5,  1},
        {"smx",          0x00000001, NA, CPUID_REG_ECX,  6,  1},
        {"est",          0x00000001, NA, CPUID_REG_ECX,  7,  1},
        {"tm2",          0x00000001, NA, CPUID_REG_ECX,  8,  1},
        {"ssse3",        0x00000001, NA, CPUID_REG_ECX,  9,  1},
        {"cntxid",       0x00000001, NA, CPUID_REG_ECX, 10,  1},
        {"fma",          0x00000001, NA, CPUID_REG_ECX, 12,  1},
        {"cmpxchg16",    0x00000001, NA, CPUID_REG_ECX, 13,  1},
        {"xtpr",         0x00000001, NA, CPUID_REG_ECX, 14,  1},
        {"pdcm",         0x00000001, NA, CPUID_REG_ECX, 15,  1},
        {"pcid",         0x00000001, NA, CPUID_REG_ECX, 17,  1},
        {"dca",          0x00000001, NA, CPUID_REG_ECX, 18,  1},
        /* Linux uses sse4_{1,2}.  Keep sse4.{1,2} for compatibility */
        {"sse4_1",       0x00000001, NA, CPUID_REG_ECX, 19,  1},
        {"sse4.1",       0x00000001, NA, CPUID_REG_ECX, 19,  1},
        {"sse4_2",       0x00000001, NA, CPUID_REG_ECX, 20,  1},
        {"sse4.2",       0x00000001, NA, CPUID_REG_ECX, 20,  1},
        {"x2apic",       0x00000001, NA, CPUID_REG_ECX, 21,  1},
        {"movbe",        0x00000001, NA, CPUID_REG_ECX, 22,  1},
        {"popcnt",       0x00000001, NA, CPUID_REG_ECX, 23,  1},
        {"tsc-deadline", 0x00000001, NA, CPUID_REG_ECX, 24,  1},
        {"aes",          0x00000001, NA, CPUID_REG_ECX, 25,  1},
        {"xsave",        0x00000001, NA, CPUID_REG_ECX, 26,  1},
        {"osxsave",      0x00000001, NA, CPUID_REG_ECX, 27,  1},
        {"avx",          0x00000001, NA, CPUID_REG_ECX, 28,  1},
        {"f16c",         0x00000001, NA, CPUID_REG_ECX, 29,  1},
        {"rdrand",       0x00000001, NA, CPUID_REG_ECX, 30,  1},
        {"hypervisor",   0x00000001, NA, CPUID_REG_ECX, 31,  1},

        {"fpu",          0x00000001, NA, CPUID_REG_EDX,  0,  1},
        {"vme",          0x00000001, NA, CPUID_REG_EDX,  1,  1},
        {"de",           0x00000001, NA, CPUID_REG_EDX,  2,  1},
        {"pse",          0x00000001, NA, CPUID_REG_EDX,  3,  1},
        {"tsc",          0x00000001, NA, CPUID_REG_EDX,  4,  1},
        {"msr",          0x00000001, NA, CPUID_REG_EDX,  5,  1},
        {"pae",          0x00000001, NA, CPUID_REG_EDX,  6,  1},
        {"mce",          0x00000001, NA, CPUID_REG_EDX,  7,  1},
        {"cmpxchg8",     0x00000001, NA, CPUID_REG_EDX,  8,  1},
        {"apic",         0x00000001, NA, CPUID_REG_EDX,  9,  1},
        {"sysenter",     0x00000001, NA, CPUID_REG_EDX, 11,  1},
        {"mtrr",         0x00000001, NA, CPUID_REG_EDX, 12,  1},
        {"pge",          0x00000001, NA, CPUID_REG_EDX, 13,  1},
        {"mca",          0x00000001, NA, CPUID_REG_EDX, 14,  1},
        {"cmov",         0x00000001, NA, CPUID_REG_EDX, 15,  1},
        {"pat",          0x00000001, NA, CPUID_REG_EDX, 16,  1},
        {"pse36",        0x00000001, NA, CPUID_REG_EDX, 17,  1},
        {"psn",          0x00000001, NA, CPUID_REG_EDX, 18,  1},
        {"clfsh",        0x00000001, NA, CPUID_REG_EDX, 19,  1},
        {"ds",           0x00000001, NA, CPUID_REG_EDX, 21,  1},
        {"acpi",         0x00000001, NA, CPUID_REG_EDX, 22,  1},
        {"mmx",          0x00000001, NA, CPUID_REG_EDX, 23,  1},
        {"fxsr",         0x00000001, NA, CPUID_REG_EDX, 24,  1},
        {"sse",          0x00000001, NA, CPUID_REG_EDX, 25,  1},
        {"sse2",         0x00000001, NA, CPUID_REG_EDX, 26,  1},
        {"ss",           0x00000001, NA, CPUID_REG_EDX, 27,  1},
        {"htt",          0x00000001, NA, CPUID_REG_EDX, 28,  1},
        {"tm",           0x00000001, NA, CPUID_REG_EDX, 29,  1},
        {"ia64",         0x00000001, NA, CPUID_REG_EDX, 30,  1},
        {"pbe",          0x00000001, NA, CPUID_REG_EDX, 31,  1},

        {"arat",         0x00000006, NA, CPUID_REG_EAX,  2,  1},

        {"fsgsbase",     0x00000007,  0, CPUID_REG_EBX,  0,  1},
        {"tsc_adjust",   0x00000007,  0, CPUID_REG_EBX,  1,  1},
        {"bmi1",         0x00000007,  0, CPUID_REG_EBX,  3,  1},
        {"hle",          0x00000007,  0, CPUID_REG_EBX,  4,  1},
        {"avx2",         0x00000007,  0, CPUID_REG_EBX,  5,  1},
        {"smep",         0x00000007,  0, CPUID_REG_EBX,  7,  1},
        {"bmi2",         0x00000007,  0, CPUID_REG_EBX,  8,  1},
        {"erms",         0x00000007,  0, CPUID_REG_EBX,  9,  1},
        {"invpcid",      0x00000007,  0, CPUID_REG_EBX, 10,  1},
        {"rtm",          0x00000007,  0, CPUID_REG_EBX, 11,  1},
        {"cmt",          0x00000007,  0, CPUID_REG_EBX, 12,  1},
        {"mpx",          0x00000007,  0, CPUID_REG_EBX, 14,  1},
        {"avx512f",      0x00000007,  0, CPUID_REG_EBX, 16,  1},
        {"avx512dq",     0x00000007,  0, CPUID_REG_EBX, 17,  1},
        {"rdseed",       0x00000007,  0, CPUID_REG_EBX, 18,  1},
        {"adx",          0x00000007,  0, CPUID_REG_EBX, 19,  1},
        {"smap",         0x00000007,  0, CPUID_REG_EBX, 20,  1},
        {"avx512-ifma",  0x00000007,  0, CPUID_REG_EBX, 21,  1},
        {"clflushopt",   0x00000007,  0, CPUID_REG_EBX, 23,  1},
        {"clwb",         0x00000007,  0, CPUID_REG_EBX, 24,  1},
        {"avx512pf",     0x00000007,  0, CPUID_REG_EBX, 26,  1},
        {"avx512er",     0x00000007,  0, CPUID_REG_EBX, 27,  1},
        {"avx512cd",     0x00000007,  0, CPUID_REG_EBX, 28,  1},
        {"sha",          0x00000007,  0, CPUID_REG_EBX, 29,  1},
        {"avx512bw",     0x00000007,  0, CPUID_REG_EBX, 30,  1},
        {"avx512vl",     0x00000007,  0, CPUID_REG_EBX, 31,  1},

        {"prefetchwt1",  0x00000007,  0, CPUID_REG_ECX,  0,  1},
        {"avx512-vbmi",  0x00000007,  0, CPUID_REG_ECX,  1,  1},
        {"umip",         0x00000007,  0, CPUID_REG_ECX,  2,  1},
        {"pku",          0x00000007,  0, CPUID_REG_ECX,  3,  1},
        {"ospke",        0x00000007,  0, CPUID_REG_ECX,  4,  1},
        {"avx512-vbmi2", 0x00000007,  0, CPUID_REG_ECX,  6,  1},
        {"cet-ss",       0x00000007,  0, CPUID_REG_ECX,  7,  1},
        {"gfni",         0x00000007,  0, CPUID_REG_ECX,  8,  1},
        {"vaes",         0x00000007,  0, CPUID_REG_ECX,  9,  1},
        {"vpclmulqdq",   0x00000007,  0, CPUID_REG_ECX, 10,  1},
        {"avx512-vnni",  0x00000007,  0, CPUID_REG_ECX, 11,  1},
        {"avx512-bitalg",0x00000007,  0, CPUID_REG_ECX, 12,  1},
        {"avx512-vpopcntdq",0x00000007,0,CPUID_REG_ECX, 14,  1},
        {"rdpid",        0x00000007,  0, CPUID_REG_ECX, 22,  1},
        {"cldemote",     0x00000007,  0, CPUID_REG_ECX, 25,  1},

        {"avx512-4vnniw",0x00000007,  0, CPUID_REG_EDX,  2,  1},
        {"avx512-4fmaps",0x00000007,  0, CPUID_REG_EDX,  3,  1},
        {"md-clear",     0x00000007,  0, CPUID_REG_EDX, 10,  1},
        {"cet-ibt",      0x00000007,  0, CPUID_REG_EDX, 20,  1},
        {"ibrsb",        0x00000007,  0, CPUID_REG_EDX, 26,  1},
        {"stibp",        0x00000007,  0, CPUID_REG_EDX, 27,  1},
        {"l1d-flush",    0x00000007,  0, CPUID_REG_EDX, 28,  1},
        {"arch-caps",    0x00000007,  0, CPUID_REG_EDX, 29,  1},
        {"core-caps",    0x00000007,  0, CPUID_REG_EDX, 30,  1},
        {"ssbd",         0x00000007,  0, CPUID_REG_EDX, 31,  1},

        {"avx512-bf16",  0x00000007,  1, CPUID_REG_EAX,  5,  1},

        {"lahfsahf",     0x80000001, NA, CPUID_REG_ECX,  0,  1},
        {"cmplegacy",    0x80000001, NA, CPUID_REG_ECX,  1,  1},
        {"svm",          0x80000001, NA, CPUID_REG_ECX,  2,  1},
        {"extapic",      0x80000001, NA, CPUID_REG_ECX,  3,  1},
        {"altmovcr8",    0x80000001, NA, CPUID_REG_ECX,  4,  1},
        {"abm",          0x80000001, NA, CPUID_REG_ECX,  5,  1},
        {"sse4a",        0x80000001, NA, CPUID_REG_ECX,  6,  1},
        {"misalignsse",  0x80000001, NA, CPUID_REG_ECX,  7,  1},
        {"3dnowprefetch",0x80000001, NA, CPUID_REG_ECX,  8,  1},
        {"osvw",         0x80000001, NA, CPUID_REG_ECX,  9,  1},
        {"ibs",          0x80000001, NA, CPUID_REG_ECX, 10,  1},
        {"xop",          0x80000001, NA, CPUID_REG_ECX, 11,  1},
        {"skinit",       0x80000001, NA, CPUID_REG_ECX, 12,  1},
        {"wdt",          0x80000001, NA, CPUID_REG_ECX, 13,  1},
        {"lwp",          0x80000001, NA, CPUID_REG_ECX, 15,  1},
        {"fma4",         0x80000001, NA, CPUID_REG_ECX, 16,  1},
        {"nodeid",       0x80000001, NA, CPUID_REG_ECX, 19,  1},
        {"tbm",          0x80000001, NA, CPUID_REG_ECX, 21,  1},
        {"topoext",      0x80000001, NA, CPUID_REG_ECX, 22,  1},
        {"perfctr_core", 0x80000001, NA, CPUID_REG_ECX, 23,  1},
        {"perfctr_nb",   0x80000001, NA, CPUID_REG_ECX, 24,  1},

        {"syscall",      0x80000001, NA, CPUID_REG_EDX, 11,  1},
        {"nx",           0x80000001, NA, CPUID_REG_EDX, 20,  1},
        {"mmxext",       0x80000001, NA, CPUID_REG_EDX, 22,  1},
        {"ffxsr",        0x80000001, NA, CPUID_REG_EDX, 25,  1},
        {"page1gb",      0x80000001, NA, CPUID_REG_EDX, 26,  1},
        {"rdtscp",       0x80000001, NA, CPUID_REG_EDX, 27,  1},
        {"lm",           0x80000001, NA, CPUID_REG_EDX, 29,  1},
        {"3dnowext",     0x80000001, NA, CPUID_REG_EDX, 30,  1},
        {"3dnow",        0x80000001, NA, CPUID_REG_EDX, 31,  1},

        {"procpkg",      0x00000004,  0, CPUID_REG_EAX, 26,  6},

        {"invtsc",       0x80000007, NA, CPUID_REG_EDX,  8,  1},

        {"clzero",       0x80000008, NA, CPUID_REG_EBX,  0,  1},
        {"rstr-fp-err-ptrs", 0x80000008, NA, CPUID_REG_EBX, 2, 1},
        {"wbnoinvd",     0x80000008, NA, CPUID_REG_EBX,  9,  1},
        {"ibpb",         0x80000008, NA, CPUID_REG_EBX, 12,  1},
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

        {"maxhvleaf",    0x40000000, NA, CPUID_REG_EAX,  0,  8},

        {NULL, 0, NA, CPUID_REG_INV, 0, 0}
    };
#undef NA
    char *sep, *val, *endptr;
    int i;
    const struct cpuid_flags *flag;
    struct libxl__cpuid_policy *entry;
    unsigned long num;
    char flags[33], *resstr;

    sep = strchr(str, '=');
    if (sep == NULL) {
        return 1;
    } else {
        val = sep + 1;
    }
    for (flag = cpuid_flags; flag->name != NULL; flag++) {
        if(!strncmp(str, flag->name, sep - str) && flag->name[sep - str] == 0)
            break;
    }
    if (flag->name == NULL) {
        return 2;
    }
    entry = cpuid_find_match(cpuid, flag->leaf, flag->subleaf);
    resstr = entry->policy[flag->reg - 1];
    num = strtoull(val, &endptr, 0);
    flags[flag->length] = 0;
    if (endptr != val) {
        /* if this was a valid number, write the binary form into the string */
        for (i = 0; i < flag->length; i++) {
            flags[flag->length - 1 - i] = "01"[!!(num & (1 << i))];
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
    if (!strncmp(str, "family", sep - str)) {
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
    } else if (!strncmp(str, "model", sep - str)) {
        memcpy(resstr + (32 - 4) - 16, flags, 4);
        memcpy(resstr + (32 - 4) - flag->bit, flags + 4, 4);
    } else {
        memcpy(resstr + (32 - flag->length) - flag->bit, flags,
               flag->length);
    }
    entry->policy[flag->reg - 1] = resstr;

    return 0;
}

/* parse a single list item from the legacy Python xend syntax, where
 * the strings for each register were directly exposed to the user.
 * Used for maintaining compatibility with older config files
 */
int libxl_cpuid_parse_config_xend(libxl_cpuid_policy_list *cpuid,
                                  const char* str)
{
    char *endptr;
    unsigned long value;
    uint32_t leaf, subleaf = XEN_CPUID_INPUT_UNUSED;
    struct libxl__cpuid_policy *entry;

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
    entry = cpuid_find_match(cpuid, leaf, subleaf);
    for (str = endptr + 1; *str != 0;) {
        if (str[0] != 'e' || str[2] != 'x') {
            return 4;
        }
        value = str[1] - 'a';
        endptr = strchr(str, '=');
        if (value > 3 || endptr == NULL) {
            return 4;
        }
        str = endptr + 1;
        endptr = strchr(str, ',');
        if (endptr == NULL) {
            endptr = strchr(str, 0);
        }
        if (endptr - str != 32) {
            return 5;
        }
        entry->policy[value] = calloc(32 + 1, 1);
        strncpy(entry->policy[value], str, 32);
        entry->policy[value][32] = 0;
        if (*endptr == 0) {
            break;
        }
        for (str = endptr + 1; *str == ' ' || *str == '\n'; str++);
    }
    return 0;
}

void libxl__cpuid_legacy(libxl_ctx *ctx, uint32_t domid,
                         libxl_domain_build_info *info)
{
    libxl_cpuid_policy_list cpuid = info->cpuid;
    int i;
    char *cpuid_res[4];
    bool pae = true;

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

    xc_cpuid_apply_policy(ctx->xch, domid, NULL, 0, pae);

    if (!cpuid)
        return;

    for (i = 0; cpuid[i].input[0] != XEN_CPUID_INPUT_UNUSED; i++)
        xc_cpuid_set(ctx->xch, domid, cpuid[i].input,
                     (const char**)(cpuid[i].policy), cpuid_res);
}

static const char *input_names[2] = { "leaf", "subleaf" };
static const char *policy_names[4] = { "eax", "ebx", "ecx", "edx" };
/*
 * Aiming for:
 * [
 *     { 'leaf':    'val-eax',
 *       'subleaf': 'val-ecx',
 *       'eax':     'filter',
 *       'ebx':     'filter',
 *       'ecx':     'filter',
 *       'edx':     'filter' },
 *     { 'leaf':    'val-eax', ..., 'eax': 'filter', ... },
 *     ... etc ...
 * ]
 */

yajl_gen_status libxl_cpuid_policy_list_gen_json(yajl_gen hand,
                                libxl_cpuid_policy_list *pcpuid)
{
    libxl_cpuid_policy_list cpuid = *pcpuid;
    yajl_gen_status s;
    int i, j;

    s = yajl_gen_array_open(hand);
    if (s != yajl_gen_status_ok) goto out;

    if (cpuid == NULL) goto empty;

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
out:
    return s;
}

int libxl__cpuid_policy_list_parse_json(libxl__gc *gc,
                                        const libxl__json_object *o,
                                        libxl_cpuid_policy_list *p)
{
    int i, size;
    libxl_cpuid_policy_list l;
    flexarray_t *array;

    if (!libxl__json_object_is_array(o))
        return ERROR_FAIL;

    array = libxl__json_object_get_array(o);
    if (!array->count)
        return 0;

    size = array->count;
    /* need one extra slot as sentinel */
    l = *p = libxl__calloc(NOGC, size + 1, sizeof(libxl_cpuid_policy));

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

    return 0;
}

int libxl_cpuid_policy_list_length(const libxl_cpuid_policy_list *pl)
{
    int i = 0;
    libxl_cpuid_policy_list l = *pl;

    if (l) {
        while (l[i].input[0] != XEN_CPUID_INPUT_UNUSED)
            i++;
    }

    return i;
}

void libxl_cpuid_policy_list_copy(libxl_ctx *ctx,
                                  libxl_cpuid_policy_list *dst,
                                  const libxl_cpuid_policy_list *src)
{
    GC_INIT(ctx);
    int i, j, len;

    if (*src == NULL) {
        *dst = NULL;
        goto out;
    }

    len = libxl_cpuid_policy_list_length(src);
    /* one extra slot for sentinel */
    *dst = libxl__calloc(NOGC, len + 1, sizeof(libxl_cpuid_policy));
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
