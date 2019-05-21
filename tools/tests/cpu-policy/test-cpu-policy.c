#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <xen-tools/libs.h>
#include <xen/asm/x86-vendors.h>
#include <xen/lib/x86/cpuid.h>
#include <xen/lib/x86/msr.h>
#include <xen/domctl.h>

static unsigned int nr_failures;
#define fail(fmt, ...)                          \
({                                              \
    nr_failures++;                              \
    printf(fmt, ##__VA_ARGS__);                 \
})

static void test_vendor_identification(void)
{
    static const struct test {
        union {
            char ident[12];
            struct {
                uint32_t b, d, c;
            };
        };
        unsigned int vendor;
    } tests[] = {
        { { "GenuineIntel" }, X86_VENDOR_INTEL },
        { { "AuthenticAMD" }, X86_VENDOR_AMD },
        { { "CentaurHauls" }, X86_VENDOR_CENTAUR },
        { { "  Shanghai  " }, X86_VENDOR_SHANGHAI },

        { { ""             }, X86_VENDOR_UNKNOWN },
        { { "            " }, X86_VENDOR_UNKNOWN },
        { { "xxxxxxxxxxxx" }, X86_VENDOR_UNKNOWN },
    };

    printf("Testing CPU vendor identification:\n");

    for ( size_t i = 0; i < ARRAY_SIZE(tests); ++i )
    {
        const struct test *t = &tests[i];
        unsigned int vendor = x86_cpuid_lookup_vendor(t->b, t->c, t->d);

        if ( vendor != t->vendor )
            fail("  Test '%.12s', expected vendor %u, got %u\n",
                 t->ident, t->vendor, vendor);
    }
}

static void test_cpuid_serialise_success(void)
{
    static const struct test {
        struct cpuid_policy p;
        const char *name;
        unsigned int nr_leaves;
    } tests[] = {
        {
            .name = "empty policy",
            .nr_leaves = 4,
        },

        /* Leaf 4 serialisation stops at the first subleaf with type 0. */
        {
            .name = "empty leaf 4",
            .p = {
                .basic.max_leaf = 4,
            },
            .nr_leaves = 4 + 4,
        },
        {
            .name = "partial leaf 4",
            .p = {
                .basic.max_leaf = 4,
                .cache.subleaf[0].type = 1,
            },
            .nr_leaves = 4 + 4 + 1,
        },

        /* Leaf 7 serialisation stops at max_subleaf. */
        {
            .name = "empty leaf 7",
            .p = {
                .basic.max_leaf = 7,
            },
            .nr_leaves = 4 + 7,
        },
        {
            .name = "partial leaf 7",
            .p = {
                .basic.max_leaf = 7,
                .feat.max_subleaf = 1,
            },
            .nr_leaves = 4 + 7 + 1,
        },

        /* Leaf 0xb serialisation stops at the first subleaf with type 0. */
        {
            .name = "empty leaf 0xb",
            .p = {
                .basic.max_leaf = 0xb,
            },
            .nr_leaves = 4 + 0xb,
        },
        {
            .name = "partial leaf 0xb",
            .p = {
                .basic.max_leaf = 0xb,
                .topo.subleaf[0].type = 1,
            },
            .nr_leaves = 4 + 0xb + 1,
        },

        /*
         * Leaf 0xd serialisation automatically has two leaves, and stops the
         * highest bit set in {xcr0,xss}_{high,low}.
         */
        {
            .name = "empty leaf 0xd",
            .p = {
                .basic.max_leaf = 0xd,
            },
            .nr_leaves = 4 + 0xd + 1,
        },
        {
            .name = "partial 0xd",
            .p = {
                .basic.max_leaf = 0xd,
                .xstate.xcr0_low = 7,
            },
            .nr_leaves = 4 + 0xd + 1 + 1,
        },
    };

    printf("Testing CPUID serialise success:\n");

    for ( size_t i = 0; i < ARRAY_SIZE(tests); ++i )
    {
        const struct test *t = &tests[i];
        unsigned int nr = t->nr_leaves;
        xen_cpuid_leaf_t *leaves = malloc(nr * sizeof(*leaves));
        int rc;

        if ( !leaves )
            err(1, "%s() malloc failure", __func__);

        rc = x86_cpuid_copy_to_buffer(&t->p, leaves, &nr);

        if ( rc != 0 )
        {
            fail("  Test %s, expected rc 0, got %d\n",
                 t->name, rc);
            goto test_done;
        }

        if ( nr != t->nr_leaves )
        {
            fail("  Test %s, expected %u leaves, got %u\n",
                 t->name, t->nr_leaves, nr);
            goto test_done;
        }

    test_done:
        free(leaves);
    }
}

static void test_msr_serialise_success(void)
{
    static const struct test {
        struct msr_policy p;
        const char *name;
        unsigned int nr_msrs;
    } tests[] = {
        {
            .name = "empty policy",
            .nr_msrs = MSR_MAX_SERIALISED_ENTRIES,
        },
    };

    printf("Testing MSR serialise success:\n");

    for ( size_t i = 0; i < ARRAY_SIZE(tests); ++i )
    {
        const struct test *t = &tests[i];
        unsigned int nr = t->nr_msrs;
        xen_msr_entry_t *msrs = malloc(nr * sizeof(*msrs));
        int rc;

        if ( !msrs )
            err(1, "%s() malloc failure", __func__);

        rc = x86_msr_copy_to_buffer(&t->p, msrs, &nr);

        if ( rc != 0 )
        {
            fail("  Test %s, expected rc 0, got %d\n",
                 t->name, rc);
            goto test_done;
        }

        if ( nr != t->nr_msrs )
        {
            fail("  Test %s, expected %u msrs, got %u\n",
                 t->name, t->nr_msrs, nr);
            goto test_done;
        }

    test_done:
        free(msrs);
    }
}

static void test_cpuid_deserialise_failure(void)
{
    static const struct test {
        const char *name;
        xen_cpuid_leaf_t leaf;
    } tests[] = {
        {
            .name = "incorrect basic subleaf",
            .leaf = { .leaf = 0, .subleaf = 0 },
        },
        {
            .name = "incorrect hv1 subleaf",
            .leaf = { .leaf = 0x40000000, .subleaf = 0 },
        },
        {
            .name = "incorrect hv2 subleaf",
            .leaf = { .leaf = 0x40000100, .subleaf = 0 },
        },
        {
            .name = "incorrect extd subleaf",
            .leaf = { .leaf = 0x80000000, .subleaf = 0 },
        },
        {
            .name = "OoB basic leaf",
            .leaf = { .leaf = CPUID_GUEST_NR_BASIC },
        },
        {
            .name = "OoB cache leaf",
            .leaf = { .leaf = 0x4, .subleaf = CPUID_GUEST_NR_CACHE },
        },
        {
            .name = "OoB feat leaf",
            .leaf = { .leaf = 0x7, .subleaf = CPUID_GUEST_NR_FEAT },
        },
        {
            .name = "OoB topo leaf",
            .leaf = { .leaf = 0xb, .subleaf = CPUID_GUEST_NR_TOPO },
        },
        {
            .name = "OoB xstate leaf",
            .leaf = { .leaf = 0xd, .subleaf = CPUID_GUEST_NR_XSTATE },
        },
        {
            .name = "OoB extd leaf",
            .leaf = { .leaf = 0x80000000 | CPUID_GUEST_NR_EXTD },
        },
    };

    printf("Testing CPUID deserialise failure:\n");

    for ( size_t i = 0; i < ARRAY_SIZE(tests); ++i )
    {
        const struct test *t = &tests[i];
        uint32_t err_leaf = ~0u, err_subleaf = ~0u;
        int rc;

        /* No writes should occur.  Use NULL to catch errors. */
        rc = x86_cpuid_copy_from_buffer(NULL, &t->leaf, 1,
                                        &err_leaf, &err_subleaf);

        if ( rc != -ERANGE )
        {
            fail("  Test %s, expected rc %d, got %d\n",
                 t->name, -ERANGE, rc);
            continue;
        }

        if ( err_leaf != t->leaf.leaf || err_subleaf != t->leaf.subleaf )
        {
            fail("  Test %s, expected err %08x:%08x, got %08x:%08x\n",
                 t->name, t->leaf.leaf, t->leaf.subleaf,
                 err_leaf, err_subleaf);
            continue;
        }
    }
}

static void test_msr_deserialise_failure(void)
{
    static const struct test {
        const char *name;
        xen_msr_entry_t msr;
        int rc;
    } tests[] = {
        {
            .name = "bad msr index",
            .msr = { .idx = 0xdeadc0de },
            .rc = -ERANGE,
        },
        {
            .name = "nonzero flags",
            .msr = { .idx = 0xce, .flags = 1 },
            .rc = -EINVAL,
        },
        {
            .name = "truncated val",
            .msr = { .idx = 0xce, .val = ~0ull },
            .rc = -EOVERFLOW,
        },
    };

    printf("Testing MSR deserialise failure:\n");

    for ( size_t i = 0; i < ARRAY_SIZE(tests); ++i )
    {
        const struct test *t = &tests[i];
        uint32_t err_msr = ~0u;
        int rc;

        /* No writes should occur.  Use NULL to catch errors. */
        rc = x86_msr_copy_from_buffer(NULL, &t->msr, 1, &err_msr);

        if ( rc != t->rc )
        {
            fail("  Test %s, expected rc %d, got %d\n",
                 t->name, t->rc, rc);
            continue;
        }

        if ( err_msr != t->msr.idx )
        {
            fail("  Test %s, expected err_msr %#x, got %#x\n",
                 t->name, t->msr.idx, err_msr);
            continue;
        }
    }
}

int main(int argc, char **argv)
{
    printf("CPU Policy unit tests\n");

    test_vendor_identification();

    test_cpuid_serialise_success();
    test_msr_serialise_success();

    test_cpuid_deserialise_failure();
    test_msr_deserialise_failure();

    if ( nr_failures )
        printf("Done: %u failures\n", nr_failures);
    else
        printf("Done: all ok\n");

    return !!nr_failures;
}
