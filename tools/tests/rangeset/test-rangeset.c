/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for rangesets.
 *
 * Copyright (C) 2025 Cloud Software Group
 */

#include "harness.h"

struct range {
    unsigned long start, end;
};

struct action {
    enum {
        ADD,
        REMOVE,
    } action;
    struct range r;
};

#define DECLARE_ACTIONS(nr) static const struct action actions ## nr []
#define DECLARE_RESULTS(nr) static const struct range results ## nr []

/*
 * Subtract range with tail overlap on existing range:
 *
 * { 0, 1, 4, 5 } - { 3, 4 } = { 0, 1, 5, 5 }
 */
DECLARE_ACTIONS(0) = {
    { ADD,    { 0, 1 } },
    { ADD,    { 4, 5 } },
    { REMOVE, { 3, 4 } },
};
DECLARE_RESULTS(0) = {
    { 0, 1 }, { 5, 5 },
};

/*
 * Subtract range with complete and tail overlap on existing ranges:
 *
 * { 0, 1, 4, 5, 7, 8 } - { 3, 4, 5, 6, 7 } = { 0, 1, 8 }
 */
DECLARE_ACTIONS(1) = {
    { ADD,    { 0, 1 } },
    { ADD,    { 4, 5 } },
    { ADD,    { 7, 8 } },
    { REMOVE, { 3, 7 } },
};
DECLARE_RESULTS(1) = {
    { 0, 1 }, { 8, 8 },
};

/*
 * Subtract range with no overlap:
 *
 * { 0, 1, 4, 5 } - { 2, 3 } = { 0, 1, 4, 5 }
 */
DECLARE_ACTIONS(2) = {
    { ADD,    { 0, 1 } },
    { ADD,    { 4, 5 } },
    { REMOVE, { 2, 3 } },
};
DECLARE_RESULTS(2) = {
    { 0, 1 }, { 4, 5 },
};

/*
 * Subtract range with partial overlap on two existing ranges:
 *
 * { 0, 1, 4, 5 } - { 1, 4 } = { 0, 5 }
 */
DECLARE_ACTIONS(3) = {
    { ADD,    { 0, 1 } },
    { ADD,    { 4, 5 } },
    { REMOVE, { 1, 4 } },
};
DECLARE_RESULTS(3) = {
    { 0, 0 }, { 5, 5 },
};

static const struct test {
    unsigned int nr_actions, nr_results;
    const struct action *actions;
    const struct range *result;
} tests[] = {
#define DECLARE_TEST(nr)                                \
    {                                                   \
        .actions = actions ## nr,                       \
        .nr_actions = ARRAY_SIZE(actions ## nr),        \
        .result  = results ## nr,                       \
        .nr_results = ARRAY_SIZE(results ## nr),        \
    }

    DECLARE_TEST(0),
    DECLARE_TEST(1),
    DECLARE_TEST(2),
    DECLARE_TEST(3),

#undef DECLARE_TEST
};

static int print_range(unsigned long s, unsigned long e, void *data)
{
    printf("[%ld, %ld]\n", s, e);

    return 0;
}

static int count_ranges(unsigned long s, unsigned long e, void *data)
{
    unsigned int *nr = data;

    ++*nr;
    return 0;
}

static const struct range *expected;
static int check_ranges(unsigned long s, unsigned long e, void *data)
{
    unsigned int *nr = data;
    int rc = 0;

    if ( s != expected[*nr].start || e != expected[*nr].end )
        rc = -EINVAL;

    ++*nr;
    return rc;
}

static void print_both(struct rangeset *r, const struct range *expected,
                       unsigned int nr_expected)
{
    unsigned int i;

    printf("Result:\n");
    rangeset_report_ranges(r, 0, ~0UL, print_range, NULL);
    printf("Expected:\n");
    for ( i = 0; i < nr_expected; i++ )
        printf("[%ld, %ld]\n", expected[i].start, expected[i].end);
}

int main(int argc, char **argv)
{
    struct rangeset *r = rangeset_new(NULL, NULL, 0);
    unsigned int i;
    int ret_code = 0;

    ASSERT(r);

    for ( i = 0 ; i < ARRAY_SIZE(tests); i++ )
    {
        unsigned int j, nr = 0;
        int rc = 0;

        rangeset_purge(r);
        for ( j = 0; j < tests[i].nr_actions; j++ )
        {
            const struct action *a = &tests[i].actions[j];

            switch ( a->action )
            {
            case ADD:
                rc = rangeset_add_range(r, a->r.start, a->r.end);
                break;

            case REMOVE:
                rc = rangeset_remove_range(r, a->r.start, a->r.end);
                break;
            }

            if ( rc )
            {
                printf("Test %u failed to %s range [%ld, %ld]\n",
                       i, a->action == ADD ? "add" : "remove",
                       a->r.start, a->r.end);
                rangeset_report_ranges(r, 0, ~0UL, print_range, NULL);
                break;
            }
        }

        if ( rc )
        {
            /* Action failed, skip this test and set exit code to failure. */
            ret_code = EXIT_FAILURE;
            continue;
        }

        rc = rangeset_report_ranges(r, 0, ~0UL, count_ranges, &nr);
        if ( rc )
        {
            printf("Test %u unable to count number of result ranges\n", i);
            rangeset_report_ranges(r, 0, ~0UL, print_range, NULL);
            ret_code = EXIT_FAILURE;
            continue;
        }
        if ( nr != tests[i].nr_results )
        {
            printf("Test %u unexpected number of result ranges, expected: %u got: %u\n",
                   i, tests[i].nr_results, nr);
            print_both(r, tests[i].result, tests[i].nr_results);
            ret_code = EXIT_FAILURE;
            continue;
        }

        nr = 0;
        expected = tests[i].result;
        rc = rangeset_report_ranges(r, 0, ~0UL, check_ranges, &nr);
        if ( rc )
        {
            printf("Test %u range checking failed\n", i);
            print_both(r, tests[i].result, tests[i].nr_results);
            ret_code = EXIT_FAILURE;
            continue;
        }
    }

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
