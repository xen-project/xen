/*
 * xs-test.c
 *
 * Do Xenstore tests.
 *
 * Copyright (C) 2016  Juergen Gross <jgross@suse.com>,
 *                     SUSE Linux GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <xenstore.h>

#define TEST_PATH "xenstore-test"
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define WRITE_BUFFERS_N    10
#define WRITE_BUFFERS_SIZE 4000
#define MAX_TA_LOOPS       100

struct test {
    char *name;
    int (*func_init)(uintptr_t par);
    int (*func)(uintptr_t par);
    int (*func_deinit)(uintptr_t par);
    uintptr_t par;
    char *descr;
};

static struct xs_handle *xsh;
static char *path;
static char *paths[WRITE_BUFFERS_N];
static char write_buffers[WRITE_BUFFERS_N][WRITE_BUFFERS_SIZE];
static int ta_loops;

static struct option options[] = {
    { "list-tests", 0, NULL, 'l' },
    { "test", 1, NULL, 't' },
    { "random", 1, NULL, 'r' },
    { "help", 0, NULL, 'h' },
    { "iterations", 1, NULL, 'i' },
    { NULL, 0, NULL, 0 }
};

static int call_test(struct test *tst, int iters, bool no_clock)
{
    char *stage = "?";
    struct timespec tp1, tp2;
    uint64_t nsec, nsec_min, nsec_max, nsec_sum;
    int i, ret;

    nsec_min = -1;
    nsec_max = 0;
    nsec_sum = 0;

    for ( i = 0; i < iters; i++ )
    {
        stage = "pre-init";
        xs_rm(xsh, XBT_NULL, path);
        if ( !xs_write(xsh, XBT_NULL, path, "", 0) )
        {
            ret = errno;
            break;
        }
        stage = "init";
        ret = tst->func_init(tst->par);
        if ( ret )
            break;
        if ( clock_gettime(CLOCK_REALTIME, &tp1) )
            no_clock = true;
        stage = "run";
        ret = tst->func(tst->par);
        if ( ret )
            break;
        if ( clock_gettime(CLOCK_REALTIME, &tp2) )
            no_clock = true;
        if ( !no_clock )
        {
            nsec = tp2.tv_sec * 1000000000 + tp2.tv_nsec -
                   tp1.tv_sec * 1000000000 - tp1.tv_nsec;
            if ( nsec < nsec_min )
                nsec_min = nsec;
            if ( nsec > nsec_max )
                nsec_max = nsec;
            nsec_sum += nsec;
        }
        stage = "deinit";
        ret = tst->func_deinit(tst->par);
        if ( ret )
            break;
    }

    if ( ret )
        printf("%-10s: failed (ret = %d, stage %s)\n", tst->name, ret, stage);
    else if ( !no_clock )
    {
        printf("%-10s:", tst->name);
        if ( iters > 1 )
            printf(" avg: %"PRIu64" ns (%"PRIu64" ns .. %"PRIu64" ns)",
                   nsec_sum / iters, nsec_min, nsec_max);
        else
            printf(" %"PRIu64" ns", nsec_sum);
        printf("\n");
    }

    return ret;
}

static void usage(int ret)
{
    FILE *out;

    out = ret ? stderr : stdout;

    fprintf(out, "usage: xs-test [<options>]\n");
    fprintf(out, "  <options> are:\n");
    fprintf(out, "  -i|--iterations <i>  perform each test <i> times (default 1)\n");
    fprintf(out, "  -l|--list-tests      list available tests\n");
    fprintf(out, "  -r|--random <time>   perform random tests for <time> seconds\n");
    fprintf(out, "  -t|--test <test>     run <test> (default is all tests)\n");
    fprintf(out, "  -h|--help            print this usage information\n");
    exit(ret);
}

static int ret0(uintptr_t par)
{
    return 0;
}

static int verify_node(char *node, char *data, unsigned int size)
{
    char *buf;
    unsigned int len;
    int ret;

    buf = xs_read(xsh, XBT_NULL, node, &len);
    if ( !buf )
        return errno;

    ret = (len == size && !memcmp(buf, data, len)) ? 0 : ENODATA;
    free(buf);

    return ret;
}

static int test_read_init(uintptr_t par)
{
    if ( par > WRITE_BUFFERS_SIZE )
        return EFBIG;
    return xs_write(xsh, XBT_NULL, paths[0], write_buffers[0], par) ? 0 : errno;
}

static int test_read(uintptr_t par)
{
    char *buf;
    unsigned int len;

    buf = xs_read(xsh, XBT_NULL, paths[0], &len);
    if ( !buf )
        return errno;
    free(buf);
    return 0;
}

#define test_read_deinit ret0

static int test_write_init(uintptr_t par)
{
    return (par > WRITE_BUFFERS_SIZE) ? EFBIG : 0;
}

static int test_write(uintptr_t par)
{
    return xs_write(xsh, XBT_NULL, paths[0], write_buffers[0], par) ? 0 : errno;
}

static int test_write_deinit(uintptr_t par)
{
    return verify_node(paths[0], write_buffers[0], par);
}

static int test_dir_init(uintptr_t par)
{
    unsigned int i;

    for ( i = 0; i < WRITE_BUFFERS_N; i++ )
        if ( !xs_write(xsh, XBT_NULL, paths[i], write_buffers[i], 1) )
            return errno;

    return 0;
}

static int test_dir(uintptr_t par)
{
    char **dir;
    unsigned int num;

    dir = xs_directory(xsh, XBT_NULL, path, &num);
    if ( !dir )
        return errno;

    free(dir);
    return 0;
}

static int test_dir_deinit(uintptr_t par)
{
    char **dir;
    unsigned int i, j, num;
    int rc = 0;

    dir = xs_directory(xsh, XBT_NULL, path, &num);
    if ( !dir )
        return errno;

    for ( j = 0; j < WRITE_BUFFERS_N; j++ )
    {
        for ( i = 0; i < num; i++ )
            if ( dir[i][0] == 'a' + j && dir[i][1] == 0 )
                break;
        if ( i == num )
            rc = ENODATA;
    }
    if ( num != WRITE_BUFFERS_N )
            rc = ENODATA;
    free(dir);
    return rc;
}

static int test_rm_init(uintptr_t par)
{
    unsigned int i;

    if ( par > WRITE_BUFFERS_N )
        return EFBIG;

    for ( i = 0; i < par; i++ )
        if ( xs_write(xsh, XBT_NULL, paths[i], write_buffers[i], 1) )
            return errno;

    return 0;
}

static int test_rm(uintptr_t par)
{
    if ( !xs_rm(xsh, XBT_NULL, path) )
        return errno;

    return 0;
}

#define test_rm_deinit ret0

#define test_ta1_init ret0

static int test_ta1(uintptr_t par)
{
    xs_transaction_t t;
    int l;

    for ( l = 0; l < MAX_TA_LOOPS; l++ )
    {
        t = xs_transaction_start(xsh);
        if ( t == XBT_NULL )
            return errno;
        if ( xs_transaction_end(xsh, t, par ? true : false) )
            return 0;
        if ( errno != EAGAIN )
            return errno;
    }

    ta_loops++;
    return 0;
}

#define test_ta1_deinit ret0

static int test_ta2_init(uintptr_t par)
{
    return xs_write(xsh, XBT_NULL, paths[0], write_buffers[0], 1) ? 0 : errno;
}

static int test_ta2(uintptr_t par)
{
    xs_transaction_t t;
    char *buf;
    unsigned int len;
    int ret;
    int l;

    for ( l = 0; l < MAX_TA_LOOPS; l++ )
    {
        t = xs_transaction_start(xsh);
        if ( t == XBT_NULL )
            return errno;
        buf = xs_read(xsh, t, paths[0], &len);
        if ( !buf )
            goto out;
        free(buf);
        if ( !xs_write(xsh, t, paths[0], "b", 1) )
            goto out;
        buf = xs_read(xsh, t, paths[0], &len);
        if ( !buf )
            goto out;
        errno = (len == 1 && buf[0] == 'b') ? 0 : ENODATA;
        free(buf);
        if ( errno )
            goto out;
        buf = xs_read(xsh, XBT_NULL, paths[0], &len);
        if ( !buf )
            goto out;
        errno = (len == 1 && buf[0] == 'a') ? 0 : ENODATA;
        free(buf);
        if ( errno )
            goto out;
        if ( xs_transaction_end(xsh, t, par ? true : false) )
            return 0;
        if ( errno != EAGAIN )
            return errno;
    }

    ta_loops++;
    return 0;

 out:
    ret = errno;
    xs_transaction_end(xsh, t, true);
    return ret;
}

static int test_ta2_deinit(uintptr_t par)
{
    return verify_node(paths[0], par ? "a" : "b", 1);
}

static int test_ta3_init(uintptr_t par)
{
    return xs_write(xsh, XBT_NULL, paths[0], write_buffers[0], 1) ? 0 : errno;
}

static int test_ta3(uintptr_t par)
{
    xs_transaction_t t;
    char *buf;
    unsigned int len;
    int ret;

    t = xs_transaction_start(xsh);
    if ( t == XBT_NULL )
        return errno;
    buf = xs_read(xsh, t, paths[0], &len);
    if ( !buf )
        goto out;
    free(buf);
    if ( !xs_write(xsh, XBT_NULL, paths[0], "b", 1) )
        goto out;
    buf = xs_read(xsh, t, paths[0], &len);
    if ( !buf )
        goto out;
    errno = (len == 1 && buf[0] == 'a') ? 0 : ENODATA;
    free(buf);
    if ( errno )
        goto out;
    if ( !xs_write(xsh, t, paths[0], "c", 1) )
        goto out;
    buf = xs_read(xsh, t, paths[0], &len);
    if ( !buf )
        goto out;
    errno = (len == 1 && buf[0] == 'c') ? 0 : ENODATA;
    free(buf);
    if ( errno )
        goto out;
    if ( xs_transaction_end(xsh, t, false) || errno != EAGAIN )
        return ENODATA;
    return 0;

 out:
    ret = errno;
    xs_transaction_end(xsh, t, true);
    return ret;
}

static int test_ta3_deinit(uintptr_t par)
{
    return verify_node(paths[0], "b", 1);
}

#define TEST(s, f, p, l) { s, f ## _init, f, f ## _deinit, (uintptr_t)(p), l }
struct test tests[] = {
TEST("read 1", test_read, 1, "Read node with 1 byte data"),
TEST("read 3000", test_read, 3000, "Read node with 3000 bytes data"),
TEST("write 1", test_write, 1, "Write node with 1 byte data"),
TEST("write 3000", test_write, 3000, "Write node with 3000 bytes data"),
TEST("dir", test_dir, 0, "List directory"),
TEST("rm node", test_rm, 0, "Remove single node"),
TEST("rm dir", test_rm, WRITE_BUFFERS_N, "Remove node with sub-nodes"),
TEST("ta empty", test_ta1, 0, "Empty transaction"),
TEST("ta empty x", test_ta1, 1, "Empty transaction abort"),
TEST("ta rmw", test_ta2, 0, "Read-modify-write transaction"),
TEST("ta rmw x", test_ta2, 1, "Read-modify-write transaction abort"),
TEST("ta err", test_ta3, 0, "Transaction with conflict"),
};

static void cleanup(void)
{
    xs_transaction_t t;
    char **dir;
    unsigned int num;

    xs_rm(xsh, XBT_NULL, path);

    while ( true )
    {
        t = xs_transaction_start(xsh);
        if ( t == XBT_NULL )
            return;

        dir = xs_directory(xsh, t, TEST_PATH, &num);
        if ( dir && !num )
            xs_rm(xsh, t, TEST_PATH);
        free(dir);

        if ( xs_transaction_end(xsh, t, false) || errno != EAGAIN )
            return;
    }
}

int main(int argc, char *argv[])
{
    int opt, t, iters = 1, ret = 0, randtime = 0;
    char *test = NULL;
    bool list = false;
    time_t stop;

    while ( (opt = getopt_long(argc, argv, "lr:t:hi:", options,
                               NULL)) != -1 )
    {
        switch ( opt )
        {
        case 'i':
            iters = atoi(optarg);
            break;
        case 'l':
            list = true;
            break;
        case 'r':
            randtime = atoi(optarg);
            break;
        case 't':
            test = optarg;
            break;
        case 'h':
            usage(0);
            break;
        }
    }
    if ( optind != argc )
        usage(1);

    if ( list )
    {
        for ( t = 0; t < ARRAY_SIZE(tests); t++ )
            printf("%-10s: %s\n", tests[t].name, tests[t].descr);
        return 0;
    }

    asprintf(&path, "%s/%u", TEST_PATH, getpid());
    for ( t = 0; t < WRITE_BUFFERS_N; t++ )
    {
        memset(write_buffers[t], 'a' + t, WRITE_BUFFERS_SIZE);
        asprintf(&paths[t], "%s/%c", path, 'a' + t);
    }

    xsh = xs_open(0);
    if ( !xsh )
    {
        fprintf(stderr, "could not connect to xenstore\n");
        exit(2);
    }

    if ( randtime )
    {
        stop = time(NULL) + randtime;
        srandom((unsigned int)stop);

        while ( time(NULL) < stop )
        {
            t = random() % ARRAY_SIZE(tests);
            ret = call_test(tests + t, iters, true);
        }
    }
    else
        for ( t = 0; t < ARRAY_SIZE(tests); t++ )
        {
            if ( !test || !strcmp(test, tests[t].name) )
                ret = call_test(tests + t, iters, false);
        }

    if ( !ret )
        cleanup();

    xs_close(xsh);

    if ( ta_loops )
        printf("Exhaustive transaction retries (%d) occurrred %d times.\n",
               MAX_TA_LOOPS, ta_loops);

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
