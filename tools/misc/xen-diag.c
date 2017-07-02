/*
 * Copyright (c) 2017 Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <xenctrl.h>

#include <xen/errno.h>
#include <xen-tools/libs.h>

static xc_interface *xch;

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

void show_help(void)
{
    fprintf(stderr,
            "xen-diag: xen diagnostic utility\n"
            "Usage: xen-diag command [args]\n"
            "Commands:\n"
            "  help                       display this help\n"
            "  gnttab_query_size <domid>  dump the current and max grant frames for <domid>\n");
}

/* wrapper function */
static int help_func(int argc, char *argv[])
{
    show_help();
    return 0;
}

static int gnttab_query_size_func(int argc, char *argv[])
{
    int domid, rc = 1;
    struct gnttab_query_size query;

    if ( argc != 1 )
    {
        show_help();
        return rc;
    }

    domid = strtol(argv[0], NULL, 10);
    query.dom = domid;
    rc = xc_gnttab_query_size(xch, &query);

    if ( rc == 0 && (query.status == GNTST_okay) )
        printf("domid=%d: nr_frames=%d, max_nr_frames=%d\n",
               query.dom, query.nr_frames, query.max_nr_frames);

    return rc == 0 && (query.status == GNTST_okay) ? 0 : 1;
}

struct {
    const char *name;
    int (*function)(int argc, char *argv[]);
} main_options[] = {
    { "help", help_func },
    { "gnttab_query_size", gnttab_query_size_func},
};

int main(int argc, char *argv[])
{
    int ret, i;

    /*
     * Set stdout to be unbuffered to avoid having to fflush when
     * printing without a newline.
     */
    setvbuf(stdout, NULL, _IONBF, 0);

    if ( argc <= 1 )
    {
        show_help();
        return 0;
    }

    for ( i = 0; i < ARRAY_SIZE(main_options); i++ )
        if ( !strncmp(main_options[i].name, argv[1], strlen(argv[1])) )
            break;

    if ( i == ARRAY_SIZE(main_options) )
    {
        show_help();
        return 0;
    }
    else
    {
        xch = xc_interface_open(0, 0, 0);
        if ( !xch )
        {
            fprintf(stderr, "failed to get the handler\n");
            return 0;
        }

        ret = main_options[i].function(argc - 2, argv + 2);

        xc_interface_close(xch);
    }

    /*
     * Exitcode 0 for success.
     * Exitcode 1 for an error.
     * Exitcode 2 if the operation should be retried for any reason (e.g. a
     * timeout or because another operation was in progress).
     */

#define EXIT_TIMEOUT (EXIT_FAILURE + 1)

    BUILD_BUG_ON(EXIT_SUCCESS != 0);
    BUILD_BUG_ON(EXIT_FAILURE != 1);
    BUILD_BUG_ON(EXIT_TIMEOUT != 2);

    switch ( ret )
    {
    case 0:
        return EXIT_SUCCESS;
    case EAGAIN:
    case EBUSY:
        return EXIT_TIMEOUT;
    default:
        return EXIT_FAILURE;
    }
}
