/*
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file "COPYING" in the main directory of
 * this archive for more details.
 *
 * Copyright (C) 2005 by Christian Limpach
 *
 */

#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xs.h>

static void
usage(const char *progname)
{
#if defined(CLIENT_read)
    errx(1, "Usage: %s [-h] [-p] key [...]", progname);
#elif defined(CLIENT_write)
    errx(1, "Usage: %s [-h] key value [...]", progname);
#elif defined(CLIENT_rm)
    errx(1, "Usage: %s [-h] key [...]", progname);
#endif
}

int
main(int argc, char **argv)
{
    struct xs_handle *xsh;
    bool success;
    int ret = 0;
#if defined(CLIENT_read)
    char *val;
    int prefix = 0;
#endif

    xsh = xs_domain_open();
    if (xsh == NULL)
	err(1, "xs_domain_open");

    while (1) {
	int c, index = 0;
	static struct option long_options[] = {
	    {"help", 0, 0, 'h'},
#if defined(CLIENT_read)
	    {"prefix", 0, 0, 'p'},
#endif
	    {0, 0, 0, 0}
	};

	c = getopt_long(argc, argv, "h"
#if defined(CLIENT_read)
			"p"
#endif
			, long_options, &index);
	if (c == -1)
	    break;

	switch (c) {
	case 'h':
	    usage(argv[0]);
	    /* NOTREACHED */
#if defined(CLIENT_read)
	case 'p':
	    prefix = 1;
	    break;
#endif
	}
    }

    if (optind == argc) {
	usage(argv[0]);
	/* NOTREACHED */
    }
#if defined(CLIENT_write)
    if ((argc - optind) % 2 == 1) {
	usage(argv[0]);
	/* NOTREACHED */
    }
#endif

    /* XXX maybe find longest common prefix */
    success = xs_transaction_start(xsh, "/");
    if (!success)
	errx(1, "couldn't start transaction");

    while (optind < argc) {
#if defined(CLIENT_read)
	val = xs_read(xsh, argv[optind], NULL);
	if (val == NULL) {
	    warnx("couldn't read path %s", argv[optind]);
	    ret = 1;
	    goto out;
	}
	if (prefix)
	    printf("%s: ", argv[optind]);
	printf("%s\n", val);
	free(val);
	optind++;
#elif defined(CLIENT_write)
	success = xs_write(xsh, argv[optind], argv[optind + 1],
			   strlen(argv[optind + 1]), O_CREAT);
	if (!success) {
	    warnx("could not write path %s", argv[optind]);
	    ret = 1;
	    goto out;
	}
	optind += 2;
#elif defined(CLIENT_rm)
	success = xs_rm(xsh, argv[optind]);
	if (!success) {
	    warnx("could not remove path %s", argv[optind]);
	    ret = 1;
	    goto out;
	}
	optind++;
#endif
    }

 out:
    success = xs_transaction_end(xsh, ret ? true : false);
    if (!success)
	errx(1, "couldn't end transaction");

    return ret;
}
