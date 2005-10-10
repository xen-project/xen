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
#include <errno.h>

static void
usage(const char *progname)
{
#if defined(CLIENT_read)
    errx(1, "Usage: %s [-h] [-p] key [...]", progname);
#elif defined(CLIENT_write)
    errx(1, "Usage: %s [-h] key value [...]", progname);
#elif defined(CLIENT_rm) || defined(CLIENT_exists) || defined(CLIENT_list)
    errx(1, "Usage: %s [-h] key [...]", progname);
#endif
}

int
main(int argc, char **argv)
{
    struct xs_handle *xsh;
    struct xs_transaction_handle *xth;
    bool success;
    int ret = 0;
#if defined(CLIENT_read) || defined(CLIENT_list)
    int prefix = 0;
#endif

    xsh = xs_domain_open();
    if (xsh == NULL)
	err(1, "xs_domain_open");

    while (1) {
	int c, index = 0;
	static struct option long_options[] = {
	    {"help", 0, 0, 'h'},
#if defined(CLIENT_read) || defined(CLIENT_list)
	    {"prefix", 0, 0, 'p'},
#endif
	    {0, 0, 0, 0}
	};

	c = getopt_long(argc, argv, "h"
#if defined(CLIENT_read) || defined(CLIENT_list)
			"p"
#endif
			, long_options, &index);
	if (c == -1)
	    break;

	switch (c) {
	case 'h':
	    usage(argv[0]);
	    /* NOTREACHED */
#if defined(CLIENT_read) || defined(CLIENT_list)
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

  again:
    xth = xs_transaction_start(xsh);
    if (xth == NULL)
	errx(1, "couldn't start transaction");

    while (optind < argc) {
#if defined(CLIENT_read)
	char *val = xs_read(xsh, xth, argv[optind], NULL);
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
	success = xs_write(xsh, xth, argv[optind], argv[optind + 1],
			   strlen(argv[optind + 1]));
	if (!success) {
	    warnx("could not write path %s", argv[optind]);
	    ret = 1;
	    goto out;
	}
	optind += 2;
#elif defined(CLIENT_rm)
	success = xs_rm(xsh, xth, argv[optind]);
	if (!success) {
	    warnx("could not remove path %s", argv[optind]);
	    ret = 1;
	    goto out;
	}
	optind++;
#elif defined(CLIENT_exists)
	char *val = xs_read(xsh, xth, argv[optind], NULL);
	if (val == NULL) {
	    ret = 1;
	    goto out;
	}
	free(val);
	optind++;
#elif defined(CLIENT_list)
	unsigned int i, num;
	char **list = xs_directory(xsh, xth, argv[optind], &num);
	if (list == NULL) {
	    warnx("could not list path %s", argv[optind]);
	    ret = 1;
	    goto out;
	}
	for (i = 0; i < num; i++) {
	    if (prefix)
		printf("%s/", argv[optind]);
	    printf("%s\n", list[i]);
	}
	free(list);
	optind++;
#endif
    }

 out:
    success = xs_transaction_end(xsh, xth, ret ? true : false);
    if (!success) {
	if (ret == 0 && errno == EAGAIN)
	    goto again;
	errx(1, "couldn't end transaction");
    }
    return ret;
}
