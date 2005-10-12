/*
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file "COPYING" in the main directory of
 * this archive for more details.
 *
 * Copyright (C) 2005 by Christian Limpach
 * Copyright (C) 2005 XenSource Ltd.
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
    errx(1, "Usage: %s [-h] [-p] [-s] key [...]", progname);
#elif defined(CLIENT_write)
    errx(1, "Usage: %s [-h] [-s] key value [...]", progname);
#elif defined(CLIENT_rm) || defined(CLIENT_exists) || defined(CLIENT_list)
    errx(1, "Usage: %s [-h] [-s] key [...]", progname);
#endif
}


static int
perform(int optind, int argc, char **argv, struct xs_handle *xsh,
        struct xs_transaction_handle *xth, int prefix)
{
    while (optind < argc) {
#if defined(CLIENT_read)
	char *val = xs_read(xsh, xth, argv[optind], NULL);
	if (val == NULL) {
	    warnx("couldn't read path %s", argv[optind]);
	    return 1;
	}
	if (prefix)
	    printf("%s: ", argv[optind]);
	printf("%s\n", val);
	free(val);
	optind++;
#elif defined(CLIENT_write)
	if (!xs_write(xsh, xth, argv[optind], argv[optind + 1],
                      strlen(argv[optind + 1]))) {
	    warnx("could not write path %s", argv[optind]);
	    return 1;
	}
	optind += 2;
#elif defined(CLIENT_rm)
	if (!xs_rm(xsh, xth, argv[optind])) {
	    warnx("could not remove path %s", argv[optind]);
	    return 1;
	}
	optind++;
#elif defined(CLIENT_exists)
	char *val = xs_read(xsh, xth, argv[optind], NULL);
	if (val == NULL) {
	    return 1;
	}
	free(val);
	optind++;
#elif defined(CLIENT_list)
	unsigned int i, num;
	char **list = xs_directory(xsh, xth, argv[optind], &num);
	if (list == NULL) {
	    warnx("could not list path %s", argv[optind]);
	    return 1;
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

    return 0;
}


int
main(int argc, char **argv)
{
    struct xs_handle *xsh;
    struct xs_transaction_handle *xth;
    int ret = 0, socket = 0;
    int prefix = 0;

    while (1) {
	int c, index = 0;
	static struct option long_options[] = {
	    {"help", 0, 0, 'h'},
#if defined(CLIENT_read) || defined(CLIENT_list)
	    {"prefix", 0, 0, 'p'},
#endif
            {"socket", 0, 0, 's'},
	    {0, 0, 0, 0}
	};

	c = getopt_long(argc, argv, "hs"
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
        case 's':
            socket = 1;
            break;
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

    xsh = socket ? xs_daemon_open() : xs_domain_open();
    if (xsh == NULL)
	err(1, socket ? "xs_daemon_open" : "xs_domain_open");

  again:
    xth = xs_transaction_start(xsh);
    if (xth == NULL)
	errx(1, "couldn't start transaction");

    ret = perform(optind, argc, argv, xsh, xth, prefix);

    if (!xs_transaction_end(xsh, xth, ret)) {
	if (ret == 0 && errno == EAGAIN)
	    goto again;
	errx(1, "couldn't end transaction");
    }
    return ret;
}
