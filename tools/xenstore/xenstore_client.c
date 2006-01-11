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
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xs.h>

static char *output_buf = NULL;
static int output_pos = 0;

#if defined(CLIENT_read) || defined(CLIENT_list)
static int output_size = 0;

static void
output(const char *fmt, ...) {
    va_list ap;
    int len;
    char buf[1];

    va_start(ap, fmt);
    len = vsnprintf(buf, 1, fmt, ap);
    if (len < 0)
	err(1, "output");
    va_end(ap);
    if (len + 1 + output_pos > output_size) {
	output_size += len + 1024;
	output_buf = realloc(output_buf, output_size);
	if (output_buf == NULL)
	    err(1, "malloc");
    }
    va_start(ap, fmt);
    if (vsnprintf(&output_buf[output_pos], len + 1, fmt, ap) != len)
	err(1, "output");
    va_end(ap);
    output_pos += len;
}
#endif

static void
usage(const char *progname)
{
#if defined(CLIENT_read)
    errx(1, "Usage: %s [-h] [-p] [-s] key [...]", progname);
#elif defined(CLIENT_write)
    errx(1, "Usage: %s [-h] [-s] key value [...]", progname);
#elif defined(CLIENT_rm)
    errx(1, "Usage: %s [-h] [-s] [-t] key [...]", progname);
#elif defined(CLIENT_exists) || defined(CLIENT_list)
    errx(1, "Usage: %s [-h] [-s] key [...]", progname);
#endif
}


#if defined(CLIENT_rm)
static int
do_rm(char *path, struct xs_handle *xsh, xs_transaction_t xth)
{
    if (xs_rm(xsh, xth, path)) {
        return 0;
    }
    else {
        warnx("could not remove path %s", path);
        return 1;
    }
}
#endif


static int
perform(int optind, int argc, char **argv, struct xs_handle *xsh,
        xs_transaction_t xth, int prefix, int tidy)
{
    while (optind < argc) {
#if defined(CLIENT_read)
	char *val = xs_read(xsh, xth, argv[optind], NULL);
	if (val == NULL) {
	    warnx("couldn't read path %s", argv[optind]);
	    return 1;
	}
	if (prefix)
	    output("%s: ", argv[optind]);
	output("%s\n", val);
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
        /* Remove the specified path.  If the tidy flag is set, then also
           remove any containing directories that are both empty and have no
           value attached, and repeat, recursing all the way up to the root if
           necessary.
        */

        char *slash, *path = argv[optind];

        if (tidy) {
            /* Copy path, because we can't modify argv because we will need it
               again if xs_transaction_end gives us EAGAIN. */
            char *p = malloc(strlen(path) + 1);
            strcpy(p, path);
            path = p;

        again:
            if (do_rm(path, xsh, xth)) {
                return 1;
            }

            slash = strrchr(p, '/');
            if (slash) {
                char *val;
                *slash = '\0';
                val = xs_read(xsh, xth, p, NULL);
                if (val && strlen(val) == 0) {
                    unsigned int num;
                    char ** list = xs_directory(xsh, xth, p, &num);

                    if (list && num == 0) {
                        goto again;
                    }
                }
            }

            free(path);
        }
        else {
            if (do_rm(path, xsh, xth)) {
                return 1;
            }
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
		output("%s/", argv[optind]);
	    output("%s\n", list[i]);
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
    xs_transaction_t xth;
    int ret = 0, socket = 0;
    int prefix = 0;
    int tidy = 0;

    while (1) {
	int c, index = 0;
	static struct option long_options[] = {
	    {"help", 0, 0, 'h'},
            {"socket", 0, 0, 's'},
#if defined(CLIENT_read) || defined(CLIENT_list)
	    {"prefix", 0, 0, 'p'},
#elif defined(CLIENT_rm)
            {"tidy",   0, 0, 't'},
#endif
	    {0, 0, 0, 0}
	};

	c = getopt_long(argc, argv, "hs"
#if defined(CLIENT_read) || defined(CLIENT_list)
			"p"
#elif defined(CLIENT_rm)
                        "t"
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
#elif defined(CLIENT_rm)
	case 't':
	    tidy = 1;
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

    ret = perform(optind, argc, argv, xsh, xth, prefix, tidy);

    if (!xs_transaction_end(xsh, xth, ret)) {
	if (ret == 0 && errno == EAGAIN) {
	    output_pos = 0;
	    goto again;
	}
	errx(1, "couldn't end transaction");
    }

    if (output_pos)
	printf("%s", output_buf);

    return ret;
}
