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
#elif defined(CLIENT_chmod)
    errx(1, "Usage: %s [-h] [-s] key <mode [modes...]>", progname);
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

#if defined(CLIENT_chmod)
#define PATH_SEP '/'
#define MAX_PATH_LEN 256

static void
do_chmod(char *path, struct xs_permissions *perms, int nperms, int upto,
	 int recurse, struct xs_handle *xsh, xs_transaction_t xth)
{
    int ret;

    if (!path[0])
	return;

    ret = xs_set_permissions(xsh, xth, path, perms, nperms);
    if (!ret)
	err(1, "Error occurred setting permissions on '%s'", path);

    if (upto) {
	/* apply same permissions to all parent entries: */
	char *path_sep_ptr = strrchr(path, PATH_SEP);
	if (!path_sep_ptr)
	    errx(1, "Unable to locate path separator '%c' in '%s'",
		 PATH_SEP, path);
	
	*path_sep_ptr = '\0'; /* truncate path */
	
	do_chmod(path, perms, nperms, 1, 0, xsh, xth);

	*path_sep_ptr = PATH_SEP;
    }

    if (recurse) {
	char buf[MAX_PATH_LEN];

	/* apply same permissions to all child entries: */
	unsigned int xsval_n;
	char **xsval = xs_directory(xsh, xth, path, &xsval_n);

	if (xsval) {
	    int i;
	    for (i = 0; i < xsval_n; i++) {
		snprintf(buf, MAX_PATH_LEN, "%s/%s", path, xsval[i]);

		do_chmod(buf, perms, nperms, 0, 1, xsh, xth);
	    }

	    free(xsval);
	}
    }
}
#endif

static int
perform(int optind, int argc, char **argv, struct xs_handle *xsh,
        xs_transaction_t xth, int prefix, int tidy, int upto, int recurse)
{
    while (optind < argc) {
#if defined(CLIENT_read)
	static struct expanding_buffer ebuf;
	unsigned len;
	char *val = xs_read(xsh, xth, argv[optind], &len);
	if (val == NULL) {
	    warnx("couldn't read path %s", argv[optind]);
	    return 1;
	}
	if (prefix)
	    output("%s: ", argv[optind]);
	output("%s\n", sanitise_value(&ebuf, val, len));
	free(val);
	optind++;
#elif defined(CLIENT_write)
	static struct expanding_buffer ebuf;
	char *val_spec = argv[optind + 1];
	unsigned len;
	expanding_buffer_ensure(&ebuf, strlen(val_spec)+1);
	unsanitise_value(ebuf.buf, &len, val_spec);
	if (!xs_write(xsh, xth, argv[optind], ebuf.buf, len)) {
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
                unsigned len;
                *slash = '\0';
                val = xs_read(xsh, xth, p, &len);
                if (val && len == 0) {
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
#elif defined(CLIENT_chmod)
#define MAX_PERMS 16
	struct xs_permissions perms[MAX_PERMS];
	int nperms = 0;
	/* save path pointer: */
	char *path = argv[optind++];
	for (; argv[optind]; optind++, nperms++)
	{
	    if (MAX_PERMS <= nperms)
		errx(1, "Too many permissions specified.  "
		     "Maximum per invocation is %d.", MAX_PERMS);

	    perms[nperms].id = atoi(argv[optind]+1);

	    switch (argv[optind][0])
	    {
	    case 'n':
		perms[nperms].perms = XS_PERM_NONE;
		break;
	    case 'r':
		perms[nperms].perms = XS_PERM_READ;
		break;
	    case 'w':
		perms[nperms].perms = XS_PERM_WRITE;
		break;
	    case 'b':
		perms[nperms].perms = XS_PERM_READ | XS_PERM_WRITE;
		break;
	    default:
		errx(1, "Invalid permission specification: '%c'",
		     argv[optind][0]);
	    }
	}

	do_chmod(path, perms, nperms, upto, recurse, xsh, xth);
#endif
    }

    return 0;
}


int
main(int argc, char **argv)
{
    struct xs_handle *xsh;
    xs_transaction_t xth = XBT_NULL;
    int ret = 0, socket = 0;
    int prefix = 0;
    int tidy = 0;
    int upto = 0;
    int recurse = 0;
    int transaction;

    while (1) {
	int c, index = 0;
	static struct option long_options[] = {
	    {"help", 0, 0, 'h'},
            {"socket", 0, 0, 's'},
#if defined(CLIENT_read) || defined(CLIENT_list)
	    {"prefix", 0, 0, 'p'},
#elif defined(CLIENT_rm)
            {"tidy",   0, 0, 't'},
#elif defined(CLIENT_chmod)
	    {"upto",    0, 0, 'u'},
	    {"recurse", 0, 0, 'r'},
#endif
	    {0, 0, 0, 0}
	};

	c = getopt_long(argc, argv, "hs"
#if defined(CLIENT_read) || defined(CLIENT_list)
			"p"
#elif defined(CLIENT_rm)
                        "t"
#elif defined(CLIENT_chmod)
			"ur"
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
#elif defined(CLIENT_chmod)
	case 'u':
	    upto = 1;
	    break;
	case 'r':
	    recurse = 1;
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

#if defined(CLIENT_read)
    transaction = (argc - optind) > 1;
#elif defined(CLIENT_write)
    transaction = (argc - optind) > 2;
#else
    transaction = 1;
#endif

    xsh = socket ? xs_daemon_open() : xs_domain_open();
    if (xsh == NULL)
	err(1, socket ? "xs_daemon_open" : "xs_domain_open");

  again:
    if (transaction) {
	xth = xs_transaction_start(xsh);
	if (xth == XBT_NULL)
	    errx(1, "couldn't start transaction");
    }

    ret = perform(optind, argc, argv, xsh, xth, prefix, tidy, upto, recurse);

    if (transaction && !xs_transaction_end(xsh, xth, ret)) {
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
