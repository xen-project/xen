/*
 *  Author:  Daniel De Graaf <dgdegra@tycho.nsa.gov>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <xenctrl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

static void usage(char **argv)
{
	fprintf(stderr, "Usage: %s {name|-a}\n", argv[0]);
	exit(1);
}

static int all_bools(xc_interface *xch)
{
	int err = 0, i = 0, curr, pend;
	char name[256];
	while (1) {
		err = xc_flask_getbool_byid(xch, i, name, sizeof name, &curr, &pend);
		if (err < 0) {
			if (errno == ENOENT)
				return 0;
			fprintf(stderr, "xc_flask_getbool: Unable to get boolean #%d: %s (%d)",
				i, strerror(errno), err);
			return 2;
		}
		if (curr == pend)
			printf("%s: %d\n", name, curr);
		else
			printf("%s: %d (pending %d)\n", name, curr, pend);
		i++;
	}
}

int main(int argc, char **argv)
{
	int err = 0;
	xc_interface *xch;
	int curr, pend;

	if (argc != 2)
		usage(argv);

	xch = xc_interface_open(0,0,0);
	if ( !xch )
	{
		fprintf(stderr, "Unable to create interface to xenctrl: %s\n",
				strerror(errno));
		err = 1;
		goto done;
	}

	if (!strcmp(argv[1], "-a"))
	{
		err = all_bools(xch);
		goto done;
	}

	err = xc_flask_getbool_byname(xch, argv[1], &curr, &pend);
	if (err) {
		fprintf(stderr, "xc_flask_getbool: Unable to get boolean %s: %s (%d)",
			argv[1], strerror(errno), err);
		err = 2;
		goto done;
	}

	if (curr == pend)
		printf("%s: %d\n", argv[1], curr);
	else
		printf("%s: %d (pending %d)\n", argv[1], curr, pend);

 done:
	if ( xch )
		xc_interface_close(xch);

	return err;
}
