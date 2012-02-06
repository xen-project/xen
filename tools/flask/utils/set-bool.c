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
	fprintf(stderr, "Usage: %s name value\n", argv[0]);
	exit(1);
}

static int str2bool(const char *str)
{
	if (str[0] == '0' || str[0] == '1')
		return (str[0] == '1');
	if (!strcasecmp(str, "enabled") || !strcasecmp(str, "on") || !strcasecmp(str, "y"))
		return 1;
	if (!strcasecmp(str, "disabled") || !strcasecmp(str, "off") || !strcasecmp(str, "n"))
		return 0;
	fprintf(stderr, "Unknown value %s\n", str);
	exit(1);
}

int main(int argc, char **argv)
{
	int err = 0;
	xc_interface *xch;
	int value;

	if (argc != 3)
		usage(argv);

	value = str2bool(argv[2]);

	xch = xc_interface_open(0,0,0);
	if ( !xch )
	{
		fprintf(stderr, "Unable to create interface to xenctrl: %s\n",
				strerror(errno));
		err = 1;
		goto done;
	}

	err = xc_flask_setbool(xch, argv[1], value, 1);
	if (err) {
		fprintf(stderr, "xc_flask_setbool: Unable to set boolean %s=%s: %s (%d)",
			argv[1], argv[2], strerror(errno), err);
		err = 2;
		goto done;
	}

 done:
	if ( xch )
		xc_interface_close(xch);

	return err;
}
