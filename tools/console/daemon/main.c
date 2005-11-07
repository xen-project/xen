/*\
 *  Copyright (C) International Business Machines  Corp., 2005
 *  Author(s): Anthony Liguori <aliguori@us.ibm.com>
 *
 *  Xen Console Daemon
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
\*/

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include "xenctrl.h"

#include "utils.h"
#include "io.h"

static void usage(char *name)
{
	printf("Usage: %s [-h] [-V] [-v] [-i]\n", name);
}

static void version(char *name)
{
	printf("Xen Console Daemon 3.0\n");
}

int main(int argc, char **argv)
{
	const char *sopts = "hVvi";
	struct option lopts[] = {
		{ "help", 0, 0, 'h' },
		{ "version", 0, 0, 'V' },
		{ "verbose", 0, 0, 'v' },
		{ "interactive", 0, 0, 'i' },
		{ 0 },
	};
	bool is_interactive = false;
	int ch;
	int syslog_option = LOG_CONS;
	int syslog_mask = LOG_WARNING;
	int opt_ind = 0;

	while ((ch = getopt_long(argc, argv, sopts, lopts, &opt_ind)) != -1) {
		switch (ch) {
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'V':
			version(argv[0]);
			exit(0);
		case 'v':
			syslog_option |= LOG_PERROR;
			syslog_mask = LOG_DEBUG;
			break;
		case 'i':
			is_interactive = true;
			break;
		case '?':
			fprintf(stderr,
				"Try `%s --help' for more information\n",
				argv[0]);
			exit(EINVAL);
		}
	}

	if (geteuid() != 0) {
		fprintf(stderr, "%s requires root to run.\n", argv[0]);
		exit(EPERM);
	}

	openlog("xenconsoled", syslog_option, LOG_DAEMON);
	setlogmask(syslog_mask);

	if (!is_interactive) {
		daemonize("/var/run/xenconsoled.pid");
	}

	if (!xen_setup())
		exit(1);

	enum_domains();

	handle_io();

	closelog();

	return 0;
}
