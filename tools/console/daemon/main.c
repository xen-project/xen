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
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
\*/

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/resource.h>

#include "xenctrl.h"

#include "utils.h"
#include "io.h"
#include "_paths.h"

int log_reload = 0;
int log_guest = 0;
int log_hv = 0;
int log_time_hv = 0;
int log_time_guest = 0;
char *log_dir = NULL;
int discard_overflowed_data = 1;
int replace_escape = 0;

static void handle_hup(int sig)
{
        log_reload = 1;
}

static void usage(char *name)
{
	printf("Usage: %s [-h] [-V] [-v] [-i] [--log=none|guest|hv|all] [--log-dir=DIR] [--pid-file=PATH] [-t, --timestamp=none|guest|hv|all] [-o, --overflow-data=discard|keep] [--replace-escape]\n", name);
	printf("  --replace-escape  - replace ESC character with dot when writing console log\n");
}

static void version(char *name)
{
	printf("Xen Console Daemon 3.0\n");
}

static void increase_fd_limit(void)
{
	/*
	 * We require many file descriptors:
	 * - per domain: pty master, pty slave, logfile and evtchn
	 * - misc extra: hypervisor log, privcmd, gntdev, std...
	 *
	 * Allow a generous 1000 for misc, and calculate the maximum possible
	 * number of fds which could be used.
	 */
	unsigned min_fds = (DOMID_FIRST_RESERVED * 4) + 1000;
	struct rlimit lim, new = { min_fds, min_fds };

	if (getrlimit(RLIMIT_NOFILE, &lim) < 0) {
		fprintf(stderr, "Failed to obtain fd limit: %s\n",
			strerror(errno));
		exit(1);
	}

	/* Do we already have sufficient? Great! */
	if (lim.rlim_cur >= min_fds)
		return;

	/* Try to increase our limit. */
	if (setrlimit(RLIMIT_NOFILE, &new) < 0)
		syslog(LOG_WARNING,
		       "Unable to increase fd limit from {%llu, %llu} to "
		       "{%llu, %llu}: (%s) - May run out with lots of domains",
		       (unsigned long long)lim.rlim_cur,
		       (unsigned long long)lim.rlim_max,
		       (unsigned long long)new.rlim_cur,
		       (unsigned long long)new.rlim_max,
		       strerror(errno));
}

int main(int argc, char **argv)
{
	const char *sopts = "hVvit:o:";
	struct option lopts[] = {
		{ "help", 0, 0, 'h' },
		{ "version", 0, 0, 'V' },
		{ "verbose", 0, 0, 'v' },
		{ "interactive", 0, 0, 'i' },
		{ "log", 1, 0, 'l' },
		{ "log-dir", 1, 0, 'r' },
		{ "pid-file", 1, 0, 'p' },
		{ "timestamp", 1, 0, 't' },
		{ "overflow-data", 1, 0, 'o'},
		{ "replace-escape", 0, 0, 'e'},
		{ 0 },
	};
	bool is_interactive = false;
	int ch;
	int syslog_option = LOG_CONS;
	int syslog_mask = LOG_MASK(LOG_WARNING)|LOG_MASK(LOG_ERR)|LOG_MASK(LOG_CRIT)|\
		          LOG_MASK(LOG_ALERT)|LOG_MASK(LOG_EMERG);
	int opt_ind = 0;
	char *pidfile = NULL;

	while ((ch = getopt_long(argc, argv, sopts, lopts, &opt_ind)) != -1) {
		switch (ch) {
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'V':
			version(argv[0]);
			exit(0);
		case 'v':
#ifndef __sun__
			syslog_option |= LOG_PERROR;
#endif
			syslog_mask |= LOG_MASK(LOG_NOTICE)|LOG_MASK(LOG_INFO)| \
				      LOG_MASK(LOG_DEBUG);
			break;
		case 'i':
			is_interactive = true;
			break;
		case 'l':
		        if (!strcmp(optarg, "all")) {
			      log_hv = 1;
			      log_guest = 1;
			} else if (!strcmp(optarg, "hv")) {
			      log_hv = 1;
			} else if (!strcmp(optarg, "guest")) {
			      log_guest = 1;
			}
			break;
		case 'r':
		        log_dir = strdup(optarg);
			break;
		case 'p':
		        pidfile = strdup(optarg);
			break;
		case 't':
			if (!strcmp(optarg, "all")) {
				log_time_hv = 1;
				log_time_guest = 1;
			} else if (!strcmp(optarg, "hv")) {
				log_time_hv = 1;
			} else if (!strcmp(optarg, "guest")) {
				log_time_guest = 1;
			} else if (!strcmp(optarg, "none")) {
				log_time_guest = 0;
				log_time_hv = 0;
			}
			break;
		case 'o':
			if (!strcmp(optarg, "keep")) {
				discard_overflowed_data = 0;
			} else if (!strcmp(optarg, "discard")) {
				discard_overflowed_data = 1;
			}
			break;
		case 'e':
			replace_escape = 1;
			break;
		case '?':
			fprintf(stderr,
				"Try `%s --help' for more information\n",
				argv[0]);
			exit(EINVAL);
		}
	}

	if (!log_dir) {
		log_dir = strdup(XEN_LOG_DIR "/console");
	}

	if (geteuid() != 0) {
		fprintf(stderr, "%s requires root to run.\n", argv[0]);
		exit(EPERM);
	}

	signal(SIGHUP, handle_hup);

	openlog("xenconsoled", syslog_option, LOG_DAEMON);
	setlogmask(syslog_mask);

	increase_fd_limit();

	if (!is_interactive) {
		daemonize(pidfile ? pidfile : XEN_RUN_DIR "/xenconsoled.pid");
	}

	if (!xen_setup())
		exit(1);

	handle_io();

	closelog();
	free(log_dir);
	free(pidfile);

	return 0;
}

/*
 * Local variables:
 *  mode: C
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
