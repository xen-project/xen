/* $NetBSD: xenbackendd.c,v 1.1.1.1 2008/08/07 20:26:57 cegger Exp $ */
/*
 * Copyright (C) 2006 Manuel Bouyer <bouyer@netbsd.org>
 * Copyright (C) 2009 Christoph Egger <Christoph.Egger@amd.com>
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
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>

#include <xenstore.h>

#define DEVTYPE_UNKNOWN 0
#define DEVTYPE_VIF 1
#define DEVTYPE_VBD 2
#define DISABLE_EXEC "libxl/disable_udev"

#define DOMAIN_PATH "/local/domain/0"

#ifndef XEN_SCRIPT_DIR
#error XEN_SCRIPT_DIR not defined
#endif

#ifndef VBD_SCRIPT
#define VBD_SCRIPT XEN_SCRIPT_DIR"/block"
#endif
#ifndef LOG_FILE
#define LOG_FILE "/var/log/xen/xenbackendd.log"
#endif
#ifndef PID_FILE
#define PID_FILE "/var/run/xenbackendd.pid"
#endif


struct xs_handle *xs;

int fflag = 0;
int dflag = 0;

const char *vbd_script = NULL;
const char *log_file = NULL;
const char *pidfile = NULL;

static void
dolog(int pri, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	fflush(stderr);
	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}

static void
dodebug(const char *fmt, ...)
{
	va_list ap;

	if (dflag == 0)
		return;
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	printf("\n");
	fflush(stdout);
}

static void
doexec(const char *cmd, const char *arg1, const char *arg2)
{
	dodebug("exec %s %s %s", cmd, arg1, arg2);
	switch(vfork()) {
	case -1:
		dolog(LOG_ERR, "can't vfork: %s", strerror(errno));
		break;
	case 0:
		execl(cmd, cmd, arg1, arg2, NULL);
		dolog(LOG_ERR, "can't exec %s: %s", cmd, strerror(errno));
		exit(EXIT_FAILURE);
		/* NOTREACHED */
		break;
	default:
		wait(NULL);
		break;
	}
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: %s [-d] [-f] [-l log_file] [-p pif_file] [-s vbd_script]\n",
	    getprogname());
	exit(EXIT_FAILURE);
}

static int
xen_setup(void)
{
	xs = xs_daemon_open();
	if (xs == NULL) {
		dolog(LOG_ERR,
		    "Failed to contact xenstore (%s).  Is it running?",
		    strerror(errno));
		goto out;
	}

	if (!xs_watch(xs, DOMAIN_PATH, "backend")) {
		dolog(LOG_ERR, "xenstore watch on backend fails.");
		goto out;
	}
	return 0;

 out:
	if (xs) {
		xs_daemon_close(xs);
		xs = NULL;
	}
	return -1;
}

int
main(int argc, char * const argv[])
{
	char **vec;
	unsigned int num;
	char *s;
	int state;
	char *sstate, *sdisable;
	char *p;
	char buf[80];
	int type;
	int ch;
	int debug_fd;
	FILE *pidfile_f;

	while ((ch = getopt(argc, argv, "dfl:p:s:")) != -1) {
		switch (ch) {
		case 'd':
			dflag = 1;
			break;
		case 'f':
			fflag = 1;
			break;
		case 'l':
			log_file = optarg;
			break;
		case 'p':
			pidfile = optarg;
		case 's':
			vbd_script = optarg;
			break;
		default:
			usage();
		}
	}

	if (vbd_script == NULL)
		vbd_script = VBD_SCRIPT;
	if (pidfile == NULL)
		pidfile = PID_FILE;
	if (log_file == NULL)
		log_file = LOG_FILE;

	openlog("xenbackendd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	if (fflag == 0) {
		/* open log file */
		debug_fd = open(log_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (debug_fd == -1) {
			dolog(LOG_ERR, "can't open %s: %s",
			    log_file, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (fflag == 0) {
		/* daemonize */
		pidfile_f = fopen(pidfile, "w");
		if (pidfile_f == NULL) {
			dolog(LOG_ERR, "can't open %s: %s",
			    pidfile, strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (daemon(0, 0) < 0) {
			dolog(LOG_ERR, "can't daemonize: %s",
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
		fprintf(pidfile_f, "%d\n", (int)getpid());
		fclose(pidfile_f);

		/* redirect stderr to log file */
		if (dup2(debug_fd, STDERR_FILENO) < 0) {
			dolog(LOG_ERR, "can't redirect stderr to %s: %s\n",
			    log_file, strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* also redirect stdout if we're in debug mode */
		if (dflag) {
			if (dup2(debug_fd, STDOUT_FILENO) < 0) {
				dolog(LOG_ERR,
				    "can't redirect stdout to %s: %s\n",
				    log_file, strerror(errno));
				exit(EXIT_FAILURE);
			}
		}

		close(debug_fd);
		debug_fd = -1;
	}

	if (xen_setup() < 0)
		exit(EXIT_FAILURE);

	for (;;) {
		vec = xs_read_watch(xs, &num);
		dodebug("read from xen watch: %s", *vec);
		if (!vec) {
			dolog(LOG_ERR, "xs_read_watch: NULL\n");
			continue;
		}

		sdisable = xs_read(xs, XBT_NULL, DISABLE_EXEC, 0);
		if (sdisable)
			goto next1;

		if (strlen(vec[XS_WATCH_PATH]) < sizeof("state"))
			goto next1;

		/* find last component of path, check if it's "state" */
		p = &vec[XS_WATCH_PATH][
		    strlen(vec[XS_WATCH_PATH]) - sizeof("state")];
		if (p[0] != '/')
			goto next1;
		p[0] = '\0';
		p++;
		if (strcmp(p, "state") != 0)
			goto next1;

		snprintf(buf, sizeof(buf), "%s/state", vec[XS_WATCH_PATH]);
		sstate = xs_read(xs, XBT_NULL, buf, 0);
		if (sstate == NULL) {
			dolog(LOG_ERR,
			    "Failed to read %s (%s)", buf, strerror(errno));
			goto next1;
		}

		state = atoi(sstate);
		snprintf(buf, sizeof(buf), "%s/hotplug-status",
		    vec[XS_WATCH_PATH]);
		s = xs_read(xs, XBT_NULL, buf, 0);
		if (s != NULL && state != 6 /* XenbusStateClosed */)
			goto next2;

		type = DEVTYPE_UNKNOWN;
		if (strncmp(vec[XS_WATCH_PATH],
		    DOMAIN_PATH "/backend/vif",
		    strlen(DOMAIN_PATH "/backend/vif")) == 0)
			type = DEVTYPE_VIF;

		if (strncmp(vec[XS_WATCH_PATH],
		    DOMAIN_PATH "/backend/vbd",
		    strlen(DOMAIN_PATH "/backend/vbd")) == 0)
			type = DEVTYPE_VBD;

		switch(type) {
		case DEVTYPE_VIF:
			free(s);
			snprintf(buf, sizeof(buf), "%s/script",
			    vec[XS_WATCH_PATH]);
			s = xs_read(xs, XBT_NULL, buf, 0);
			if (s == NULL) {
				dolog(LOG_ERR,
				    "Failed to read %s (%s)", buf,
				    strerror(errno));
				goto next2;
			}
			doexec(s, vec[XS_WATCH_PATH], sstate);
			break;

		case DEVTYPE_VBD:
			doexec(vbd_script, vec[XS_WATCH_PATH], sstate);
			break;

		default:
			break;
		}

next2:
		free(s);
		free(sstate);

next1:
		free(sdisable);
		free(vec);
	}

	return 0;
}
