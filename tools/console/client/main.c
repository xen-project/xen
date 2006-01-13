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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <termios.h>
#include <signal.h>
#include <getopt.h>
#include <sys/select.h>
#include <err.h>
#include <errno.h>
#include <pty.h>

#include "xenctrl.h"
#include "xs.h"

#define ESCAPE_CHARACTER 0x1d

static volatile sig_atomic_t received_signal = 0;

static void sighandler(int signum)
{
	received_signal = 1;
}

static bool write_sync(int fd, const void *data, size_t size)
{
	size_t offset = 0;
	ssize_t len;

	while (offset < size) {
		len = write(fd, data + offset, size - offset);
		if (len < 1) {
			return false;
		}
		offset += len;
	}

	return true;
}

static void usage(const char *program) {
	printf("Usage: %s [OPTION] DOMID\n"
	       "Attaches to a virtual domain console\n"
	       "\n"
	       "  -h, --help       display this help and exit\n"
	       , program);
}

/* don't worry too much if setting terminal attributes fail */
static void init_term(int fd, struct termios *old)
{
	struct termios new_term;

	if (tcgetattr(fd, old) == -1) {
		return;
	}

	new_term = *old;
	cfmakeraw(&new_term);

	tcsetattr(fd, TCSAFLUSH, &new_term);
}

static void restore_term(int fd, struct termios *old)
{
	tcsetattr(fd, TCSAFLUSH, old);
}

static int console_loop(int xc_handle, domid_t domid, int fd)
{
	int ret;

	do {
		fd_set fds;

		FD_ZERO(&fds);
		FD_SET(STDIN_FILENO, &fds);
		FD_SET(fd, &fds);

		ret = select(fd + 1, &fds, NULL, NULL, NULL);
		if (ret == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			return -1;
		}

		if (FD_ISSET(STDIN_FILENO, &fds)) {
			ssize_t len;
			char msg[60];

			len = read(STDIN_FILENO, msg, sizeof(msg));
			if (len == 1 && msg[0] == ESCAPE_CHARACTER) {
				return 0;
			} 

			if (len == 0 || len == -1) {
				if (len == -1 &&
				    (errno == EINTR || errno == EAGAIN)) {
					continue;
				}
				return -1;
			}

			if (!write_sync(fd, msg, len)) {
				perror("write() failed");
				return -1;
			}
		}

		if (FD_ISSET(fd, &fds)) {
			ssize_t len;
			char msg[512];

			len = read(fd, msg, sizeof(msg));
			if (len == 0 || len == -1) {
				if (len == -1 &&
				    (errno == EINTR || errno == EAGAIN)) {
					continue;
				}
				return -1;
			}

			if (!write_sync(STDOUT_FILENO, msg, len)) {
				perror("write() failed");
				return -1;
			}
		}
	} while (received_signal == 0);

	return 0;
}

int main(int argc, char **argv)
{
	struct termios attr;
	int domid;
	int xc_handle;
	char *sopt = "h";
	int ch;
	int opt_ind=0;
	struct option lopt[] = {
		{ "help",    0, 0, 'h' },
		{ 0 },

	};
	char *str_pty, *path;
	int spty;
	unsigned int len = 0;
	struct xs_handle *xs;
	char *end;
	time_t now;

	while((ch = getopt_long(argc, argv, sopt, lopt, &opt_ind)) != -1) {
		switch(ch) {
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		}
	}
	
	if ((argc - optind) != 1) {
		fprintf(stderr, "Invalid number of arguments\n");
		fprintf(stderr, "Try `%s --help' for more information.\n", 
			argv[0]);
		exit(EINVAL);
	}
	
	domid = strtol(argv[optind], &end, 10);
	if (end && *end) {
		fprintf(stderr, "Invalid DOMID `%s'\n", argv[optind]);
		fprintf(stderr, "Try `%s --help' for more information.\n",
			argv[0]);
		exit(EINVAL);
	}

	xs = xs_daemon_open();
	if (xs == NULL) {
		err(errno, "Could not contact XenStore");
	}

	xc_handle = xc_interface_open();
	if (xc_handle == -1) {
		err(errno, "xc_interface_open()");
	}
	
	signal(SIGTERM, sighandler);

	path = xs_get_domain_path(xs, domid);
	if (path == NULL)
		err(errno, "xs_get_domain_path()");
	path = realloc(path, strlen(path) + strlen("/console/tty") + 1);
	if (path == NULL)
		err(ENOMEM, "realloc");
	strcat(path, "/console/tty");
	str_pty = xs_read(xs, XBT_NULL, path, &len);

	/* FIXME consoled currently does not assume domain-0 doesn't have a
	   console which is good when we break domain-0 up.  To keep us
	   user friendly, we'll bail out here since no data will ever show
	   up on domain-0. */
	if (domid == 0) {
		err(errno, "Could not read tty from store");
	}

	/* Wait a little bit for tty to appear.  There is a race
	   condition that occurs after xend creates a domain.  This
	   code might be running before consoled has noticed the new
	   domain and setup a pty for it.

	   A xenstore watch would slightly improve responsiveness but
	   a timeout would still be needed since we don't want to
	   block forever if given an invalid domain or worse yet, a
	   domain that someone else has connected to. */

	now = time(0);
	while (str_pty == NULL && (now + 5) > time(0)) {
		struct timeval tv = { 0, 500 };
		select(0, NULL, NULL, NULL, &tv); /* pause briefly */

		str_pty = xs_read(xs, XBT_NULL, path, &len);
	}

	if (str_pty == NULL) {
		err(errno, "Could not read tty from store");
	}

	spty = open(str_pty, O_RDWR | O_NOCTTY);
	if (spty == -1) {
		err(errno, "Could not open tty `%s'", str_pty);
	}
	free(str_pty);
	free(path);

	init_term(STDIN_FILENO, &attr);
	console_loop(xc_handle, domid, spty);
	restore_term(STDIN_FILENO, &attr);

	return 0;
 }
