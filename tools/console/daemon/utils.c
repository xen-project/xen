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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <signal.h>

#include "xenctrl.h"
#include "utils.h"

struct xs_handle *xs;
xc_interface *xc;

static void child_exit(int sig)
{
	while (waitpid(-1, NULL, WNOHANG) > 0);
}

void daemonize(const char *pidfile)
{
	pid_t pid;
	int fd;
	int len;
	int i;
	char buf[100];

	if (getppid() == 1) {
		return;
	}

	if ((pid = fork()) > 0) {
		exit(0);
	} else if (pid == -1) {
		err(errno, "fork() failed");
	}

	setsid();

	if ((pid = fork()) > 0) {
		exit(0);
	} else if (pid == -1) {
		err(errno, "fork() failed");
	}

	/* redirect fd 0,1,2 to /dev/null */
	if ((fd = open("/dev/null",O_RDWR)) == -1) {
		exit(1);
	}

	for (i = 0; i <= 2; i++) {
		close(i);
		dup2(fd, i);
	}

	close(fd);

	umask(027);
	if (chdir("/") < 0)
		exit (1);

	fd = open(pidfile, O_RDWR | O_CREAT, S_IRUSR|S_IWUSR);
	if (fd == -1) {
		exit(1);
	}

	if (lockf(fd, F_TLOCK, 0) == -1) {
		exit(1);
	}

	len = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
	if (write(fd, buf, len) < 0)
		exit(1);

	signal(SIGCHLD, child_exit);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	close(fd);
}

bool xen_setup(void)
{
	
	xs = xs_daemon_open();
	if (xs == NULL) {
		dolog(LOG_ERR,
		      "Failed to contact xenstore (%m).  Is it running?");
		goto out;
	}

	xc = xc_interface_open(0,0,0);
	if (!xc) {
		dolog(LOG_ERR, "Failed to contact hypervisor (%m)");
		goto out;
	}

	if (!xs_watch(xs, "@introduceDomain", "domlist")) {
		dolog(LOG_ERR, "xenstore watch on @introduceDomain fails.");
		goto out;
	}

	if (!xs_watch(xs, "@releaseDomain", "domlist")) {
		dolog(LOG_ERR, "xenstore watch on @releaseDomain fails.");
		goto out;
	}

	return true;

 out:
	if (xs)
		xs_daemon_close(xs);
	if (xc)
		xc_interface_close(xc);
	return false;
}

