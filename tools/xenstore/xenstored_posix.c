/* 
    Simple prototype Xen Store Daemon providing simple tree-like database.
    Copyright (C) 2005 Rusty Russell IBM Corporation

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "utils.h"
#include "xenstored_core.h"

void write_pidfile(const char *pidfile)
{
	char buf[100];
	int len;
	int fd;

	fd = open(pidfile, O_RDWR | O_CREAT, 0600);
	if (fd == -1)
		barf_perror("Opening pid file %s", pidfile);

	/* We exit silently if daemon already running. */
	if (lockf(fd, F_TLOCK, 0) == -1)
		exit(0);

	len = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
	if (write(fd, buf, len) != len)
		barf_perror("Writing pid file %s", pidfile);

	close(fd);
}

/* Stevens. */
void daemonize(void)
{
	pid_t pid;

	/* Separate from our parent via fork, so init inherits us. */
	if ((pid = fork()) < 0)
		barf_perror("Failed to fork daemon");
	if (pid != 0)
		exit(0);

	/* Session leader so ^C doesn't whack us. */
	setsid();

	/* Let session leader exit so child cannot regain CTTY */
	if ((pid = fork()) < 0)
		barf_perror("Failed to fork daemon");
	if (pid != 0)
		exit(0);

	/* Move off any mount points we might be in. */
	if (chdir("/") == -1)
		barf_perror("Failed to chdir");

	/* Discard our parent's old-fashioned umask prejudices. */
	umask(0);
}

void finish_daemonize(void)
{
	int devnull = open("/dev/null", O_RDWR);
	if (devnull == -1)
		barf_perror("Could not open /dev/null\n");
	dup2(devnull, STDIN_FILENO);
	dup2(devnull, STDOUT_FILENO);
	dup2(devnull, STDERR_FILENO);
	close(devnull);
	xprintf = trace;
}

void init_pipe(int reopen_log_pipe[2])
{
	if (pipe(reopen_log_pipe)) {
		barf_perror("pipe");
	}
}

void unmap_xenbus(void *interface)
{
	munmap(interface, getpagesize());
}
