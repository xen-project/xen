/* 
    Xen Store Daemon Speed test
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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "utils.h"
#include "xs.h"
#include "list.h"
#include "talloc.h"

static void do_command(const char *cmd)
{
	int ret;

	ret = system(cmd);
	if (ret == -1 || !WIFEXITED(ret) || WEXITSTATUS(ret) != 0)
		barf_perror("Failed '%s': %i", cmd, ret);
}

static int start_daemon(void)
{
	int fds[2], pid;

	do_command(talloc_asprintf(NULL, "rm -rf testsuite/tmp/*"));

	/* Start daemon. */
	pipe(fds);
	if ((pid = fork())) {
		/* Child writes PID when its ready: we wait for that. */
		char buffer[20];
		close(fds[1]);
		if (read(fds[0], buffer, sizeof(buffer)) < 0)
			barf("Failed to summon daemon");
		close(fds[0]);
	} else {
		dup2(fds[1], STDOUT_FILENO);
		close(fds[0]);
#if 0
		execlp("valgrind", "valgrind", "-q", "--suppressions=testsuite/vg-suppressions", "xenstored_test", "--output-pid",
		       "--no-fork", "--trace-file=/tmp/trace", NULL);
#else
		execlp("./xenstored_test", "xenstored_test", "--output-pid", "--no-fork", NULL);
//		execlp("strace", "strace", "-o", "/tmp/out", "./xenstored_test", "--output-pid", "--no-fork", NULL);
#endif
		exit(1);
	}
	return pid;
}

static void kill_daemon(int pid)
{
	int saved_errno = errno;
	kill(pid, SIGTERM);
	errno = saved_errno;
}

#define NUM_ENTRIES 50

/* We create the given number of trees, each with NUM_ENTRIES, using
 * transactions. */
int main(int argc, char *argv[])
{
	int i, j, pid, print;
	struct xs_handle *h;

	if (argc != 2)
		barf("Usage: speedtest <numdomains>");

	pid = start_daemon();
	h = xs_daemon_open();
	print = atoi(argv[1]) / 76;
	if (!print)
		print = 1;
	for (i = 0; i < atoi(argv[1]); i ++) {
		char name[64];

		if (i % print == 0)
			write(1, ".", 1);
		if (!xs_transaction_start(h)) {
			kill_daemon(pid);
			barf_perror("Starting transaction");
		}
		sprintf(name, "/%i", i);
		if (!xs_mkdir(h, name)) {
			kill_daemon(pid);
			barf_perror("Making directory %s", name);
		}

		for (j = 0; j < NUM_ENTRIES; j++) {
			sprintf(name, "/%i/%i", i, j);
			if (!xs_write(h, name, name, strlen(name))) {
				kill_daemon(pid);
				barf_perror("Making directory %s", name);
			}
		}
		if (!xs_transaction_end(h, false)) {
			kill_daemon(pid);
			barf_perror("Ending transaction");
		}
	}
	write(1, "\n", 1);

	kill_daemon(pid);
	wait(NULL);
	return 0;
}
	
	
