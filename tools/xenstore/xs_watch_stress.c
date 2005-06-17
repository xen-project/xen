/* Stress test for watch code: two processes communicating by watches */
#include "xs.h"
#include "utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc __attribute__((unused)), char *argv[])
{
	int childpid, status, fds[2];
	bool parent;
	unsigned int i, acks = 0;
	struct xs_handle *h;
	char *data;
	unsigned int len;
	const char *path, *otherpath;

	pipe(fds);
	childpid = fork();
	if (childpid == -1)
		barf_perror("Failed fork");
	parent = (childpid != 0);

	h = xs_daemon_open();
	if (!h)
		barf_perror("Could not connect to daemon");

	if (!xs_watch(h, "/", "token", 0))
		barf_perror("Could not set watch");

	if (parent) {
		char c;

		if (read(fds[0], &c, 1) != 1)
			barf("Child exited");

		path = "/parent";
		otherpath = "/child";
		/* Create initial node. */
		if (!xs_write(h, path, "0", 2, O_CREAT))
			barf_perror("Write to %s failed", path);
	} else {
		path = "/child";
		otherpath = "/parent";

		if (write(fds[1], "", 1) != 1)
			barf_perror("Write to parent failed");
	}

	for (i = 0; i < (argv[1] ? (unsigned)atoi(argv[1]) : 100);) {
		char **vec;

		vec = xs_read_watch(h);
		if (!vec)
			barf_perror("Read watch failed");

		if (!streq(vec[1], "token"))
			barf("Watch token %s bad", vec[1]);
		if (streq(vec[0], otherpath)) {
			char number[32];

			data = xs_read(h, otherpath, &len);
			if (!data)
				barf_perror("reading %s", otherpath);
			sprintf(number, "%i", atoi(data) + 1);
			free(data);
			if (!xs_write(h, path, number, strlen(number) + 1,
				      O_CREAT))
				barf_perror("writing %s", path);
			i++;
		} else if (!streq(vec[0], path))
			barf_perror("Watch fired on unknown path %s", vec[0]);
		xs_acknowledge_watch(h, vec[1]);
		acks++;
		free(vec);
	}

	if (!parent) {
		while (acks != 2 * i - 1) {
			char **vec;
			vec = xs_read_watch(h);
			if (!vec)
				barf_perror("Watch failed");
			if (!streq(vec[0], path))
				barf_perror("Watch fired path %s", vec[0]);
			if (!streq(vec[1], "token"))
				barf("Watch token %s bad", vec[1]);
			free(vec);

			printf("Expect %i events, only got %i\n",
			       2 * i - 1, acks);
			acks++;
		}
		exit(0);
	}

	if (acks != 2 * i)
		barf("Parent got %i watch events\n", acks);

	printf("Waiting for %i\n", childpid);
	if (waitpid(childpid, &status, 0) != childpid)
		barf_perror("Child wait failed");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		barf_perror("Child status %i", status);

	data = xs_read(h, path, &len);
	if (atoi(data) != 2 * (int)i)
		barf("%s count is %s\n", path, data);
	free(data);
	data = xs_read(h, otherpath, &len);
	if (atoi(data) != 2 * (int)i - 1)
		barf("%s count is %s\n", otherpath, data);
	free(data);
	printf("Success!\n");
	exit(0);
}
