/* Written by Anthony Liguori <aliguori@us.ibm.com> */

#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <stdlib.h>
#include <err.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PACKAGE_NAME "procpipe"
#define PACKAGE_VERSION "0.0.1"

#define GPL_SHORT \
"This is free software; see the source for copying conditions.  There is NO\n"\
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."

#define PACKAGE_BUGS "aliguori@us.ibm.com"
#define PACKAGE_AUTHOR "Anthony Liguori"
#define PACKAGE_OWNER "IBM, Corp."
#define PACKAGE_LICENSE GPL_SHORT

static void usage(const char *name)
{
	printf("Usage: %s [OPTIONS]\n"
	       "\n"
	       "  -h, --help      display this help and exit\n"
	       "  -V, --version   output version information and exit\n"
	       "\n"
	       "Report bugs to <%s>.\n"
	       , name, PACKAGE_BUGS);
}

static void version(const char *name)
{
	printf("%s (%s) %s\n"
	       "Written by %s.\n"
	       "\n"
	       "Copyright (C) 2005 %s.\n"
	       "%s\n"
	       , name, PACKAGE_NAME, PACKAGE_VERSION,
	       PACKAGE_AUTHOR, PACKAGE_OWNER, PACKAGE_LICENSE);
}

static pid_t exec(int stdout, int stdin, const char *cmd)
{
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		close(STDOUT_FILENO);
		dup2(stdout, STDOUT_FILENO);
		close(STDIN_FILENO);
		dup2(stdin, STDIN_FILENO);

		execlp("/bin/sh", "sh", "-c", cmd, NULL);
	}

	return pid;
}

int main(int argc, char **argv)
{
	int ch, opt_ind = 0;
	const char *sopt = "hV";
	struct option lopt[] = {
		{ "help", 0, 0, 'h' },
		{ "version", 0, 0, 'V' },
		{ 0 }
	};
	int host_stdout[2];
	int host_stdin[2];
	int res;
	pid_t pid1, pid2;
	int status;

	while ((ch = getopt_long(argc, argv, sopt, lopt, &opt_ind)) != -1) {
		switch (ch) {
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'V':
			version(argv[0]);
			exit(0);
		case '?':
			errx(EINVAL, "Try `%s --help' for more information.",
			     argv[0]);
		}
	}

	if ((argc - optind) != 2) {
		errx(EINVAL, "Two commands are required.\n"
		     "Try `%s --help' for more information.", argv[0]);
	}

	res = pipe(host_stdout);
	if (res == -1) {
		err(errno, "pipe() failed");
	}

	res = pipe(host_stdin);
	if (res == -1) {
		err(errno, "pipe() failed");
	}

	pid1 = exec(host_stdout[1], host_stdin[0], argv[optind]);
	if (pid1 == -1) {
		err(errno, "exec(%s)", argv[optind]);
	}

	pid2 = exec(host_stdin[1], host_stdout[0], argv[optind + 1]);
	if (pid2 == -1) {
		err(errno, "exec(%s)", argv[optind + 1]);
	}

	waitpid(pid1, &status, 0);
	if (WIFEXITED(status)) status = WEXITSTATUS(status);

	if (status != 0) {
		printf("Child exited with status %d\n", status);
	}

	waitpid(pid2, &status, 0);
	if (WIFEXITED(status)) status = WEXITSTATUS(status);

	if (status != 0) {
		printf("Child2 exited with status %d\n", status);
	}

	return 0;
}
