#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void *
xmalloc(size_t s)
{
	void *x;

	x = malloc(s);
	if (x == NULL)
		err(1, "allocating memory");
	memset(x, 0, s);
	return x;
}

void *
xrealloc(void *x, size_t s)
{
	void *y;
	y = realloc(x, s);
	if (y == NULL)
		err(1, "allocating more memory");
	return y;
}

char *
xstrdup(const char *s)
{
	char *x = strdup(s);
	if (x == NULL)
		err(1, "duplicating %s", s);
	return x;
}

/* Slightly less stupid implementation of system().  We return
   negative iff there is an error executing the shell; otherwise, we
   return the wait status as reported by waitpid(). Also, we support
   printf-style escapes.  We don't handle setting the SIGCHLD handler
   to SIGIGN, though: in that case, we have a race. */
int
our_system(const char *fmt, ...)
{
	char *cmd = NULL;
	int r;
	va_list ap;
	pid_t child = -1;
	int pip[2] = {-1, -1};
	int e;
	fd_set fds;
	struct timeval to;
	int res;
	pid_t c;
	unsigned status;

	va_start(ap, fmt);
	r = vasprintf(&cmd, fmt, ap);
	va_end(ap);
	if (r < 0)
		return r;
	r = pipe(pip);
	if (r < 0) {
		res = r;
		goto out;
	}
	child = fork();
	if (child < 0) {
		res = child;
		goto out;
	}
	if (child == 0) {
		close(pip[0]);
		fcntl(pip[1], F_SETFD, 1);
		r = execl("/bin/sh", "/bin/sh", "-c", cmd, NULL);
		/* Uh oh, exec failed */
		write(pip[1], &r, sizeof(r));
		_exit(1);
	}

	close(pip[1]);
	pip[1] = -1;

	c = waitpid(child, &status, 0);
	if (c < 0) {
		res = c;
		goto out;
	}
	assert(c == child);
	child = -1;

	/* Check execl result */
	FD_ZERO(&fds);
	FD_SET(pip[0], &fds);
	memset(&to, 0, sizeof(to));
	r = select(pip[0]+1, &fds, NULL, NULL, &to);
	if (r == 0) {
		res = status;
	} else {
		assert(FD_ISSET(pip[0], &fds));
		r = read(pip[0], &res, sizeof(res));
		if (r != sizeof(res))
			res = status;
	}
	close(pip[0]);
	pip[0] = -1;

 out:
	e = errno;
	if (child >= 0) {
		/* Not obvious what the correct thing to do here is. */
		/* Don't want to kill the child; that will create a
		   zombie. */
//		kill(child, 9);
	}
	if (pip[0] >= 0)
		close(pip[0]);
	if (pip[1] >= 0)
		close(pip[1]);
	free(cmd);
	errno = e;
	return res;
}
