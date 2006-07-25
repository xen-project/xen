/* 12.t
- ioctx access across fork() (12.t)
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#include "aio_setup.h"

void test_child(void)
{
	int res;
	res = attempt_io_submit(io_ctx, 0, NULL, -EINVAL);
	fflush(stdout);
	_exit(res);
}

int test_main(void)
{
	int res, status;
	pid_t pid;

	if (attempt_io_submit(io_ctx, 0, NULL, 0))
		return 1;

	sigblock(sigmask(SIGCHLD) | siggetmask());
	fflush(NULL);
	pid = fork();				assert(pid != -1);

	if (pid == 0)
		test_child();

	res = waitpid(pid, &status, 0);

	if (WIFEXITED(status)) {
		int failed = (WEXITSTATUS(status) != 0);
		printf("child exited with status %d%s\n", WEXITSTATUS(status),
			failed ? " -- FAILED" : "");
		return failed;
	}

	/* anything else: failed */
	if (WIFSIGNALED(status))
		printf("child killed by signal %d -- FAILED.\n",
			WTERMSIG(status));

	return 1;
}
