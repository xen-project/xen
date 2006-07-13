#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#include "aio_setup.h"
#include <sys/mman.h>

#define SIZE 768*1024*1024

//just submit an I/O

int test_child(void)
{
        char *buf;
        int rwfd;
        int res;
        long size;
        struct iocb iocb;
        struct iocb *iocbs[] = { &iocb };
        int loop = 10;
        int i;

	aio_setup(1024);

        size = SIZE;

        printf("size = %ld\n", size);

        rwfd = open("testdir/rwfile", O_RDWR);          assert(rwfd != 
-1);
        res = ftruncate(rwfd, 0);                       assert(res == 0);
        buf = malloc(size);                             assert(buf != 
NULL);

        for(i=0;i<loop;i++) {

                switch(i%2) {
                case 0:
                        io_prep_pwrite(&iocb, rwfd, buf, size, 0);
                        break;
                case 1:
                        io_prep_pread(&iocb, rwfd, buf, size, 0);
                }

                res = io_submit(io_ctx, 1, iocbs);
                if (res != 1) {
                        printf("child: submit: io_submit res=%d [%s]\n", res, 
strerror(-res));
                        _exit(1);
                }
        }

        res = ftruncate(rwfd, 0);                       assert(res == 0);

        _exit(0);
}

/* from 12.t */
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
