/* 4.t
- read of descriptor without read permission (4.t)
- write to descriptor without write permission (4.t)
- check that O_APPEND writes actually append

*/
#include "aio_setup.h"

#define SIZE	512
#define READ	'r'
#define WRITE	'w'
int attempt(int fd, void *buf, int count, long long pos, int rw, int expect)
{
	struct iocb iocb;
	int res;

	switch(rw) {
	case READ:	io_prep_pread (&iocb, fd, buf, count, pos); break;
	case WRITE:	io_prep_pwrite(&iocb, fd, buf, count, pos); break;
	}

	printf("expect %3d: (%c), res = ", expect, rw);
	fflush(stdout);
	res = sync_submit(&iocb);
	printf("%3d [%s]%s\n", res, (res <= 0) ? strerror(-res) : "Success",
		(res != expect) ? " -- FAILED" : "");
	if (res != expect)
		return 1;

	return 0;
}

int test_main(void)
{
	char buf[SIZE];
	int rofd, wofd, rwfd;
	int	status = 0, res;

	memset(buf, 0, SIZE);

	rofd = open("testdir/rofile", O_RDONLY);	assert(rofd != -1);
	wofd = open("testdir/wofile", O_WRONLY);	assert(wofd != -1);
	rwfd = open("testdir/rwfile", O_RDWR);		assert(rwfd != -1);

	status |= attempt(rofd, buf, SIZE,  0, WRITE, -EBADF);
	status |= attempt(wofd, buf, SIZE,  0,  READ, -EBADF);
	status |= attempt(rwfd, buf, SIZE,  0, WRITE, SIZE);
	status |= attempt(rwfd, buf, SIZE,  0,  READ, SIZE);
	status |= attempt(rwfd, buf, SIZE, -1,  READ, -EINVAL);
	status |= attempt(rwfd, buf, SIZE, -1, WRITE, -EINVAL);

	rwfd = open("testdir/rwfile", O_RDWR|O_APPEND);	assert(rwfd != -1);
	res = ftruncate(rwfd, 0);			assert(res == 0);
	status |= attempt(rwfd, buf,    SIZE, 0,  READ, 0);
	status |= attempt(rwfd, "1234",    4, 0, WRITE, 4);
	status |= attempt(rwfd, "5678",    4, 0, WRITE, 4);
	memset(buf, 0, SIZE);
	status |= attempt(rwfd,    buf, SIZE, 0,  READ, 8);
	printf("read after append: [%s]\n", buf);
	assert(memcmp(buf, "12345678", 8) == 0);

	status |= attempt(rwfd, KERNEL_RW_POINTER, SIZE, 0,  READ, -EFAULT);
	status |= attempt(rwfd, KERNEL_RW_POINTER, SIZE, 0, WRITE, -EFAULT);

	/* Some architectures map the 0 page.  Ugh. */
#if !defined(__ia64__)
	status |= attempt(rwfd,              NULL, SIZE, 0, WRITE, -EFAULT);
#endif

	return status;
}

