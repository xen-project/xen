/* 5.t
- Write from a mmap() of the same file. (5.t)
*/
#include "aio_setup.h"
#include <sys/mman.h>

int test_main(void)
{
	int page_size = getpagesize();
#define SIZE	512
	char *buf;
	int rwfd;
	int	status = 0, res;

	rwfd = open("testdir/rwfile", O_RDWR);		assert(rwfd != -1);
	res = ftruncate(rwfd, 512);			assert(res == 0);

	buf = mmap(0, page_size, PROT_READ|PROT_WRITE, MAP_SHARED, rwfd, 0);
	assert(buf != (char *)-1);

	status |= attempt_rw(rwfd, buf, SIZE,  0, WRITE, SIZE);
	status |= attempt_rw(rwfd, buf, SIZE,  0,  READ, SIZE);

	res = munmap(buf, page_size);			assert(res == 0);
	buf = mmap(0, page_size, PROT_READ|PROT_WRITE, MAP_SHARED, rwfd, 0);
	assert(buf != (char *)-1);

	status |= attempt_rw(rwfd, buf, SIZE,  0,  READ, SIZE);
	status |= attempt_rw(rwfd, buf, SIZE,  0, WRITE, SIZE);

	res = munmap(buf, page_size);			assert(res == 0);
	buf = mmap(0, page_size, PROT_READ, MAP_SHARED, rwfd, 0);
	assert(buf != (char *)-1);

	status |= attempt_rw(rwfd, buf, SIZE,  0, WRITE, SIZE);
	status |= attempt_rw(rwfd, buf, SIZE,  0,  READ, -EFAULT);

	res = munmap(buf, page_size);			assert(res == 0);
	buf = mmap(0, page_size, PROT_WRITE, MAP_SHARED, rwfd, 0);
	assert(buf != (char *)-1);

	status |= attempt_rw(rwfd, buf, SIZE,  0,  READ, SIZE);
	status |= attempt_rw(rwfd, buf, SIZE,  0, WRITE, -EFAULT);

	return status;
}

