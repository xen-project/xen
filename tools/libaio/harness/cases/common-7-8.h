/* common-7-8.h
*/
#include "aio_setup.h"

#include <unistd.h>

#define SIZE	512

int test_main(void)
{
	char *buf;
	int rwfd;
	int status = 0, res;
	long long limit;

	rwfd = open(FILENAME, O_RDWR);		assert(rwfd != -1);
	res = ftruncate(rwfd, 0);			assert(res == 0);
	buf = malloc(SIZE);				assert(buf != NULL);
	memset(buf, 0, SIZE);

	limit = LIMIT;

	SET_RLIMIT(limit);

	status |= attempt_rw(rwfd, buf, SIZE,   limit-SIZE, WRITE, SIZE);
	status |= attempt_rw(rwfd, buf, SIZE,   limit-SIZE,  READ, SIZE);

	status |= attempt_rw(rwfd, buf, SIZE, 1+limit-SIZE, WRITE, SIZE-1);
	status |= attempt_rw(rwfd, buf, SIZE, 1+limit-SIZE,  READ, SIZE-1);

	status |= attempt_rw(rwfd, buf, SIZE,        limit, WRITE, -EFBIG);
	status |= attempt_rw(rwfd, buf, SIZE,        limit,  READ,      0);
	status |= attempt_rw(rwfd, buf,    0,        limit, WRITE,      0);

	return status;
}

