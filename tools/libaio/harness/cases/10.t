/* 10.t - uses testdir.enospc/rwfile
- Check results on out-of-space and out-of-quota. (10.t)
        - write that fills filesystem but does not go over should succeed
        - write that fills filesystem and goes over should be partial
        - write to full filesystem should return -ENOSPC
        - read beyond end of file after ENOSPC should return 0
*/
#include "aio_setup.h"

#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

int test_main(void)
{
/* Note: changing either of these requires updating the ext2-enospc.img
 * filesystem image.  Also, if SIZE is less than PAGE_SIZE, problems 
 * crop up due to ext2's preallocation.
 */
#define LIMIT	65536
#define SIZE	65536
	char *buf;
	int rwfd;
	int status = 0, res;

	rwfd = open("testdir.enospc/rwfile", O_RDWR|O_CREAT|O_TRUNC, 0600);
							assert(rwfd != -1);
	res = ftruncate(rwfd, 0);			assert(res == 0);
	buf = malloc(SIZE);				assert(buf != NULL);
	memset(buf, 0, SIZE);


	status |= attempt_rw(rwfd, buf, SIZE,   LIMIT-SIZE, WRITE, SIZE);
	status |= attempt_rw(rwfd, buf, SIZE,   LIMIT-SIZE,  READ, SIZE);

	status |= attempt_rw(rwfd, buf, SIZE,        LIMIT, WRITE, -ENOSPC);
	status |= attempt_rw(rwfd, buf, SIZE,        LIMIT,  READ,       0);

	res = ftruncate(rwfd, 0);			assert(res == 0);

	status |= attempt_rw(rwfd, buf, SIZE, 1+LIMIT-SIZE, WRITE, SIZE-1);
	status |= attempt_rw(rwfd, buf, SIZE, 1+LIMIT-SIZE,  READ, SIZE-1);
	status |= attempt_rw(rwfd, buf, SIZE,        LIMIT,  READ,      0);

	status |= attempt_rw(rwfd, buf, SIZE,        LIMIT, WRITE, -ENOSPC);
	status |= attempt_rw(rwfd, buf, SIZE,        LIMIT,  READ,       0);
	status |= attempt_rw(rwfd, buf,    0,        LIMIT, WRITE,       0);

	res = close(rwfd);				assert(res == 0);
	res = unlink("testdir.enospc/rwfile");		assert(res == 0);
	return status;
}

