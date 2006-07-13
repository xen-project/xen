/* 6.t
- huge reads (pinned pages) (6.t)
- huge writes (6.t)
*/
#include "aio_setup.h"
#include <sys/mman.h>

long getmemsize(void)
{
	FILE *f = fopen("/proc/meminfo", "r");
	long size;
	int gotit = 0;
	char str[256];

	assert(f != NULL);
	while (NULL != fgets(str, 255, f)) {
		str[255] = 0;
		if (0 == memcmp(str, "MemTotal:", 9)) {
			if (1 == sscanf(str + 9, "%ld", &size)) {
				gotit = 1;
				break;
			}
		}
	}
	fclose(f);

	assert(gotit != 0);
	return size;
}

int test_main(void)
{
	char *buf;
	int rwfd;
	int status = 0, res;
	long size;

	size = getmemsize();
	printf("size = %ld\n", size);
	assert(size >= (16 * 1024));
	if (size > (768 * 1024))
		size = 768 * 1024;
	size *= 1024;

	rwfd = open("testdir/rwfile", O_RDWR);		assert(rwfd != -1);
	res = ftruncate(rwfd, 0);			assert(res == 0);
	buf = malloc(size);				assert(buf != NULL);

	//memset(buf, 0, size);
	status |= attempt_rw(rwfd, buf, size,  0, WRITE, size);
	status |= attempt_rw(rwfd, buf, size,  0,  READ, size);

	//res = ftruncate(rwfd, 0);			assert(res == 0);

	return status;
}

