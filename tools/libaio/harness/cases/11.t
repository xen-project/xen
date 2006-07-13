/* 11.t - uses testdir/rwfile
- repeated read / write of same page (to check accounting) (11.t)
*/
#include "aio_setup.h"

#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

int test_main(void)
{
#define COUNT	1000000
#define SIZE	256
	char *buf;
	int rwfd;
	int status = 0;
	int i;

	rwfd = open("testdir/rwfile", O_RDWR|O_CREAT|O_TRUNC, 0600);
							assert(rwfd != -1);
	buf = malloc(SIZE);				assert(buf != NULL);
	memset(buf, 0, SIZE);

	for (i=0; i<COUNT; i++) {
		status |= attempt_rw(rwfd, buf, SIZE, 0, WRITE_SILENT, SIZE);
		if (status)
			break;
	}
	printf("completed %d out of %d writes\n", i, COUNT);
	for (i=0; i<COUNT; i++) {
		status |= attempt_rw(rwfd, buf, SIZE, 0, READ_SILENT, SIZE);
		if (status)
			break;
	}
	printf("completed %d out of %d reads\n", i, COUNT);

	return status;
}

