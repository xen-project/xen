/* 13.t - uses testdir/rwfile
- Submit multiple writes larger than aio-max-size (deadlocks on older
  aio code)
*/
#include "aio_setup.h"

#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

int test_main(void)
{
#define SIZE	(1024 * 1024)
#define IOS	8
	struct iocb	iocbs[IOS];
	struct iocb	*iocb_list[IOS];
	char *bufs[IOS];
	int rwfd;
	int status = 0, res;
	int i;

	rwfd = open("testdir/rwfile", O_RDWR|O_CREAT|O_TRUNC, 0600);
							assert(rwfd != -1);
	res = ftruncate(rwfd, 0);			assert(res == 0);

	for (i=0; i<IOS; i++) {
		bufs[i] = malloc(SIZE);
		assert(bufs[i] != NULL);
		memset(bufs[i], 0, SIZE);

		io_prep_pwrite(&iocbs[i], rwfd, bufs[i], SIZE, i * SIZE);
		iocb_list[i] = &iocbs[i];
	}

	status |= attempt_io_submit(io_ctx, IOS, iocb_list, IOS);

	for (i=0; i<IOS; i++) {
		struct timespec ts = { tv_sec: 30, tv_nsec: 0 };
		struct io_event event;
		struct iocb *iocb;

		res = io_getevents(io_ctx, 0, 1, &event, &ts);
		if (res != 1) {
			status |= 1;
			printf("io_getevents failed [%d] with res=%d [%s]\n",
				i, res, (res < 0) ? strerror(-res) : "okay");
			break;
		}

		if (event.res != SIZE)
			status |= 1;

		iocb = (void *)event.obj;
		printf("event[%d]: write[%d] %s, returned: %ld [%s]\n",
			i, (int)(iocb - &iocbs[0]),
			(event.res != SIZE) ? "failed" : "okay",
			(long)event.res,
			(event.res < 0) ? strerror(-event.res) : "okay"
			);
	}

	res = ftruncate(rwfd, 0);			assert(res == 0);
	res = close(rwfd);				assert(res == 0);
	return status;
}

