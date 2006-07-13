io_context_t	io_ctx;
#define BAD_CTX	((io_context_t)-1)

void aio_setup(int n)
{
	int res = io_queue_init(n, &io_ctx);
	if (res != 0) {
		printf("io_queue_setup(%d) returned %d (%s)\n",
			n, res, strerror(-res));
		exit(3);
	}
}

int attempt_io_submit(io_context_t ctx, long nr, struct iocb *ios[], int expect)
{
	int res;

	printf("expect %3d: io_submit(%10p, %3ld, %10p) = ", expect, ctx, nr, ios);
	fflush(stdout);
	res = io_submit(ctx, nr, ios);
	printf("%3d [%s]%s\n", res, (res <= 0) ? strerror(-res) : "",
		(res != expect) ? " -- FAILED" : "");
	if (res != expect)
		return 1;

	return 0;
}

int sync_submit(struct iocb *iocb)
{
	struct io_event event;
	struct iocb *iocbs[] = { iocb };
	int res;

	/* 30 second timeout should be enough */
	struct timespec	ts;
	ts.tv_sec = 30;
	ts.tv_nsec = 0;

	res = io_submit(io_ctx, 1, iocbs);
	if (res != 1) {
		printf("sync_submit: io_submit res=%d [%s]\n", res, strerror(-res));
		return res;
	}

	res = io_getevents(io_ctx, 0, 1, &event, &ts);
	if (res != 1) {
		printf("sync_submit: io_getevents res=%d [%s]\n", res, strerror(-res));
		return res;
	}
	return event.res;
}

#define SETUP	aio_setup(1024)


#define READ		'r'
#define WRITE		'w'
#define READ_SILENT	'R'
#define WRITE_SILENT	'W'
int attempt_rw(int fd, void *buf, int count, long long pos, int rw, int expect)
{
	struct iocb iocb;
	int res;
	int silent = 0;

	switch(rw) {
	case READ_SILENT:
		silent = 1;
	case READ:
		io_prep_pread (&iocb, fd, buf, count, pos);
		break;
	case WRITE_SILENT:
		silent = 1;
	case WRITE:
		io_prep_pwrite(&iocb, fd, buf, count, pos);
		break;
	}

	if (!silent) {
		printf("expect %5d: (%c), res = ", expect, rw);
		fflush(stdout);
	}
	res = sync_submit(&iocb);
	if (!silent || res != expect) {
		if (silent)
			printf("expect %5d: (%c), res = ", expect, rw);
		printf("%5d [%s]%s\n", res,
			(res <= 0) ? strerror(-res) : "Success",
			(res != expect) ? " -- FAILED" : "");
	}

	if (res != expect)
		return 1;

	return 0;
}

