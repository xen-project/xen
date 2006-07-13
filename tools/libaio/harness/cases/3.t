/* 3.t
- io_submit/io_getevents with invalid addresses (3.t)

*/
#include "aio_setup.h"

int test_main(void)
{
	struct iocb a, b;
	struct iocb *good_ios[] = { &a, &b };
	struct iocb *bad1_ios[] = { NULL, &b };
	struct iocb *bad2_ios[] = { KERNEL_RW_POINTER, &a };
	int	status = 0;

	status |= attempt_io_submit(BAD_CTX, 1,   good_ios, -EINVAL);
	status |= attempt_io_submit( io_ctx, 0,   good_ios,       0);
	status |= attempt_io_submit( io_ctx, 1,       NULL, -EFAULT);
	status |= attempt_io_submit( io_ctx, 1, (void *)-1, -EFAULT);
	status |= attempt_io_submit( io_ctx, 2,   bad1_ios, -EFAULT);
	status |= attempt_io_submit( io_ctx, 2,   bad2_ios, -EFAULT);
	status |= attempt_io_submit( io_ctx, -1,  good_ios, -EINVAL);

	return status;
}

