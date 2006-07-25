/* 2.t
- io_setup (#2)
        - with invalid context pointer
        - with maxevents <= 0
        - with an already initialized ctxp
*/

int attempt(int n, io_context_t *ctxp, int expect)
{
	int res;

	printf("expect %3d: io_setup(%5d, %p) = ", expect, n, ctxp);
	fflush(stdout);
	res = io_setup(n, ctxp);
	printf("%3d [%s]%s\n", res, strerror(-res), 
		(res != expect) ? " -- FAILED" : "");
	if (res != expect)
		return 1;

	return 0;
}

int test_main(void)
{
	io_context_t	ctx;
	int	status = 0;

	ctx = NULL;
	status |= attempt(-1000, KERNEL_RW_POINTER, -EFAULT);
	status |= attempt( 1000, KERNEL_RW_POINTER, -EFAULT);
	status |= attempt(    0, KERNEL_RW_POINTER, -EFAULT);
	status |= attempt(-1000, &ctx, -EINVAL);
	status |= attempt(   -1, &ctx, -EINVAL);
	status |= attempt(    0, &ctx, -EINVAL);
	assert(ctx == NULL);
	status |= attempt(    1, &ctx, 0);
	status |= attempt(    1, &ctx, -EINVAL);

	return status;
}

