#include "test_common.h"

libxl_ctx *ctx;

void test_common_setup(int level)
{
    xentoollog_logger_stdiostream *logger_s
        = xtl_createlogger_stdiostream(stderr, level,  0);
    assert(logger_s);

    xentoollog_logger *logger = (xentoollog_logger*)logger_s;

    int rc = libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, logger);
    assert(!rc);
}

struct timeval now;

void test_common_get_now(void)
{
    int r = gettimeofday(&now, 0);  assert(!r);
}

int poll_nfds, poll_nfds_allocd;
struct pollfd *poll_fds;
int poll_timeout;

void test_common_beforepoll(void)
{
    for (;;) {
        test_common_get_now();

        poll_timeout = -1;
        poll_nfds = poll_nfds_allocd;
        int rc = libxl_osevent_beforepoll(ctx, &poll_nfds, poll_fds,
                                          &poll_timeout, now);
        if (!rc) return;
        assert(rc == ERROR_BUFFERFULL);

        assert(poll_nfds > poll_nfds_allocd);
        poll_fds = realloc(poll_fds, poll_nfds * sizeof(poll_fds[0]));
        assert(poll_fds);
        poll_nfds_allocd = poll_nfds;
    }
}

void test_common_dopoll(void) {
    errno = 0;
    int r = poll(poll_fds, poll_nfds, poll_timeout);
    fprintf(stderr, "poll: r=%d errno=%s\n", r, strerror(errno));
}

void test_common_afterpoll(void)
{
    test_common_get_now();
    libxl_osevent_afterpoll(ctx, poll_nfds, poll_fds, now);
}
