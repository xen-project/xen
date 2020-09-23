#include "test_common.h"
#include "libxl_test_fdevent.h"

int main(int argc, char **argv) {
    int rc, i;
    libxl_asyncop_how how;
    libxl_event *event;

    test_common_setup(XTL_DEBUG);

    how.callback = NULL;
    how.u.for_event = 1;

    int fd = open("/dev/null", O_RDONLY);
    assert(fd > 0);

    rc = libxl_test_fdevent(ctx, fd, POLLIN, &how);
    assert(!rc);

    test_common_beforepoll();

    rc = libxl_ao_abort(ctx, &how);
    assert(!rc);

    rc = libxl_event_check(ctx, &event, LIBXL_EVENTMASK_ALL, 0,0);
    assert(!rc);
    assert(event);
    assert(event->for_user == how.u.for_event);
    assert(event->type == LIBXL_EVENT_TYPE_OPERATION_COMPLETE);
    assert(event->u.operation_complete.rc == ERROR_ABORTED);

    close(fd);

    test_common_dopoll();

    for (i=0; i<poll_nfds; i++) {
        if (poll_fds[i].fd == fd && (poll_fds[i].revents & POLLNVAL)) {
            fprintf(stderr, "POLLNVAL on fd=%d in slot i=%d as expected\n",
                    fd, i);
            goto found;
        }
    }
    abort();
 found:;

    int fd2 = open("/dev/null", O_RDONLY);
    assert(fd2 == fd);

    how.u.for_event++;
    rc = libxl_test_fdevent(ctx, fd, POLLIN, &how);
    assert(!rc);

    test_common_afterpoll();

    fprintf(stderr, "complete\n");
}
