#ifndef TEST_FDEVENT_H
#define TEST_FDEVENT_H

#include <pthread.h>

int libxl_test_fdevent(libxl_ctx *ctx, int fd, short events,
                       libxl_asyncop_how *ao_how)
                       LIBXL_EXTERNAL_CALLERS_ONLY;
/* This operation waits for one of the poll events to occur on fd, and
 * then completes successfully.  (Or, it can be aborted.) */

#endif /*TEST_FDEVENT_H*/
