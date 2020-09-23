#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include "libxl.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

void test_common_setup(int level);

extern libxl_ctx *ctx;

void test_common_get_now(void);

extern struct timeval now;

void test_common_beforepoll(void);
void test_common_dopoll(void);
void test_common_afterpoll(void);

extern int poll_nfds, poll_nfds_allocd;
extern struct pollfd *poll_fds;
extern int poll_timeout;

#endif /*TEST_COMMON_H*/
