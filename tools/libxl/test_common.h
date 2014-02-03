#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include "libxl.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

void test_common_setup(int level);

extern libxl_ctx *ctx;

#endif /*TEST_COMMON_H*/
