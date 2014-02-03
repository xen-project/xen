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
