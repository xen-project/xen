/*
 * xtl_core.c
 *
 * core code including functions for generating log messages
 *
 * Copyright (c) 2010 Citrix
 * Part of a generic logging interface used by various dom0 userland libraries.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xentoollog.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>

static const char *level_strings[XTL_NUM_LEVELS]= {
    "[BUG:XTL_NONE]",
    "debug", "verbose", "detail",  /* normally off by default */
    "progress", "info", "notice",  /* not a problem */
    "warning", "error", "critical" /* problems and errors */
};

const char *xtl_level_to_string(xentoollog_level level) {
    assert(level >= 0 && level < XTL_NUM_LEVELS);
    return level_strings[level];
}

void xtl_logv(struct xentoollog_logger *logger,
              xentoollog_level level,
              int errnoval /* or -1 */,
              const char *context /* eg "xc", "xenstore", "xl" */,
              const char *format /* does not contain \n */,
              va_list al) {
    int errno_save = errno;
    assert(level > XTL_NONE && level < XTL_NUM_LEVELS);
    logger->vmessage(logger,level,errnoval,context,format,al);
    errno = errno_save;
}

void xtl_log(struct xentoollog_logger *logger,
             xentoollog_level level,
             int errnoval /* or -1 */,
             const char *context /* eg "xc", "xenstore", "xl" */,
             const char *format /* does not contain \n */,
             ...) {
    va_list al;
    va_start(al,format);
    xtl_logv(logger,level,errnoval,context,format,al);
    va_end(al);
}

void xtl_progress(struct xentoollog_logger *logger,
                  const char *context, const char *doing_what,
                  unsigned long done, unsigned long total) {
    int percent = 0;

    if (!logger->progress) return;

    if ( total )
        percent = (total < LONG_MAX/100)
            ? (done * 100) / total
            : done / ((total + 99) / 100);

    logger->progress(logger, context, doing_what, percent, done, total);
}

void xtl_logger_destroy(struct xentoollog_logger *logger) {
    if (!logger) return;
    logger->destroy(logger);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
