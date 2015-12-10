/*
 * xentoollog.h
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

#ifndef XENTOOLLOG_H
#define XENTOOLLOG_H

#include <stdio.h>
#include <stdarg.h>


/*---------- common declarations and types ----------*/

typedef enum xentoollog_level {
    XTL_NONE, /* sentinel etc, never used for logging */
    XTL_DEBUG,
    XTL_VERBOSE,
    XTL_DETAIL,
    XTL_PROGRESS, /* also used for "progress" messages */
    XTL_INFO,
    XTL_NOTICE,
    XTL_WARN,
    XTL_ERROR,
    XTL_CRITICAL,
    XTL_NUM_LEVELS
} xentoollog_level;

typedef struct xentoollog_logger xentoollog_logger;
struct xentoollog_logger {
    void (*vmessage)(struct xentoollog_logger *logger,
                     xentoollog_level level,
                     int errnoval /* or -1 */,
                     const char *context /* eg "xc", "xl", may be 0 */,
                     const char *format /* without level, context, \n */,
                     va_list al)
         __attribute__((format(printf,5,0)));
    void (*progress)(struct xentoollog_logger *logger,
                     const char *context /* see above */,
                     const char *doing_what /* no \r,\n */,
                     int percent, unsigned long done, unsigned long total)
         /* null function pointer is ok.
          * will always be called with done==0 for each new
          * context/doing_what */;
    void (*destroy)(struct xentoollog_logger *logger);
    /* each logger can put its necessary data here */
};


/*---------- facilities for consuming log messages ----------*/

#define XTL_STDIOSTREAM_SHOW_PID            001u
#define XTL_STDIOSTREAM_SHOW_DATE           002u
#define XTL_STDIOSTREAM_HIDE_PROGRESS       004u
#define XTL_STDIOSTREAM_PROGRESS_USE_CR     010u /* default is to */
#define XTL_STDIOSTREAM_PROGRESS_NO_CR      020u /* use \r to ttys */

typedef struct xentoollog_logger_stdiostream  xentoollog_logger_stdiostream;

xentoollog_logger_stdiostream *xtl_createlogger_stdiostream
        (FILE *f, xentoollog_level min_level, unsigned flags);
    /* may return 0 if malloc fails, in which case error was logged */
    /* destroy on this logger does not close the file */

void xtl_stdiostream_set_minlevel(xentoollog_logger_stdiostream*,
                                  xentoollog_level min_level);
void xtl_stdiostream_adjust_flags(xentoollog_logger_stdiostream*,
                                  unsigned set_flags, unsigned clear_flags);
  /* if set_flags and clear_flags overlap, set_flags takes precedence */

void xtl_logger_destroy(struct xentoollog_logger *logger /* 0 is ok */);


/*---------- facilities for generating log messages ----------*/

void xtl_logv(struct xentoollog_logger *logger,
              xentoollog_level level,
              int errnoval /* or -1 */,
              const char *context /* eg "xc", "xenstore", "xl", may be 0 */,
              const char *format /* does not contain \n */,
              va_list) __attribute__((format(printf,5,0)));

void xtl_log(struct xentoollog_logger *logger,
             xentoollog_level level,
             int errnoval /* or -1 */,
             const char *context /* eg "xc", "xenstore", "xl" */,
             const char *format /* does not contain \n */,
             ...) __attribute__((format(printf,5,6)));

void xtl_progress(struct xentoollog_logger *logger,
                  const char *context /* see above, may be 0 */,
                  const char *doing_what,
                  unsigned long done, unsigned long total);


/*---------- facilities for defining log message consumers ----------*/

const char *xtl_level_to_string(xentoollog_level); /* never fails */


#define XTL_NEW_LOGGER(LOGGER,buffer) ({                                \
    xentoollog_logger_##LOGGER *new_consumer;                           \
                                                                        \
    (buffer).vtable.vmessage = LOGGER##_vmessage;                       \
    (buffer).vtable.progress = LOGGER##_progress;                       \
    (buffer).vtable.destroy  = LOGGER##_destroy;                        \
                                                                        \
    new_consumer = malloc(sizeof(*new_consumer));                       \
    if (!new_consumer) {                                                \
        xtl_log((xentoollog_logger*)&buffer,                            \
                XTL_CRITICAL, errno, "xtl",                             \
                "failed to allocate memory for new message logger");    \
    } else {                                                            \
        *new_consumer = buffer;                                         \
    }                                                                   \
                                                                        \
    new_consumer;                                                       \
});


#endif /* XENTOOLLOG_H */
