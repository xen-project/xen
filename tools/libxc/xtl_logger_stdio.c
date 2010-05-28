/*
 * xtl_logger_stdio.c
 *
 * log message consumer that writes to stdio
 *
 * Copyright (c) 2010 Citrix
 * Part of a generic logging interface used by various dom0 userland libraries.
 */

#include "xentoollog.h"

#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

struct xentoollog_logger_stdiostream {
    xentoollog_logger vtable;
    FILE *f;
    xentoollog_level min_level;
    unsigned flags;
    int progress_erase_len, progress_last_percent;
};

static void progress_erase(xentoollog_logger_stdiostream *lg) {
    if (lg->progress_erase_len)
        fprintf(lg->f, "\r%*s\r", lg->progress_erase_len, "");
}

static void stdiostream_vmessage(xentoollog_logger *logger_in,
                                 xentoollog_level level,
                                 int errnoval,
                                 const char *context,
                                 const char *format,
                                 va_list al) {
    xentoollog_logger_stdiostream *lg = (void*)logger_in;

    if (level < lg->min_level)
        return;

    progress_erase(lg);

    if (lg->flags & XTL_STDIOSTREAM_SHOW_DATE) {
        struct tm lt_buf;
        time_t now = time(0);
        struct tm *lt= localtime_r(&now, &lt_buf);
        fprintf(lg->f, "%04d-%02d-%02d %02d:%02d:%02d %s ",
                lt->tm_year+1900, lt->tm_mon+1, lt->tm_mday,
                lt->tm_hour, lt->tm_min, lt->tm_sec,
                tzname[daylight ? !!lt->tm_isdst : 0]);
    }
    if (lg->flags & XTL_STDIOSTREAM_SHOW_PID)
        fprintf(lg->f, "[%lu] ", (unsigned long)getpid());

    if (context)
        fprintf(lg->f, "%s: ", context);

    fprintf(lg->f, "%s: ", xtl_level_to_string(level));

    vfprintf(lg->f, format, al);

    if (errnoval >= 0)
        vfprintf(lg->f, ": %s", strerror(errnoval));

    putc('\n', lg->f);
    fflush(lg->f);
}

static void stdiostream_progress(struct xentoollog_logger *logger_in,
                                 const char *context,
                                 const char *doing_what, int percent,
                                 unsigned long done, unsigned long total) {
    xentoollog_logger_stdiostream *lg = (void*)logger_in;
    int newpel, extra_erase;
    xentoollog_level this_level;

    if (!(lg->flags & XTL_STDIOSTREAM_HIDE_PROGRESS))
        return;

    if (percent < lg->progress_last_percent) {
        this_level = XTL_PROGRESS;
    } else if (percent == lg->progress_last_percent) {
        return;
    } else if (percent < lg->progress_last_percent + 5) {
        this_level = XTL_DETAIL;
    } else {
        this_level = XTL_PROGRESS;
    }

    if (this_level < lg->min_level)
        return;

    if (lg->progress_erase_len)
        putc('\r', lg->f);

    newpel = fprintf(lg->f, "%s%s" "%s: %lu/%lu  %3d%%",
                     context?context:"", context?": ":"",
                     doing_what, done, total, percent);

    extra_erase = lg->progress_erase_len - newpel;
    if (extra_erase > 0)
        fprintf(lg->f, "%*s\r", extra_erase, "");

    lg->progress_erase_len = newpel;
}

static void stdiostream_destroy(struct xentoollog_logger *logger_in) {
    xentoollog_logger_stdiostream *lg = (void*)logger_in;
    progress_erase(lg);
    free(lg);
}

void xtl_stdiostream_set_minlevel(xentoollog_logger_stdiostream *lg,
                                  xentoollog_level min_level) {
    lg->min_level = min_level;
}

void xtl_stdiostream_adjust_flags(xentoollog_logger_stdiostream *lg,
                                  unsigned set_flags, unsigned clear_flags) {
    unsigned new_flags = (lg->flags & ~clear_flags) | set_flags;
    if (new_flags & XTL_STDIOSTREAM_HIDE_PROGRESS)
        progress_erase(lg);
    lg->flags = new_flags;
}

xentoollog_logger_stdiostream *xtl_createlogger_stdiostream
        (FILE *f, xentoollog_level min_level, unsigned flags) {
    xentoollog_logger_stdiostream newlogger;

    newlogger.f = f;
    newlogger.min_level = min_level;
    newlogger.flags = flags;

    if (newlogger.flags & XTL_STDIOSTREAM_SHOW_DATE) tzset();

    newlogger.progress_erase_len = 0;

    return XTL_NEW_LOGGER(stdiostream, newlogger);
}
