/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * xen-9pfsd - Xen 9pfs daemon
 *
 * Copyright (C) 2024 Juergen Gross <jgross@suse.com>
 *
 * Daemon to enable guests to access a directory of the dom0 file system.
 * Access is made via the 9pfs protocol (xen-9pfsd acts as a PV 9pfs backend).
 *
 * Usage: xen-9pfsd
 *
 * xen-9pfsd does NOT support writing any links (neither soft links nor hard
 * links), and it is accepting only canonicalized file paths in order to
 * avoid the possibility to "escape" from the guest specific directory.
 *
 * The backend device string is "xen_9pfs", the tag used for mounting the
 * 9pfs device is "Xen".
 *
 * As an additional security measure the maximum file space used by the guest
 * can be limited by the backend Xenstore node "max-size" specifying the size
 * in MBytes. This size includes the size of the root directory of the guest.
 */

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <xenevtchn.h>
#include <xengnttab.h>
#include <xenstore.h>

static volatile bool stop_me;
static bool daemon_running;
static struct xs_handle *xs;
static xengnttab_handle *xg;
static xenevtchn_handle *xe;

static void handle_stop(int sig)
{
    stop_me = true;
}

static void close_all(void)
{
    if ( daemon_running )
        xs_rm(xs, XBT_NULL, "libxl/xen-9pfs");
    if ( xe )
        xenevtchn_close(xe);
    if ( xg )
        xengnttab_close(xg);
    if ( xs )
        xs_close(xs);
    closelog();
}

static void do_err(const char *msg)
{
    syslog(LOG_ALERT, "%s, errno = %d, %s", msg, errno, strerror(errno));
    close_all();
    exit(1);
}

static void xen_connect(void)
{
    xs_transaction_t t;
    char *val;
    unsigned int len;

    xs = xs_open(0);
    if ( xs == NULL )
        do_err("xs_open() failed");

    xg = xengnttab_open(NULL, 0);
    if ( xg == NULL )
        do_err("xengnttab_open() failed");

    xe = xenevtchn_open(NULL, 0);
    if ( xe == NULL )
        do_err("xenevtchn_open() failed");

    while ( true )
    {
        t = xs_transaction_start(xs);
        if ( t == XBT_NULL )
            do_err("xs_transaction_start() failed");

        val = xs_read(xs, t, "libxl/xen-9pfs/state", &len);
        if ( val )
        {
            free(val);
            xs_transaction_end(xs, t, true);
            syslog(LOG_INFO, "daemon already running");
            close_all();
            exit(0);
        }

        if ( !xs_write(xs, t, "libxl/xen-9pfs/state", "running",
                       strlen("running")) )
        {
            xs_transaction_end(xs, t, true);
            do_err("xs_write() failed writing state");
        }

        if ( xs_transaction_end(xs, t, false) )
            break;
        if ( errno != EAGAIN )
            do_err("xs_transaction_end() failed");
    }

    daemon_running = true;
}

int main(int argc, char *argv[])
{
    struct sigaction act = { .sa_handler = handle_stop, };
    int syslog_mask = LOG_MASK(LOG_WARNING) | LOG_MASK(LOG_ERR) |
                      LOG_MASK(LOG_CRIT) | LOG_MASK(LOG_ALERT) |
                      LOG_MASK(LOG_EMERG);

    umask(027);
    if ( getenv("XEN_9PFSD_VERBOSE") )
        syslog_mask |= LOG_MASK(LOG_NOTICE) | LOG_MASK(LOG_INFO);
    openlog("xen-9pfsd", LOG_CONS, LOG_DAEMON);
    setlogmask(syslog_mask);

    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, NULL);

    xen_connect();

    while ( !stop_me )
    {
        sleep(60);
    }

    close_all();

    return 0;
}
