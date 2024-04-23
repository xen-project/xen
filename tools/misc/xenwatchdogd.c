/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xenwatchdogd.c
 *
 * Watchdog based on Xen hypercall watchdog interface.
 *
 * Copyright 2010 Citrix Ltd
 * Copyright 2024 Leigh Brown <leigh@solinno.co.uk>
 *
 */

#include <err.h>
#include <limits.h>
#include "xenctrl.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>

#define WDOG_MIN_TIMEOUT 2
#define WDOG_MIN_SLEEP 1
#define WDOG_EXIT_TIMEOUT 300

static xc_interface *h;
static volatile bool safeexit = false;
static volatile bool done = false;

static void daemonize(void)
{
    switch (fork()) {
    case -1:
	err(EXIT_FAILURE, "fork");
    case 0:
	break;
    default:
	exit(EXIT_SUCCESS);
    }
    umask(0);
    if (setsid() < 0)
	err(EXIT_FAILURE, "setsid");
    if (chdir("/") < 0)
	err(EXIT_FAILURE, "chdir /");
    if (freopen("/dev/null", "r", stdin) == NULL)
        err(EXIT_FAILURE, "reopen stdin");
    if(freopen("/dev/null", "w", stdout) == NULL)
        err(EXIT_FAILURE, "reopen stdout");
    if(freopen("/dev/null", "w", stderr) == NULL)
        err(EXIT_FAILURE, "reopen stderr");
}

static void catch_exit(int sig)
{
    done = true;
}

static void catch_usr1(int sig)
{
    safeexit = true;
    done = true;
}

static void __attribute__((noreturn)) usage(int exit_code)
{
    FILE *out = exit_code ? stderr : stdout;

    fprintf(out,
	"Usage: xenwatchdog [OPTION]... <timeout> [<sleep>]\n"
	"  -h, --help\t\tDisplay this help text and exit.\n"
	"  -F, --foreground\tRun in foreground.\n"
	"  -x, --safe-exit\tDisable watchdog on orderly exit.\n"
	"\t\t\tNote: default is to set a %d second timeout on exit.\n\n"
	"  timeout\t\tInteger seconds to arm the watchdog each time.\n"
	"\t\t\tNote: minimum timeout is %d seconds.\n\n"
	"  sleep\t\t\tInteger seconds to sleep between arming the watchdog.\n"
	"\t\t\tNote: sleep must be at least %d and less than timeout.\n"
	"\t\t\tIf not specified then set to half the timeout.\n",
	WDOG_EXIT_TIMEOUT, WDOG_MIN_TIMEOUT, WDOG_MIN_SLEEP
	);
    exit(exit_code);
}

static int parse_secs(const char *arg, const char *what)
{
    char *endptr;
    unsigned long val;

    val = strtoul(arg, &endptr, 0);
    if (val > INT_MAX || *endptr)
	errx(EXIT_FAILURE, "invalid %s: '%s'", what, arg);

    return val;
}

int main(int argc, char **argv)
{
    int id;
    int t, s;
    int ret;
    bool daemon = true;

    for ( ;; )
    {
	int option_index = 0, c;
	static const struct option long_options[] =
	{
	    { "help", no_argument, NULL, 'h' },
	    { "foreground", no_argument, NULL, 'F' },
	    { "safe-exit", no_argument, NULL, 'x' },
	    { NULL, 0, NULL, 0 },
	};

	c = getopt_long(argc, argv, "hFxD", long_options, &option_index);
	if (c == -1)
	    break;

	switch (c)
	{
	case 'h':
	    usage(EXIT_SUCCESS);

	case 'F':
	    daemon = false;
	    break;

	case 'x':
	    safeexit = true;
	    break;

	default:
	    usage(EXIT_FAILURE);
	}
    }

    if (argc - optind < 1)
	errx(EXIT_FAILURE, "timeout must be specified");

    if (argc - optind > 2)
	errx(EXIT_FAILURE, "too many arguments");

    t = parse_secs(argv[optind], "timeout");
    if (t < WDOG_MIN_TIMEOUT)
	errx(EXIT_FAILURE, "Error: timeout must be at least %d seconds",
			   WDOG_MIN_TIMEOUT);

    ++optind;
    if (optind < argc) {
	s = parse_secs(argv[optind], "sleep");
	if (s < WDOG_MIN_SLEEP)
	    errx(EXIT_FAILURE, "Error: sleep must be no less than %d",
			       WDOG_MIN_SLEEP);
	if (s >= t)
	    errx(EXIT_FAILURE, "Error: sleep must be less than timeout");
    }
    else
	s = t / 2;

    if (daemon)
	daemonize();

    h = xc_interface_open(NULL, NULL, 0);
    if (h == NULL)
	err(EXIT_FAILURE, "xc_interface_open");

    if (signal(SIGHUP, &catch_exit) == SIG_ERR)
	err(EXIT_FAILURE, "signal");
    if (signal(SIGINT, &catch_exit) == SIG_ERR)
	err(EXIT_FAILURE, "signal");
    if (signal(SIGQUIT, &catch_exit) == SIG_ERR)
	err(EXIT_FAILURE, "signal");
    if (signal(SIGTERM, &catch_exit) == SIG_ERR)
	err(EXIT_FAILURE, "signal");
    if (signal(SIGUSR1, &catch_usr1) == SIG_ERR)
	err(EXIT_FAILURE, "signal");

    id = xc_watchdog(h, 0, t);
    if (id <= 0)
        err(EXIT_FAILURE, "xc_watchdog setup");

    while (!done) {
        sleep(s);
        ret = xc_watchdog(h, id, t);
        if (ret != 0)
            err(EXIT_FAILURE, "xc_watchdog");
    }

    // Zero seconds timeout will disarm the watchdog timer
    xc_watchdog(h, id, safeexit ? 0 : WDOG_EXIT_TIMEOUT);
    return 0;
}
