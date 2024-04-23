
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

    if (argc < 2)
	errx(EXIT_FAILURE, "usage: %s <timeout> <sleep>", argv[0]);

    daemonize();

    h = xc_interface_open(NULL, NULL, 0);
    if (h == NULL)
	err(EXIT_FAILURE, "xc_interface_open");

    t = parse_secs(argv[1], "timeout");

    s = t / 2;
    if (argc == 3)
	s = parse_secs(argv[2], "sleep");

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
    xc_watchdog(h, id, safeexit ? 0 : 300);
    return 0;
}
