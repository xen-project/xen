
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

xc_interface *h;
int id = 0;

void daemonize(void)
{
    switch (fork()) {
    case -1:
	err(1, "fork");
    case 0:
	break;
    default:
	exit(0);
    }
    umask(0);
    if (setsid() < 0)
	err(1, "setsid");
    if (chdir("/") < 0)
	err(1, "chdir /");
    if (freopen("/dev/null", "r", stdin) == NULL)
        err(1, "reopen stdin");
    if(freopen("/dev/null", "w", stdout) == NULL)
        err(1, "reopen stdout");
    if(freopen("/dev/null", "w", stderr) == NULL)
        err(1, "reopen stderr");
}

void catch_exit(int sig)
{
    if (id)
        xc_watchdog(h, id, 300);
    exit(0);
}

void catch_usr1(int sig)
{
    if (id)
        xc_watchdog(h, id, 0);
    exit(0);
}

int main(int argc, char **argv)
{
    int t, s;
    int ret;

    if (argc < 2)
	errx(1, "usage: %s <timeout> <sleep>", argv[0]);

    daemonize();

    h = xc_interface_open(NULL, NULL, 0);
    if (h == NULL)
	err(1, "xc_interface_open");

    t = strtoul(argv[1], NULL, 0);
    if (t == ULONG_MAX)
	err(1, "strtoul");

    s = t / 2;
    if (argc == 3) {
	s = strtoul(argv[2], NULL, 0);
	if (s == ULONG_MAX)
	    err(1, "strtoul");
    }

    if (signal(SIGHUP, &catch_exit) == SIG_ERR)
	err(1, "signal");
    if (signal(SIGINT, &catch_exit) == SIG_ERR)
	err(1, "signal");
    if (signal(SIGQUIT, &catch_exit) == SIG_ERR)
	err(1, "signal");
    if (signal(SIGTERM, &catch_exit) == SIG_ERR)
	err(1, "signal");
    if (signal(SIGUSR1, &catch_usr1) == SIG_ERR)
	err(1, "signal");

    id = xc_watchdog(h, 0, t);
    if (id <= 0)
        err(1, "xc_watchdog setup");

    for (;;) {
        sleep(s);
        ret = xc_watchdog(h, id, t);
        if (ret != 0)
            err(1, "xc_watchdog");
    }
}
