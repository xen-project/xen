#include <sys/types.h>
#include <tcpd.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>

#include "hypervisor-ifs/dom0_ops.h"
#include "dom0_defs.h"
#include "mem_defs.h"

#define SILENT_ERRORS_FROM_XEN
#define SYSLOG 1
#define SYSLOGTO LOG_LOCAL5

int logoutput;

void stripit(char *str)
{
  register int i;

  for (i = 0; str[i]; i++) {
      if (str[i] == '\n') str[i] = '\0';
      if (str[i] == '\r') str[i] = '\0';
  }
}

void errexit(char *str)
{
    if(logoutput == SYSLOG) {
        stripit(str);
        syslog(LOG_ERR, "%s failed: %d (%m)", str, errno);
    } else {
        printf("%s", str);
    }
    exit(1);
}

void log(char *str)
{
    if(logoutput == SYSLOG) {
        stripit(str);
        syslog(LOG_INFO, "%s", str);
    } else {
        printf("%s", str);
    }
}

void process()
{
    dom0_op_t op;
    unsigned char buf[208], obuf[224];
    struct sockaddr_in addr, from;
    int fromlen = sizeof(from);
    int len, fd = socket(PF_INET, SOCK_DGRAM, 0);
    unsigned short int lastport = 0, curport = 0;
    
    if ( fd < 0 )
        errexit("could not open datagram socket");

    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = htonl(0xa9fe0100); /* 169.254.1.0 */
    addr.sin_port = htons(666);
    addr.sin_family = AF_INET;

    if ( bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 )
        errexit("could not bind to local address and port");

    op.cmd = DOM0_GETDOMAININFO;

    while ( (len = recvfrom(fd, buf, sizeof(buf), 0,
            (struct sockaddr *)&from, &fromlen)) >= 0 )
    {
        curport = ntohs(from.sin_port);
        if(lastport != curport) {
           op.u.getdominfo.domain = (int)curport;
           if ( do_dom0_op(&op) < 0 ) {
              log("Error resolving domain name\n");
           } else {
              lastport = curport;
           }
        }

        sprintf(obuf, "[%s] %s", op.u.getdominfo.name, buf);
		log(obuf);

        fromlen = sizeof(from);
    }
}

void closeall(int fd)
{
    int fdlimit = sysconf(_SC_OPEN_MAX);

    while (fd < fdlimit)
      close(fd++);
}

int daemon(int nochdir, int noclose)
{
    switch (fork())
    {
        case 0:  break;
        case -1: return -1;
        default: _exit(0);
    }

    if (setsid() < 0)
      return -1;

    switch (fork())
    {
        case 0:  break;
        case -1: return -1;
        default: _exit(0);
    }

    if (!nochdir)
      chdir("/");

    if (!noclose)
    {
        closeall(0);
        open("/dev/null",O_RDWR);
        dup(0); dup(0);
    }

    return 0;
}

int main(int argc, char **argv)
{
    logoutput = 0;
    int c;

    opterr = 0;

    while ((c = getopt (argc, argv, "dh")) != -1)
    {
        switch(c)
        {
            case 'd':
                logoutput = SYSLOG;
                if (daemon(0,0) < 0)
                {
                    errno = 2;
                    errexit("daemon");
                } else {
                    openlog("xenolog", LOG_PID, SYSLOGTO);
                }
                break;
            case 'h':
                printf("Usage: xenolog [options]\n");
                printf("Capture and display output of xen domains.\n\n");
                printf("  -d       Daemonize and send output to syslog.\n");
                exit(0);
                break;
        }
    }

    process();

    return 0;
}

