/******************************************************************************
 * netwatch.c
 * 
 * Watch for network interfaces needing frobbing.
 * 
 * Copyright (c) 2003, K A Fraser
 */

#include <asm/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#define LOG(_f, _a...)                                  \
    do {                                                \
        time_t now = time(NULL);                        \
        char *tstr = ctime(&now);                       \
        char *p = strchr(tstr, '\n'); if (p) *p = '\0'; \
        fprintf(logfd, "%s: " _f "\n", tstr,  ## _a);   \
        fflush(logfd);                                  \
    } while ( 0 )

#define EXIT do { LOG("Exiting."); return 1; } while ( 0 )

static void daemonise(void)
{
    int i;
    struct rlimit rlim;

    /* Close all file handles we inherited from our parent. */
    if ( getrlimit(RLIMIT_NOFILE, &rlim) == 0 )
        for ( i = 0; i < rlim.rlim_cur; i++ )
            close(i);

    /* Lose the controlling tty. */
    setsid();
}

void handle_child_death(int dummy)
{
    (void)waitpid(-1, NULL, WNOHANG);
}

int main(int argc, char **argv)
{
    char *logfile = "/var/xen/netwatch";
    char *scriptfile = "/etc/xen/netwatch";
    FILE *logfd;
    int nlfd, unixfd, bytes;
    int last_index = ~0;
    unsigned int last_flags = ~0;
    char buffer[8192];
    struct sockaddr_nl nladdr;
    struct nlmsghdr *nlmsg;
    struct ifinfomsg *ifi;
    struct ifreq ifr;
    struct sigaction sigchld;

    /* Ensure that zombie children are reaped. */
    memset(&sigchld, 0, sizeof(sigchld));
    sigchld.sa_handler = handle_child_death;
    sigemptyset(&sigchld.sa_mask);
    sigchld.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    (void)sigaction(SIGCHLD, &sigchld, NULL);

    /*
     * After child daemonises it can't display errors until it opens the log 
     * file. Since it may be unable to open the log file, we test for that
     * possibility here.
     */
    if ( (logfd = fopen(logfile, "wb")) == NULL )
    {
        fprintf(stderr, "Could not open log file '%s' (%d)\n", logfile, errno);
        fprintf(stderr, "Exiting.\n");
        return 1;
    }
    fclose(logfd);

    switch ( fork() )
    {
    case 0:
        daemonise();
        break;
    case -1:
        fprintf(stderr, "Could not daemonize. (%d)\n", errno);
        fprintf(stderr, "Exiting.\n");
        return 1;
    default:
        goto out;
    }

    /* Silent error is forgiveable here, as our parent did a test for us. */
    if ( (logfd = fopen(logfile, "wb")) == NULL )
        return 1;

    if ( (nlfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) == -1 )
    {
        LOG("Could not open an rtnetlink socket. (%d)\n", errno);
        EXIT;
    }

    if ( (unixfd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1 )
    {
        LOG("Could not open UNIX socket. (%d)\n", errno);
        EXIT;
    }

    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid    = 0;
    nladdr.nl_groups = RTMGRP_LINK;
    if ( bind(nlfd, (struct sockaddr *)&nladdr, sizeof(nladdr)) == -1 )
    {
        LOG("Could not bind to kernel (%d)\n", errno);
        EXIT;
    }

    for ( ; ; )
    {
        memset(buffer, 0, sizeof(buffer));

        if ( (bytes = read(nlfd, buffer, sizeof(buffer))) == -1 )
        {
            if ( errno != EINTR )
                LOG("Error when reading from socket (%d)", errno);
            continue;
        }

        if ( bytes == 0 )
            continue;

        for ( nlmsg = (struct nlmsghdr *)buffer; 
              !(nlmsg->nlmsg_flags & NLMSG_DONE);
              nlmsg = NLMSG_NEXT(nlmsg, bytes) )
        {
            /* This termination condition works. NLMSG_DONE doesn't always. */
            if ( nlmsg->nlmsg_len == 0 )
                break;

            if ( nlmsg->nlmsg_type != RTM_NEWLINK )
                continue;

            ifi = NLMSG_DATA(nlmsg);

            ifr.ifr_ifindex = ifi->ifi_index;
            if ( ioctl(unixfd, SIOCGIFNAME, &ifr) == -1 )
                continue;

            if ( !(ifi->ifi_change & IFF_UP) )
                continue;

            /* Ignore duplicate messages. */
            if ( (last_index == ifr.ifr_ifindex) &&
                 (last_flags == ifi->ifi_flags) )
                continue;
            last_index = ifr.ifr_ifindex;
            last_flags = ifi->ifi_flags;

            LOG("Network %s event for interface %s",
                (ifi->ifi_flags & IFF_UP) ? "UP" : "DOWN",
                ifr.ifr_name);

            switch ( fork() )
            {
            case 0:
                execl(scriptfile,
                      ifr.ifr_name, 
                      (ifi->ifi_flags & IFF_UP) ? "up" : "down");
                LOG("Error executing network script '%s %s %s'", 
                    scriptfile, ifr.ifr_name, 
                    (ifi->ifi_flags & IFF_UP) ? "up" : "down");
                return 1;
            case -1:
                LOG("Error forking to exec script");
                break;
            default:
                break;
            }
        }
    }

 out:
    return 0;
}
