/*
 *	nsplitd.c
 *	---------
 *
 * $Id: nsplitd.c,v 2.6 1998/09/17 14:28:37 sde1000 Exp $
 *
 * Copyright (c) 1995, University of Cambridge Computer Laboratory,
 * Copyright (c) 1995, Richard Black, All Rights Reserved.
 *
 *
 * A complete re-implementation of DME's nsplitd for use from inetd
 *
 */

/* The basic stream comes in (via inetd) and we then conenct to
 * somewhere else providing a loop-through service, except we offer
 * two other ports for connection - one of which gets a second channel
 * using the top bit to distinguish, and the other is a master control
 * port (normally used for gdb) which gets complete exclusive access
 * for its duration.
 *
 * Originally designed for multiplexing a xwcons/telnet with a gdb
 * post-mortem debugging session.
 *
 * Here is a picture:
 *
 * 					    port0 (from inetd)
 *      8-bit connection     	       	   /
 * 	   made by us	   <----> nsplitd <-----gdbport (default port0+2)
 * 	to host:port/tcp		  |\
 * 					  | port1 (default port0+1)
 *                                         \
 *                                          control (default port0+3)
 *
 * If port1 is explicitly disabled (through a command-line option) then
 * port0 becomes 8-bit clean.
 */

/*
 * N.B.: We do NOT support 8 bit stdin/stdout usage on a
 * /dev/... because to do that right involves much messing with ioctl
 * and TIOC... etc.  If you want to do that sort of thing then the
 * right way to do it is to chain this onto wconsd (which does know
 * about and understand all the ioctl and TIOC grief).
 */

#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <string.h>

#include <sys/time.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <syslog.h>

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#ifndef LOG_DAEMON
#define LOG_DAEMON 0
#endif

#define DB(x)  /* ((x), fflush(stderr)) */

extern char *optarg;

extern int optind, opterr, optopt;

static char *prog_name;

static void usage(void)
{
    fprintf(stderr, "This program (%s) should be run via inetd (tcp)\n\n",
	    prog_name);
    fprintf(stderr, "usage: %s [-h<highport>][-g<gdbport>]"
	    "[-c<ctlport>][-8] host:service\n",
	    prog_name);
    exit(1);
}

static void fault(char *format, ...)
{
    va_list		ap;
    char		logbuf[1024];

    va_start(ap, format);
    fprintf(stderr, "%s: ", prog_name);
    vfprintf(stderr, format, ap);
    fflush(stderr);
    va_end(ap);
    
    /* XXX This is a bit dubious, but there is no vsyslog */
    va_start(ap, format);
    vsnprintf(logbuf, sizeof(logbuf), format, ap);
    syslog(LOG_ERR, logbuf);
    va_end(ap);
    exit(1);
}

static int getservice(char *name, unsigned short *port)
{
    struct servent		*se;

    if (!name) return -1;

    if (isdigit(name[0]))
	*port = atoi(name);
    else
    {
	if (!(se = getservbyname(name, "tcp")))
	    return -1;
	*port = ntohs(se->s_port);
    }
    return 0;
}

/* 
 *  connect_host: connect to ("name", "port")
 */
static int connect_host (char *name, unsigned int port)
{
    int			fd;
    struct hostent	*hostent;
    struct sockaddr_in	sin;
    int			on;
    
    if ((fd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
	fault("socket");
    
    if (!(hostent = gethostbyname(name)))
	fault("gethostbyname: %s: %s\n", name, strerror(errno));
    
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port   = htons (port);
    memcpy(&sin.sin_addr.s_addr, hostent->h_addr, sizeof(struct in_addr));
    
    if (connect(fd, (struct sockaddr *) &sin, sizeof (sin)) < 0)
	fault("connect: %s:%u: %s\n", name, port, strerror(errno));
    
    on = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof (on)) < 0)
	syslog(LOG_WARNING, "setsockopt (TCP_NODELAY): %m");

    on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof (on)) < 0)
	syslog(LOG_WARNING, "setsockopt (SO_KEEPALIVE): %m");

    return fd;
}

/*
 * open a tcp socket and start listening for connections on it
 */
static int startlistening(unsigned short port)
{
    int			fd, on;
    struct sockaddr_in	sin;

    if ((fd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
	fault("socket");
    
    on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
      syslog(LOG_WARNING, "setsockopt (SO_REUSEADDR): %m");

    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons (port);
    sin.sin_addr.s_addr = INADDR_ANY;
    if (bind(fd, &sin, sizeof(sin)) < 0)
	fault("bind: %u: %s\n", port, strerror(errno));
    
    if (listen(fd, 1) < 0)
	fault("listen: %s\n", strerror(errno));
    
    return fd;
}

static void noblock(int fd)
{
    int on=1;
    
    if (ioctl(fd, FIONBIO, &on) < 0)
	fault("ioctl: FIONBIO: %s\n", strerror(errno));
}


/* You might not believe this, but fd_sets don't have to be a 32-bit
 * integer.  In particular, in glibc2 it is an array of unsigned
 * longs.  Hence, this hacked up FD_SET_rjb() that works out if it
 * would have been a nop. */
#define FD_SET_rjb(fd, setp) \
do {						\
    if ((fd) != 32)				\
	FD_SET((fd), (setp));			\
} while(0)

#define FD_ISSET_rjb(fd, setp) (((fd) != 32)? FD_ISSET((fd), (setp)) : 0)

#define MAXSIZE	256

/* -----------------------------------------------------------------
 * The main bit of the algorithm. Note we use 32 to mean not connected
 * because this gives us 1<<32 == 0. We could have done this one
 * character at a time, but that would have been very inefficient and
 * not the unix way.  */
static int debug;

static void doit(int actl, int acto, int lish, int lisg, int lisc)
{
    int		acth, actg, actc;
    int		gdbmode = FALSE;
    char	gibuf[MAXSIZE], oibuf[MAXSIZE];
    char	libuf[MAXSIZE], lobuf[MAXSIZE];
    char	hibuf[MAXSIZE], hobuf[MAXSIZE];
    char	ctlbuf[MAXSIZE];
    fd_set	rdfs, wrfs, exfs;
    int		gicc, oicc, licc, locc, hicc, hocc, ctlcc;
    char	*giptr, *oiptr, *liptr, *loptr, *hiptr, *hoptr;
    int		rc, fromlen;
    struct sockaddr_in		from;
    
    gicc = oicc = licc = locc = hicc = hocc = ctlcc = 0;
    acth = actg = actc = 32;			/* XXX yummy */

    noblock(actl);
    noblock(acto);

    for(;;)
    {
	FD_ZERO(&rdfs);
	FD_ZERO(&wrfs);
	FD_ZERO(&exfs);

	/* always take input from the control port (if it's connected) */
	FD_SET_rjb(actc, &rdfs);

	if (gdbmode)
	{
	    if (oicc)
		FD_SET_rjb(actg, &wrfs);
	    else
		FD_SET_rjb(acto, &rdfs);
	    
	    if (gicc)
		FD_SET_rjb(acto, &wrfs);
	    else
		FD_SET_rjb(actg, &rdfs);
	}
	else
	{
	    /* There is no such thing as oibuf because its been split into
	     * lobuf and hobuf
	     */
	    if (locc || hocc)
	    {
		if (locc)
		    FD_SET_rjb(actl, &wrfs);
		if (hocc)
		    FD_SET_rjb(acth, &wrfs);
	    }
	    else
		FD_SET_rjb(acto, &rdfs);
	    
	    if (licc)
		FD_SET_rjb(acto, &wrfs);
	    else
		FD_SET_rjb(actl, &rdfs);
	    
	    if (hicc)
		FD_SET_rjb(acto, &wrfs);
	    else
		FD_SET_rjb(acth, &rdfs);
	}
	
	if (acth == 32 && lish>=0)	FD_SET_rjb(lish, &rdfs);
	if (actg == 32)			FD_SET_rjb(lisg, &rdfs);
	if (actc == 32)			FD_SET_rjb(lisc, &rdfs);

	/* now make exfs the union of the read and write fd sets, plus
	 * "actl" */
	{
	    int i;
	    exfs = rdfs;
	    for(i=0; i<32; i++)  /* XXX we only copy fd numbers up to 31 */
		if (FD_ISSET(i, &wrfs))
		    FD_SET_rjb(i, &exfs);
	    FD_SET_rjb(actl, &exfs);
	}

	/* XXX AND: can't print something of type fd_set as %x - it
         * might be an array */
	DB(fprintf(stderr, "%s: before select: %08x %08x %08x\n",
		   prog_name, rdfs, wrfs, exfs));
	
	if (select(32, &rdfs, &wrfs, &exfs, NULL) < 0)
	    fault("select: %s\n", strerror(errno));
	
	DB(fprintf(stderr, "%s: after  select: %08x %08x %08x\n",
		   prog_name, rdfs, wrfs, exfs));
	
	/* XXX it appears that a non-blocking socket may not show up
	 * correctly in exfs but instead goes readable with no data in
	 * it. Thus we check for zero and goto the appropriate close
	 * method.  */

	/* Deal with exceptions */
	if (FD_ISSET_rjb(actg, &exfs))
	{
	exfs_actg:
	    close(actg);
	    gdbmode = FALSE;
	    oicc = 0;
	    oiptr = oibuf;
	    actg = 32;
	    continue;		/* because assumptions changed */
	}
	if (FD_ISSET_rjb(acth, &exfs))
	{
	exfs_acth:
	    close(acth);
	    hicc = hocc = 0;
	    hiptr = hibuf;
	    hoptr = hibuf;
	    acth = 32;
	    continue;		/* because assumptions changed */
	}
	if (FD_ISSET_rjb(actl, &exfs) ||
	    FD_ISSET_rjb(acto, &exfs))
	{
	exfs_actl:
	exfs_acto:
	    /* Thats all folks ... */
	    break;
	}
	if (FD_ISSET_rjb(actc, &exfs))
	{
	exfs_ctl:
	    close(actc);
	    actc = 32;
	    ctlcc = 0;
	    continue;
	}

	/* Deal with reading */
	if (FD_ISSET_rjb(acto, &rdfs))
	{
	    if ((oicc = read(acto, oiptr = oibuf, MAXSIZE)) < 0)
		fault("read acto: %d: %s\n", oicc, strerror(errno));
	    if (!oicc) goto exfs_acto;
	    
	    if (!gdbmode)
	    {
		int t;

		assert((locc == 0) && (hocc == 0));
		loptr = lobuf;
		hoptr = hobuf;
		
		if (lish>=0) {
		    for(t=0; t<oicc; t++)
			if (oibuf[t] & 0x80)
			    hobuf[hocc++] = oibuf[t] & 0x7f;
			else
			    lobuf[locc++] = oibuf[t];
		} else {
		    for (t=0; t<oicc; t++)
			lobuf[locc++] = oibuf[t];
		}
		/* If no high connection scratch that */
		if (acth == 32)
		    hocc=0;
	    }
	}
	if (FD_ISSET_rjb(actl, &rdfs))
	{
	    if ((licc = read(actl, liptr = libuf, MAXSIZE)) < 0)
		fault("read actl: %d: %s\n", licc, strerror(errno));
	    if (!licc) goto exfs_actl;
	}
	if (FD_ISSET_rjb(acth, &rdfs))
	{
	    int t;
	    
	    if ((hicc = read(acth, hiptr = hibuf, MAXSIZE)) < 0)
		fault("read acth: %d: %s\n", hicc, strerror(errno));
	    if (!hicc) goto exfs_acth;
	    for(t=0; t<hicc; t++)
		hibuf[t] |= 0x80;
	}
	if (FD_ISSET_rjb(actg, &rdfs))
	{
	    if ((gicc = read(actg, giptr = gibuf, MAXSIZE)) < 0)
		fault("read actg: %d: %s\n", gicc, strerror(errno));
	    if (debug) write(1, giptr, gicc);		/* XXX */
	    if (!gicc) goto exfs_actg;
	}
	if (FD_ISSET_rjb(actc, &rdfs))
	{
	    if ((ctlcc = read(actc, ctlbuf, MAXSIZE)) < 0)
		fault("read actc: %d: %s\n", ctlcc, strerror(errno));
	    if (debug) write(1, ctlbuf, gicc);
	    if (!ctlcc) goto exfs_ctl;
	    if (ctlbuf[0] == 'r') /* reset command */
	    {
		syslog(LOG_INFO, "reset command read, exiting");
		if (debug) write(1, "reseting\n", sizeof("reseting\n"));
		break;
	    }
	}
	
	/* Deal with writing */
	if (FD_ISSET_rjb(actg, &wrfs))
	{
	    /* We must be in gdb mode so send oi buffer data */
	    assert(gdbmode);
	    if (debug) write(2, oiptr, oicc);		/* XXX */
	    if ((rc = write(actg, oiptr, oicc)) <= 0)
		fault("write actg: %d: %s\n", rc, strerror(errno));
	    oiptr += rc;
	    oicc  -= rc;
	}
	if (FD_ISSET_rjb(actl, &wrfs))
	{
	    if ((rc = write(actl, loptr, locc)) <= 0)
		fault("write actl: %d: %s\n", rc, strerror(errno));
	    loptr += rc;
	    locc  -= rc;
	}
	if (FD_ISSET_rjb(acth, &wrfs))
	{
	    if ((rc = write(acth, hoptr, hocc)) <= 0)
		fault("write acth: %d: %s\n", rc, strerror(errno));
	    hoptr += rc;
	    hocc  -= rc;
	}
	if (FD_ISSET_rjb(acto, &wrfs))
	{
	    /* If in gdb mode send gdb input, otherwise send low data
	       preferentially */
	    if (gdbmode)
	    {
		assert(gicc);
		if ((rc = write(acto, giptr, gicc)) <= 0)
		    fault("write acto: %d: %s\n", rc, strerror(errno));
		giptr += rc;
		gicc  -= rc;
	    }
	    else
	    {
		if (licc)
		{
		    if ((rc = write(acto, liptr, licc)) <= 0)
			fault("write acto: %d: %s\n", rc, strerror(errno));
		    liptr += rc;
		    licc  -= rc;
		}
		else
		{
		    assert(hicc);
		    if ((rc = write(acto, hiptr, hicc)) <= 0)
			fault("write acto: %d: %s\n", rc, strerror(errno));
		    hiptr += rc;
		    hicc  -= rc;
		}
	    }
	}
	
	/* Deals with new connections */
	if ((acth == 32) && lish>=0 && (FD_ISSET_rjb(lish, &rdfs)))
	{
	    fromlen = sizeof(from);
	    if ((acth = accept(lish, &from, &fromlen)) < 0)
	    {
		syslog(LOG_WARNING, "accept: %m");
		acth = 32;
	    }
	    else
	    {
		noblock(acth);
		hicc = hocc = 0;
		syslog(LOG_INFO, "highbit client peer is %s:%u\n",
		       inet_ntoa(from.sin_addr), ntohs(from.sin_port));
	    }
	}
	
	if ((actg == 32) && (FD_ISSET_rjb(lisg, &rdfs)))
	{
	    fromlen = sizeof(from);
	    if ((actg = accept(lisg, &from, &fromlen)) < 0)
	    {
		syslog(LOG_WARNING, "accept: %m");
		actg = 32;
	    }
	    else
	    {
		noblock(actg);
		gicc = 0;
		gdbmode = TRUE;
		syslog(LOG_INFO, "gdb client peer is %s:%u\n",
		       inet_ntoa(from.sin_addr), ntohs(from.sin_port));
	    }
	}

	if ((actc == 32) && (FD_ISSET_rjb(lisc, &rdfs)))
	{
	    fromlen = sizeof(from);
	    if ((actc = accept(lisc, &from, &fromlen)) < 0)
	    {
		syslog(LOG_WARNING, "accept (ctl): %m");
		actc = 32;
	    }
	    else
	    {
		noblock(actc);
		syslog(LOG_INFO, "ctl client peer is %s:%u\n",
		       inet_ntoa(from.sin_addr), ntohs(from.sin_port));
	    }
	}
	    
	/* Back to top of loop */
    }
    
    /* We are bailing because one of the primary connections has gone
     * away. We close these all explicitly here because that way the
     * timeout on reusing the port numbers is smnaller. */
    
    close(acth);
    close(actg);
    /* XXX AND: why are we closing all these "character counts" ?? */
    close(gicc);
    close(oicc);
    close(licc);
    close(locc);
    close(hicc);
    close(hocc);
}

/*
 * ------------------------------------------------------------
 */
int main(int argc, char **argv)
{
    /* In general, suffix "l" is low channel, "h" is high channel, "g"
     * is gdb channel, "c" is control channel and "o" is output channel.
     */
    struct sockaddr_in		from;
    int				infd = 0, outfd;
    unsigned short		portl, porth, portg, portc, porto;
    int				on = 1, c;
    char			*outname, *outservice;
    int				fromlen;
    int				lish, lisg, lisc;
#if 0
    FILE			*newerr;
#endif /* 0 */
    
    prog_name = argv[0];

    if (isatty(infd))
	usage();

    /* Here, then not just a simple idiot. */

    signal(SIGPIPE, SIG_IGN);

    openlog(prog_name, LOG_PID, LOG_DAEMON);

    fromlen = sizeof(from);
    if (getsockname(infd, &from, &fromlen) < 0)
	fault("getsockname: %s", strerror(errno));
    if ((fromlen != sizeof(from)) || (from.sin_family != AF_INET))
	fault("not an inet socket (family=%d)\n", from.sin_family);
    
    portl = ntohs(from.sin_port);
    porth = portl+1;
    portg = porth+1;
    portc = portg+1;

    fromlen = sizeof(from);
    if (getpeername(infd, &from, &fromlen) < 0)
	fault("getpeername: %s", strerror(errno));
    if ((fromlen != sizeof(from)) || (from.sin_family != AF_INET))
	fault("not an inet socket (family=%d)\n", from.sin_family);

    syslog(LOG_INFO, "on port %u peer is %s:%u\n", portl,
	   inet_ntoa(from.sin_addr), ntohs(from.sin_port));
    
    if (setsockopt(infd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof (on)) < 0)
	syslog(LOG_WARNING, "setsockopt (SO_KEEPALIVE): %m");

    /* from here on, we map stderr to output on the connection so we can
     * report errors to the remote user.
     */
#if 0
    if (!(newerr = fdopen(infd, "w")))
	syslog(LOG_WARNING, "fdopen: %m");
    else
	*stderr = *newerr;
#endif
	
    while((c = getopt(argc, argv, "d8h:g:c:")) != EOF)
    {
	switch(c)
	{
	case 'd':
	    debug++;
	    break;
	    
	case 'h':
	    /* high bit port */
	    if (getservice(optarg, &porth) < 0)
		fault("getservice failed (high port '%s')\n", optarg);
	    break;
	    
	case 'g':
	    /* gdb port */
	    if (getservice(optarg, &portg) < 0)
		fault("getservice failed (gdb port '%s')\n", optarg);
	    break;

	case 'c':
	    /* control port */
	    if (getservice(optarg, &portc) < 0)
		fault("getservice failed (control port '%s')\n", optarg);
	    break;

	case '8':
	    /* 8-bit clean; no high port */
	    porth=0;
	    break;

	default:
	    fault("bad argument list!\n");
	}
    }
    
    if (argc != optind + 1)
	fault("unparsed arguments (%d!=%d)\n", argc, optind+1);

    outname = argv[optind];
    if (!(outservice = strchr(outname, ':')))
	fault("output arg '%s' doesn't contain ':'\n", outname);
    *outservice++ = 0;
    if (getservice(outservice, &porto) < 0)
	fault("getservice failed (output port '%s')\n", outservice);
    
    /* Time to start the sockets */

    if (porth) {
	lish  = startlistening(porth);
    } else {
	lish  = -1;
    }
    lisg  = startlistening(portg);
    lisc  = startlistening(portc);
    
    outfd = connect_host(outname, porto);
    
    doit(infd, outfd, lish, lisg, lisc);

    syslog(LOG_INFO, "terminating normally\n");

    fclose(stderr);

    closelog();
    exit(0); 
}

/* End $Id: nsplitd.c,v 2.6 1998/09/17 14:28:37 sde1000 Exp $ */
