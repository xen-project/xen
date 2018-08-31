/*
 * depriv-fd-checker
 *
 * utility to check whether file descriptor(s) are deprivileged
 *
 * usage:
 *  .../depriv-fd-checker CLASS FD X-INFO [CLASS FD X-INFO...]
 *
 * CLASS is one of:
 *    privcmd gntdev evtchn     FD should be appropriate Xen control fd
 *    readonly                  FD is expected to be readonly
 *    appendonly                FD is expected to be append write only
 #    tun                       FD is expected to be an open tun device
 *
 * In each case FD is probably a reference to an open-file stolen
 * from another process, eg by the use of fishdescriptor.
 *
 * X-INFO is simply appended to the discursive reportage.
 *
 * It is an error if depriv-fd-checker cannot open the control
 * facilities itself, or something goes wrong with checking, or an FD
 * is entirely the wrong kind for the specified CLASS.  Otherwise:
 *
 * depriv-fd-checker will perhaps print, for each triplet:
 *   CLASS checking FD INFORMATION... X-INFO
 * and in any case print, for each triplet, exactly one of:
 *   CLASS pass|fail FD INFORMATION... X-INFO
 *   tun maybe FD IFNAME X-INFO
 *
 * "pass" means that the descriptor was restricted as expected.
 * "fail" means that the descriptor was unrestricted.
 * "maybe" means that further information is printed, as detailed above,
 *         and the caller should check that it is as expected
 */
/*
 * Copyright (C)2018 Citrix Systems R&D
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; version 2.1 of the
 * License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include <err.h>

#include <xenctrl.h>
#include <xencall.h>
#include <xengnttab.h>
#include <xenevtchn.h>

/*
 * Every class needs setup.  setup is called once per class at program
 * startup.
 *
 * Then it can have
 *     open test getfd close
 * In which case the core code will for every fd
 *     open test getfd dup2 test close
 * And test should call blocked or succeeded and then immediately
 * return, or error out
 *
 * Or it can have
 *     check
 * which should call report, or error out
 *
 * Errors: use trouble for simple syscall errors.  Or use err or errx
 * and maybe print fd_desc and test_which, according to the comments
 * in struct classinfo.
 */

static xentoollog_logger *logger;

static int object_fd;
static const char *classname;
static const char *fd_desc;
static const char *test_which;

static const char *test_wh_unrest = "test (unrestricted)";
static const char *test_wh_rest   = "test (restricted)";


static void trouble(const char *what) __attribute__((noreturn));
static void trouble(const char *what) {
    fprintf(stderr,
	    "trouble: %s %s %d (%s) %s: %s\n",
	    classname, test_which, object_fd, fd_desc, what, strerror(errno));
    exit(-1);
}

static void report(const char *pass_or_fail, const char *what,
		   const char *notes) {
    printf("%s %s %d %s (%s) %s\n",
	   classname, pass_or_fail,
	   object_fd, what, notes, fd_desc);
    if (ferror(stdout) || fflush(stdout)) err(16,"stdout");
}

static void succeeded(const char *what) {
    if (test_which == test_wh_unrest) {
	/* ok */
	test_which = 0;
    } else if (test_which == test_wh_rest) {
	report("fail",what,"unexpectedly succeeded");
	test_which = 0;
    } else {
	abort();
    }
}

static void blocked(const char *what) {
    if (test_which == test_wh_rest) {
	/* yay */
	report("pass", what,"blocked");
	test_which = 0;
    } else if (test_which == test_wh_unrest) {
	err(4,"test blocked on unrestricted fd: %s {%s}",what,test_which);
    } else {
	abort();
    }
}

/* privcmd */

static xc_interface *xch;
static void setup_privcmd(void) { }
static void open_privcmd(void) {
    xch = xc_interface_open(logger,0,0);
    if (!xch) trouble("xc_interface_open");
}
static void test_privcmd(void) {
    int r = xc_get_online_cpus(xch);
    if (r>0)
	succeeded("xc_get_online_cpus");
    else if (r==0)
	errx(-1,"xc_get_online_cpus{%s, %s}=0", test_which, fd_desc);
    else if (errno==EPERM || errno==EACCES)
	blocked("xc_get_online_cpus");
    else
	trouble("xc_get_online_cpus");
}
static int getfd_privcmd(void) {
    return xencall_fd(xc_interface_xcall_handle(xch));
}
static void close_privcmd(void) {
    xc_interface_close(xch);
}

/* gntdev */

static xengntshr_handle *xgs;
static uint32_t gntshr_gref;
static xengnttab_handle *xgt;
static void setup_gntdev(void) {
    void *r;
    xgs = xengntshr_open(logger,0);
    if (!xgs) trouble("xengntshr_open");
    r = xengntshr_share_pages(xgs, 0, 1, &gntshr_gref, 1);
    if (!r || r==(void*)-1) trouble("xengntshr_share_pages");
    memset(r, 0x55, XC_PAGE_SIZE);
}
static void open_gntdev(void) {
    xgt = xengnttab_open(logger,0);
    if (!xgt) trouble("xengnttab_open");
}
static void test_gntdev(void) {
    char mybuf[XC_PAGE_SIZE];
    memset(mybuf, 0xaa, XC_PAGE_SIZE);
    xengnttab_grant_copy_segment_t seg;
    seg.source.foreign.ref = gntshr_gref;
    seg.source.foreign.offset = 0;
    seg.source.foreign.domid = 0;
    seg.dest.virt = mybuf;
    seg.len = 1;
    seg.flags = GNTCOPY_source_gref;
    for (;;) {
	seg.status = 0;
	int r = xengnttab_grant_copy(xgt,1,&seg);
	if (r<0) {
	    if (errno==EPERM || errno==EACCES || errno==ENOTTY)
		blocked("xengnttab_grant_copy");
	    else
		trouble("xengnttab_grant_copy");
	} else if (r==0) {
	    if (seg.status==GNTST_okay)
		succeeded("xengnttab_grant_copy okay");
	    else if (seg.status==GNTST_eagain)
		continue;
	    else errx(-1,"xengnttab_grant_copy=%d {%s, %s} but .status=%d",
		      r, test_which, fd_desc,(int)seg.status);
	} else {
	    errx(-1,"xengnttab_grant_copy=%d {%s, %s}",
		 r, test_which, fd_desc);
	}
	break;
    }
}
static int getfd_gntdev(void) {
    return xengnttab_fd(xgt);
}
static void close_gntdev(void) {
    xengnttab_close(xgt);
}

/* evtchn */

static xenevtchn_handle *xce_recip, *xce;
static void setup_evtchn(void) {
    xce_recip = xenevtchn_open(logger, 0);
    if (!xce_recip) err(-1,"xenevtchn_open (donor)");
}
static void open_evtchn(void) {
    xce = xenevtchn_open(logger, 0);
    if (!xce) err(-1,"xenevtchn_open");
}
static void test_evtchn(void) {
    xenevtchn_port_or_error_t
        recip_port=-1, test_unbound_port=-1, test_send_port=-1;

    recip_port = xenevtchn_bind_unbound_port(xce_recip, 0);
    if (recip_port < 0) trouble("xenevtchn_bind_unbound_port");

    test_unbound_port = xenevtchn_bind_unbound_port(xce, 0);
    if (test_unbound_port >= 0) {
        succeeded("xenevtchn_bind_unbound_port");
        goto out;
    }

    test_send_port = xenevtchn_bind_interdomain(xce, 0, recip_port);
    /* bind_interdomain marks the channel pending */
    struct pollfd pfd;
    for (;;) {
        pfd.fd = xenevtchn_fd(xce_recip);
        pfd.events = POLLIN;
        pfd.revents = 0;
        int r = poll(&pfd,1,0);
        if (r>=0) break;
        if (errno!=EINTR) err(-1,"poll(xce_recip)");
    }
    if (pfd.revents & POLLIN) {
        xenevtchn_port_or_error_t p3 = xenevtchn_pending(xce_recip);
        if (p3 < 0) err(-1,"xenevtchn_pending(check)");
        if (p3 != recip_port)
            errx(-1,"xenevtchn_pending=%d expected %d",p3,recip_port);
        xenevtchn_unmask(xce_recip, recip_port);
    }

    if (test_send_port>=0 && (pfd.revents & POLLIN)) {
        succeeded("xenevtchn_bind_interdomain/poll");
        /* we make no attempt to undo what we did to this stolen fd;
         * the rightful owner will see a spurious event on test_send_port */
    } else if (test_send_port==-1 && !(pfd.revents & POLLIN) &&
               (errno==EPERM || errno==EACCES || errno==ENOTTY)) {
	blocked("xenevtchn_notify");
    } else {
        err(-1,"%s %s xenevtchn_bind_interdomain=%d .revents=0x%x",
             test_which, fd_desc, test_send_port, pfd.revents);
    }

 out:
    if (recip_port        > 0) xenevtchn_unbind(xce, recip_port);
    if (test_unbound_port > 0) xenevtchn_unbind(xce, test_unbound_port);
    if (test_send_port    > 0) xenevtchn_unbind(xce, test_send_port);
}
static int getfd_evtchn(void) {
    return xenevtchn_fd(xce);
}
static void close_evtchn(void) {
    xenevtchn_close(xce);
}

/* fcntl */

#define CHECK_FCNTL(openmode)				\
    int r = fcntl(object_fd, F_GETFL);			\
    if (r < 0) trouble("fcntl F_GETFL");		\
    int m = r & (O_RDONLY | O_WRONLY | O_RDWR);		\
							\
    char mbuf[100 + 30*3];				\
    snprintf(mbuf,sizeof(mbuf),				\
	     "F_GETFL=%#o m=%#o " #openmode "=%#o",	\
	     r,m,(int)openmode);			\
							\
    if (m != openmode) {				\
	report("fail", #openmode, mbuf);		\
	return;						\
    }

/* readonly */

static void setup_readonly(void) { }
static void check_readonly(void) {
    CHECK_FCNTL(O_RDONLY);
    report("pass", "fcntl", mbuf);
}

/* appendonly */

static void setup_appendonly(void) { }
static void check_appendonly(void) {
    CHECK_FCNTL(O_WRONLY);
    if (!(r & O_APPEND)) {
	report("fail", "O_APPEND", mbuf);
	return;
    }
    report("pass", "fcntl", mbuf);
}

#if defined(__linux__)
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#ifndef TUNGETIFF
#define TUNGETIFF _IOR('T', 210, unsigned int)
#endif

/* linux tun */

static void setup_tun(void) { }
static void check_tun(void) {
    struct ifreq ifr;
    int r;

    memset(&ifr,0,sizeof(ifr));
    r = ioctl(object_fd, TUNGETIFF, (void*)&ifr);
    if (r<0) trouble("TUNGETIFF");
    printf("tun maybe %d %.*s %s\n", object_fd,
           (int)IFNAMSIZ, ifr.ifr_ifrn.ifrn_name,
           fd_desc);
}

#define PLATFORM_CLASSES \
    DEFCHECK(tun),

#else /* !defined(__linux__) */
#define PLATFORM_CLASSES /* empty */
#endif

/* class table and main program */

#define DEFCLASS(cl) \
    { #cl, setup_##cl, 0, open_##cl, test_##cl, getfd_##cl, close_##cl }
#define DEFCHECK(meth) \
    { #meth, setup_##meth, check_##meth }

static const struct classinfo {
    const char *name;     /* errors: print fd_desc   test_which */
    void (*setup)(void);  /*               best not   best not  */
    void (*check)(void);  /*               must       may       */
    void (*open)(void);   /*               must       may       */
    void (*test)(void);   /*               must       must      */
    int (*getfd)(void);   /*               must       may       */
    void (*close)(void);  /*               must       may       */
} classinfos[] = {
    DEFCLASS(privcmd),
    DEFCLASS(gntdev),
    DEFCLASS(evtchn),
    DEFCHECK(readonly),
    DEFCHECK(appendonly),
    PLATFORM_CLASSES
    { 0 }
};

int main(int argc, char **argv) {
    const struct classinfo *cli;
    int r;

    argv++;

    logger = (xentoollog_logger*)xtl_createlogger_stdiostream
	(stderr, XTL_NOTICE, XTL_STDIOSTREAM_HIDE_PROGRESS);

    fd_desc = "setup";
    test_which = "setup";
    for (cli = classinfos; cli->name; cli++)
	cli->setup();

    while ((classname = *argv++)) {
	if (!*argv) errx(8,"need fd after class");
	object_fd = atoi(*argv++);

	fd_desc = *argv++;
	if (!fd_desc) errx(8,"need info after fd");

	for (cli = classinfos; cli->name; cli++)
	    if (!strcmp(cli->name, classname))
		goto found;
	report("fail","unknown class","");
	continue;

    found:
	if (cli->check) {
	    report("checking","check","in progress");
	    test_which = "check";
	    cli->check();
	} else {
	    test_which = "open";
	    report("checking","dup-hack","in progress");
                                                  cli->open();

	    test_which = test_wh_unrest;          cli->test();
	    assert(!test_which);

	    test_which = "getfd"; int intern_fd = cli->getfd();
	    r = dup2(object_fd, intern_fd);
	    if (r != intern_fd) err(-1, "dup2");

	    test_which = test_wh_rest;             cli->test();
	    assert(!test_which);

	    test_which = "close";                  cli->close();
	}
    }

    return 0;
}
