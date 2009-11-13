/* API for checkpointing */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <xenctrl.h>
#include <xenguest.h>
#include <xs.h>

#include "checkpoint.h"

static char errbuf[256];

static int setup_suspend_evtchn(checkpoint_state* s);
static void release_suspend_evtchn(checkpoint_state *s);
static int setup_shutdown_watch(checkpoint_state* s);
static int check_shutdown_watch(checkpoint_state* s);
static void release_shutdown_watch(checkpoint_state* s);
static int poll_evtchn(checkpoint_state* s);

static int switch_qemu_logdirty(checkpoint_state* s, int enable);
static int suspend_hvm(checkpoint_state* s);
static int suspend_qemu(checkpoint_state* s);
static int resume_qemu(checkpoint_state* s);
static int send_qemu(checkpoint_state* s);

static int create_suspend_timer(checkpoint_state* s);
static int delete_suspend_timer(checkpoint_state* s);
static int create_suspend_thread(checkpoint_state* s);
static void stop_suspend_thread(checkpoint_state* s);

/* Returns a string describing the most recent error returned by
 * a checkpoint function. Static -- do not free. */
char* checkpoint_error(checkpoint_state* s)
{
    return s->errstr;
}

void checkpoint_init(checkpoint_state* s)
{
    s->xch = -1;
    s->xce = -1;
    s->xsh = NULL;
    s->watching_shutdown = 0;

    s->domid = 0;
    s->domtype = dt_unknown;
    s->fd = -1;

    s->suspend_evtchn = -1;

    s->errstr = NULL;

    s->suspended = 0;
    s->done = 0;
    s->suspend_thr = 0;
    s->timer = 0;
}

/* open a checkpoint session to guest domid */
int checkpoint_open(checkpoint_state* s, unsigned int domid)
{
    xc_dominfo_t dominfo;
    unsigned long pvirq;

    s->domid = domid;

    s->xch = xc_interface_open();
    if (s->xch < 0) {
       s->errstr = "could not open control interface (are you root?)";

       return -1;
    }

    s->xsh = xs_daemon_open();
    if (!s->xsh) {
       checkpoint_close(s);
       s->errstr = "could not open xenstore handle";

       return -1;
    }

    s->xce = xc_evtchn_open();
    if (s->xce < 0) {
       checkpoint_close(s);
       s->errstr = "could not open event channel handle";

       return -1;
    }

    if (xc_domain_getinfo(s->xch, s->domid, 1, &dominfo) < 0) {
       checkpoint_close(s);
       s->errstr = "could not get domain info";

       return -1;
    }
    if (dominfo.hvm) {
       if (xc_get_hvm_param(s->xch, s->domid, HVM_PARAM_CALLBACK_IRQ, &pvirq)) {
           checkpoint_close(s);
           s->errstr = "could not get HVM callback IRQ";

           return -1;
       }
       s->domtype = pvirq ? dt_pvhvm : dt_hvm;
    } else
       s->domtype = dt_pv;

    if (setup_shutdown_watch(s) < 0) {
       checkpoint_close(s);

       return -1;
    }

    if (s->domtype == dt_pv) {
       if (setup_suspend_evtchn(s) < 0) {
           checkpoint_close(s);

           return -1;
       }
    } else if (s->domtype == dt_pvhvm) {
       checkpoint_close(s);
       s->errstr = "PV-on-HVM is unsupported";

       return -1;
    }

    return 0;
}

void checkpoint_close(checkpoint_state* s)
{
  if (s->timer)
    delete_suspend_timer(s);
  if (s->suspend_thr)
    stop_suspend_thread(s);

  release_shutdown_watch(s);
  release_suspend_evtchn(s);

  if (s->xch >= 0) {
    xc_interface_close(s->xch);
    s->xch = -1;
  }
  if (s->xce >= 0) {
    xc_evtchn_close(s->xce);
    s->xce = -1;
  }
  if (s->xsh) {
    xs_daemon_close(s->xsh);
    s->xsh = NULL;
  }

  s->domid = 0;
  s->fd = -1;
  s->suspend_evtchn = -1;
}

/* we toggle logdirty ourselves around the xc_domain_save call --
 * it avoids having to pass around checkpoint_state */
static void noop_switch_logdirty(int domid, unsigned enable)
{
    return;
}

int checkpoint_start(checkpoint_state* s, int fd,
                    struct save_callbacks* callbacks)
{
    int hvm, rc;
    int flags = XCFLAGS_LIVE;

    if (!s->domid) {
       s->errstr = "checkpoint state not opened";
       return -1;
    }

    s->fd = fd;

    hvm = s->domtype > dt_pv;
    if (hvm) {
       flags |= XCFLAGS_HVM;
       if ((rc = switch_qemu_logdirty(s, 1)))
           return rc;
    }

    rc = xc_domain_save(s->xch, fd, s->domid, 0, 0, flags, callbacks, hvm,
       noop_switch_logdirty);

    if (hvm)
       switch_qemu_logdirty(s, 0);

    return rc;
}

/* suspend the domain. Returns 0 on failure, 1 on success */
int checkpoint_suspend(checkpoint_state* s)
{
  struct timeval tv;
  int rc;

  gettimeofday(&tv, NULL);
  fprintf(stderr, "PROF: suspending at %lu.%06lu\n", (unsigned long)tv.tv_sec,
         (unsigned long)tv.tv_usec);

  if (s->domtype == dt_hvm) {
      return suspend_hvm(s) < 0 ? 0 : 1;
  }

  rc = xc_evtchn_notify(s->xce, s->suspend_evtchn);
  if (rc < 0) {
    snprintf(errbuf, sizeof(errbuf),
            "failed to notify suspend event channel: %d", rc);
    s->errstr = errbuf;

    return 0;
  }

  do {
    rc = poll_evtchn(s);
  } while (rc >= 0 && rc != s->suspend_evtchn);
  if (rc <= 0) {
    snprintf(errbuf, sizeof(errbuf),
            "failed to receive suspend notification: %d", rc);
    s->errstr = errbuf;

    return 0;
  }
  if (xc_evtchn_unmask(s->xce, s->suspend_evtchn) < 0) {
    snprintf(errbuf, sizeof(errbuf),
            "failed to unmask suspend notification channel: %d", rc);
    s->errstr = errbuf;

    return 0;
  }

  return 1;
}

/* wait for a suspend to be triggered by another thread */
int checkpoint_wait(checkpoint_state* s)
{
  int rc;

  if (!s->suspend_thr) {
    s->errstr = "checkpoint timer is not active\n";
    return -1;
  }

  do {
    rc = sem_wait(&s->suspended_sem);
    if (rc < 0 && errno != EINTR) {
      snprintf(errbuf, sizeof(errbuf),
              "error waiting for suspend semaphore: %d %d\n", rc, errno);
      s->errstr = errbuf;
      return -1;
    }
  } while (rc < 0);

  if (!s->suspended) {
    snprintf(errbuf, sizeof(errbuf), "domain not suspended?\n");
    s->errstr = errbuf;
    return -1;
  }

  return 0;
}

/* let guest execution resume */
int checkpoint_resume(checkpoint_state* s)
{
  struct timeval tv;
  int rc;

  if (xc_domain_resume(s->xch, s->domid, 1)) {
    snprintf(errbuf, sizeof(errbuf), "error resuming domain: %d", errno);
    s->errstr = errbuf;

    return -1;
  }

  gettimeofday(&tv, NULL);
  fprintf(stderr, "PROF: resumed at %lu.%06lu\n", (unsigned long)tv.tv_sec,
         (unsigned long)tv.tv_usec);

  if (s->domtype > dt_pv && resume_qemu(s) < 0)
      return -1;

  /* restore watchability in xenstore */
  if (xs_resume_domain(s->xsh, s->domid) < 0)
    fprintf(stderr, "error resuming domain in xenstore\n");

  s->suspended = 0;

  if (s->suspend_thr) {
    if ((rc = sem_post(&s->resumed_sem)))
      fprintf(stderr, "error posting resume semaphore\n");
  }

  return 0;
}

/* called after xc_domain_save has flushed its buffer */
int checkpoint_postflush(checkpoint_state *s)
{
    if (s->domtype > dt_pv && send_qemu(s) < 0)
       return -1;

    return 0;
}

/* force suspend within millis ms if copy hasn't completed yet */
int checkpoint_settimer(checkpoint_state* s, int millis)
{
  struct itimerspec t;
  int err;

  if (!s->suspend_thr) {
    if (create_suspend_timer(s) < 0)
      return -1;

    if (create_suspend_thread(s) < 0) {
      delete_suspend_timer(s);
      return -1;
    }
  }

  t.it_value.tv_sec = millis / 1000;
  t.it_value.tv_nsec = (millis % 1000) * 1000000L;
  t.it_interval.tv_sec = t.it_value.tv_sec;
  t.it_interval.tv_nsec = t.it_value.tv_nsec;

  if ((err = timer_settime(s->timer, 0, &t, NULL))) {
    fprintf(stderr, "Error arming timer: %d\n", err);
    return -1;
  }

  return 0;
}

int delete_suspend_timer(checkpoint_state* s)
{
  int rc = 0;

  if (s->timer) {
    if ((rc = timer_delete(s->timer)))
      fprintf(stderr, "Error deleting timer: %s\n", strerror(errno));
    s->timer = NULL;
  }

  return rc;
}

/* Set up event channel used to signal a guest to suspend itself */
static int setup_suspend_evtchn(checkpoint_state* s)
{
  int port;

  port = xs_suspend_evtchn_port(s->domid);
  if (port < 0) {
    s->errstr = "failed to read suspend event channel";
    return -1;
  }

  s->suspend_evtchn = xc_suspend_evtchn_init(s->xch, s->xce, s->domid, port);
  if (s->suspend_evtchn < 0) {
    snprintf(errbuf, sizeof(errbuf), "failed to bind suspend event channel");
    s->errstr = errbuf;

    return -1;
  }

  fprintf(stderr, "bound to suspend event channel %u:%d as %d\n", s->domid, port,
    s->suspend_evtchn);

  return 0;
}

/* release suspend event channels bound to guest */
static void release_suspend_evtchn(checkpoint_state *s)
{
  /* TODO: teach xen to clean up if port is unbound */
  if (s->xce >= 0 && s->suspend_evtchn > 0) {
    xc_suspend_evtchn_release(s->xce, s->suspend_evtchn);
    s->suspend_evtchn = 0;
  }
}

static int setup_shutdown_watch(checkpoint_state* s)
{
  char buf[16];

  /* write domain ID to watch so we can ignore other domain shutdowns */
  snprintf(buf, sizeof(buf), "%u", s->domid);
  if ( !xs_watch(s->xsh, "@releaseDomain", buf) ) {
    fprintf(stderr, "Could not bind to shutdown watch\n");
    return -1;
  }
  /* watch fires once on registration */
  s->watching_shutdown = 1;
  check_shutdown_watch(s);

  return 0;
}

static int check_shutdown_watch(checkpoint_state* s) {
  unsigned int count;
  char **vec;
  char buf[16];

  vec = xs_read_watch(s->xsh, &count);
  if (s->watching_shutdown == 1) {
      s->watching_shutdown = 2;
      return 0;
  }
  if (!vec) {
    fprintf(stderr, "empty watch fired\n");
    return 0;
  }
  snprintf(buf, sizeof(buf), "%d", s->domid);
  if (!strcmp(vec[XS_WATCH_TOKEN], buf)) {
    fprintf(stderr, "domain %d shut down\n", s->domid);
    return -1;
  }

  return 0;
}

static void release_shutdown_watch(checkpoint_state* s) {
  char buf[16];

  if (!s->xsh)
    return;

  if (!s->watching_shutdown)
      return;

  snprintf(buf, sizeof(buf), "%u", s->domid);
  if (!xs_unwatch(s->xsh, "@releaseDomain", buf))
    fprintf(stderr, "Could not release shutdown watch\n");
}

/* wrapper around xc_evtchn_pending which detects errors */
static int poll_evtchn(checkpoint_state* s)
{
  int fd, xsfd, maxfd;
  fd_set rfds, efds;
  struct timeval tv;
  int rc;

  fd = xc_evtchn_fd(s->xce);
  xsfd = xs_fileno(s->xsh);
  maxfd = fd > xsfd ? fd : xsfd;
  FD_ZERO(&rfds);
  FD_ZERO(&efds);
  FD_SET(fd, &rfds);
  FD_SET(xsfd, &rfds);
  FD_SET(fd, &efds);
  FD_SET(xsfd, &efds);

  /* give it 500 ms to respond */
  tv.tv_sec = 0;
  tv.tv_usec = 500000;

  rc = select(maxfd + 1, &rfds, NULL, &efds, &tv);
  if (rc < 0)
    fprintf(stderr, "error polling event channel: %s\n", strerror(errno));
  else if (!rc)
    fprintf(stderr, "timeout waiting for event channel\n");
  else if (FD_ISSET(fd, &rfds))
    return xc_evtchn_pending(s->xce);
  else if (FD_ISSET(xsfd, &rfds))
    return check_shutdown_watch(s);

  return -1;
}

/* adapted from the eponymous function in xc_save */
static int switch_qemu_logdirty(checkpoint_state *s, int enable)
{
    char path[128];
    char *tail, *cmd, *response;
    char **vec;
    unsigned int len;

    sprintf(path, "/local/domain/0/device-model/%u/logdirty/", s->domid);
    tail = path + strlen(path);

    strcpy(tail, "ret");
    if (!xs_watch(s->xsh, path, "qemu-logdirty-ret")) {
       s->errstr = "error watching qemu logdirty return";
       return -1;
    }
    /* null fire. XXX unify with shutdown watch! */
    vec = xs_read_watch(s->xsh, &len);
    free(vec);

    strcpy(tail, "cmd");
    cmd = enable ? "enable" : "disable";
    if (!xs_write(s->xsh, XBT_NULL, path, cmd, strlen(cmd))) {
       s->errstr = "error signalling qemu logdirty";
       return -1;
    }

    vec = xs_read_watch(s->xsh, &len);
    free(vec);

    strcpy(tail, "ret");
    xs_unwatch(s->xsh, path, "qemu-logdirty-ret");

    response = xs_read(s->xsh, XBT_NULL, path, &len);
    if (!len || strcmp(response, cmd)) {
       if (len)
           free(response);
       s->errstr = "qemu logdirty command failed";
       return -1;
    }
    free(response);
    fprintf(stderr, "qemu logdirty mode: %s\n", cmd);

    return 0;
}

static int suspend_hvm(checkpoint_state *s)
{
    int rc = -1;

    fprintf(stderr, "issuing HVM suspend hypercall\n");
    rc = xc_domain_shutdown(s->xch, s->domid, SHUTDOWN_suspend);
    if (rc < 0) {
       s->errstr = "shutdown hypercall failed";
       return -1;
    }
    fprintf(stderr, "suspend hypercall returned %d\n", rc);

    if (check_shutdown_watch(s) >= 0)
       return -1;

    rc = suspend_qemu(s);

    return rc;
}

static int suspend_qemu(checkpoint_state *s)
{
    char path[128];

    fprintf(stderr, "pausing QEMU\n");

    sprintf(path, "/local/domain/0/device-model/%d/command", s->domid);
    if (!xs_write(s->xsh, XBT_NULL, path, "save", 4)) {
       fprintf(stderr, "error signalling QEMU to save\n");
       return -1;
    }

    sprintf(path, "/local/domain/0/device-model/%d/state", s->domid);

    do {
       char* state;
       unsigned int len;

       state = xs_read(s->xsh, XBT_NULL, path, &len);
       if (!state) {
           s->errstr = "error reading QEMU state";
           return -1;
       }

       if (!strcmp(state, "paused")) {
           free(state);
           return 0;
       }

       free(state);
       usleep(1000);
    } while(1);

    return -1;
}

static int resume_qemu(checkpoint_state *s)
{
    char path[128];
    fprintf(stderr, "resuming QEMU\n");

    sprintf(path, "/local/domain/0/device-model/%d/command", s->domid);
    if (!xs_write(s->xsh, XBT_NULL, path, "continue", 8)) {
       fprintf(stderr, "error signalling QEMU to resume\n");
       return -1;
    }

    return 0;
}

static int send_qemu(checkpoint_state *s)
{
    char buf[8192];
    char path[128];
    struct stat sb;
    uint32_t qlen = 0;
    int qfd;
    int rc;

    if (s->fd < 0)
       return -1;

    sprintf(path, "/var/lib/xen/qemu-save.%d", s->domid);

    if (stat(path, &sb) < 0) {
       snprintf(errbuf, sizeof(errbuf),
               "error getting QEMU state file status: %s", strerror(errno));
       s->errstr = errbuf;
       return -1;
    }

    qlen = sb.st_size;
    qfd = open(path, O_RDONLY);
    if (qfd < 0) {
       snprintf(errbuf, sizeof(errbuf), "error opening QEMU state file: %s",
                strerror(errno));
       s->errstr = errbuf;
       return -1;
    }

    fprintf(stderr, "Sending %u bytes of QEMU state\n", qlen);
    if (write(s->fd, "RemusDeviceModelState", 21) != 21) {
       s->errstr = "error writing QEMU header";
       close(qfd);
       return -1;
    }
    if (write(s->fd, &qlen, sizeof(qlen)) != sizeof(qlen)) {
       s->errstr = "error writing QEMU size";
       close(qfd);
       return -1;
    }

    while ((rc = read(qfd, buf, qlen > sizeof(buf) ? sizeof(buf) : qlen)) > 0) {
       qlen -= rc;
       if (write(s->fd, buf, rc) != rc) {
           rc = -1;
           break;
       }
    }
    if (rc < 0) {
       snprintf(errbuf, sizeof(errbuf), "error writing QEMU state: %s",
                strerror(errno));
       s->errstr = errbuf;
    }

    close(qfd);

    return rc;
}

/*thread responsible to suspend the domain early if necessary*/
static void *suspend_thread(void *arg)
{
  checkpoint_state* s = (checkpoint_state*)arg;
  sigset_t tss;
  int rc;
  int sig;

  fprintf(stderr, "Suspend thread started\n");

  sigemptyset(&tss);
  sigaddset(&tss, SIGRTMIN);

  while (1) {
    /* wait for checkpoint thread to signal resume */
    if ((rc = sem_wait(&s->resumed_sem)))
      fprintf(stderr, "Error waiting on resume semaphore\n");

    if ((rc = sigwait(&tss, &sig))) {
      fprintf(stderr, "sigwait failed: %d %d\n", rc, errno);
      break;
    }
    if (sig != SIGRTMIN)
      fprintf(stderr, "received unexpected signal %d\n", sig);

    if (s->done)
      break;

    if (s->suspended) {
      fprintf(stderr, "domain already suspended?\n");
    } else {
      rc = checkpoint_suspend(s);
      if (rc)
       s->suspended = 1;
      else
       fprintf(stderr, "checkpoint_suspend failed\n");
    }

    if ((rc = sem_post(&s->suspended_sem)))
      fprintf(stderr, "Error posting suspend semaphore\n");
  }

  fprintf(stderr, "Suspend thread exiting\n");

  return NULL;
}

static int create_suspend_timer(checkpoint_state* s)
{
  struct sigevent event;
  int err;

  event.sigev_notify = SIGEV_SIGNAL;
  event.sigev_signo = SIGRTMIN;
  event.sigev_value.sival_int = 0;

  if ((err = timer_create(CLOCK_REALTIME, &event, &s->timer))) {
    snprintf(errbuf, sizeof(errbuf), "Error creating timer: %d\n", err);
    s->errstr = errbuf;
    return -1;
  }

  return 0;
}

void block_timer(void)
{
  sigset_t tss;

  sigemptyset(&tss);
  sigaddset(&tss, SIGRTMIN);

  pthread_sigmask(SIG_BLOCK, &tss, NULL);
}

void unblock_timer(void)
{
  sigset_t tss;

  sigemptyset(&tss);
  sigaddset(&tss, SIGRTMIN);

  pthread_sigmask(SIG_UNBLOCK, &tss, NULL);
}

static int create_suspend_thread(checkpoint_state* s)
{
  int err;

  if ((err = sem_init(&s->suspended_sem, 0, 0))) {
    snprintf(errbuf, sizeof(errbuf),
            "Error initializing suspend semaphore: %d\n", err);
    s->errstr = errbuf;
    return -1;
  }

  if ((err = sem_init(&s->resumed_sem, 0, 0))) {
    snprintf(errbuf, sizeof(errbuf),
            "Error initializing resume semaphore: %d\n", err);
    s->errstr = errbuf;
    return -1;
  }

  /* signal mask should be inherited */
  block_timer();

  if ((err = pthread_create(&s->suspend_thr, NULL, suspend_thread, s))) {
    snprintf(errbuf, sizeof(errbuf), "Error creating suspend thread: %d\n", err);
    s->errstr = errbuf;
    return -1;
  }

  return 0;
}

static void stop_suspend_thread(checkpoint_state* s)
{
  int err;

  s->done = 1;

  err = sem_post(&s->resumed_sem);

  err = pthread_join(s->suspend_thr, NULL);
  s->suspend_thr = 0;
}
