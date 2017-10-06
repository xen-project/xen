/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <fcntl.h>

#include <xenevtchn.h>

#include "xc_private.h"
#include "xenguest.h"

#define SUSPEND_LOCK_FILE    XEN_RUN_DIR "/suspend-evtchn-%d.lock"

/*
 * locking
 */

#define ERR(x) do{                                                      \
    ERROR("Can't " #x " lock file for suspend event channel %s: %s\n",  \
          suspend_file, strerror(errno));                               \
    goto err;                                                           \
}while(0)

#define SUSPEND_FILE_BUFLEN (sizeof(SUSPEND_LOCK_FILE) + 10)

static void get_suspend_file(char buf[], uint32_t domid)
{
    snprintf(buf, SUSPEND_FILE_BUFLEN, SUSPEND_LOCK_FILE, domid);
}

static int lock_suspend_event(xc_interface *xch, uint32_t domid, int *lockfd)
{
    int fd = -1, r;
    char suspend_file[SUSPEND_FILE_BUFLEN];
    struct stat ours, theirs;
    struct flock fl;

    get_suspend_file(suspend_file, domid);

    *lockfd = -1;

    for (;;) {
        if (fd >= 0)
            close (fd);

        fd = open(suspend_file, O_CREAT | O_RDWR, 0600);
        if (fd < 0)
            ERR("create");

        r = fcntl(fd, F_SETFD, FD_CLOEXEC);
        if (r)
            ERR("fcntl F_SETFD FD_CLOEXEC");

        memset(&fl, 0, sizeof(fl));
        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_len = 1;
        r = fcntl(fd, F_SETLK, &fl);
        if (r)
            ERR("fcntl F_SETLK");

        r = fstat(fd, &ours);
        if (r)
            ERR("fstat");

        r = stat(suspend_file, &theirs);
        if (r) {
            if (errno == ENOENT)
                /* try again */
                continue;
            ERR("stat");
        }

        if (ours.st_ino != theirs.st_ino)
            /* someone else must have removed it while we were locking it */
            continue;

        break;
    }

    *lockfd = fd;
    return 0;

 err:
    if (fd >= 0)
        close(fd);

    return -1;
}

static int unlock_suspend_event(xc_interface *xch, uint32_t domid, int *lockfd)
{
    int r;
    char suspend_file[SUSPEND_FILE_BUFLEN];

    if (*lockfd < 0)
        return 0;

    get_suspend_file(suspend_file, domid);

    r = unlink(suspend_file);
    if (r)
        ERR("unlink");

    r = close(*lockfd);
    *lockfd = -1;
    if (r)
        ERR("close");

 err:
    if (*lockfd >= 0)
        close(*lockfd);

    return -1;
}

int xc_await_suspend(xc_interface *xch, xenevtchn_handle *xce, int suspend_evtchn)
{
    int rc;

    do {
        rc = xenevtchn_pending(xce);
        if (rc < 0) {
            ERROR("error polling suspend notification channel: %d", rc);
            return -1;
        }
    } while (rc != suspend_evtchn);

    /* harmless for one-off suspend */
    if (xenevtchn_unmask(xce, suspend_evtchn) < 0)
        ERROR("failed to unmask suspend notification channel: %d", rc);

    return 0;
}

/* Internal callers are allowed to call this with suspend_evtchn<0
 * but *lockfd>0. */
int xc_suspend_evtchn_release(xc_interface *xch, xenevtchn_handle *xce,
                              uint32_t domid, int suspend_evtchn, int *lockfd)
{
    if (suspend_evtchn >= 0)
        xenevtchn_unbind(xce, suspend_evtchn);

    return unlock_suspend_event(xch, domid, lockfd);
}

int xc_suspend_evtchn_init_sane(xc_interface *xch, xenevtchn_handle *xce,
                                uint32_t domid, int port, int *lockfd)
{
    int rc, suspend_evtchn = -1;

    if (lock_suspend_event(xch, domid, lockfd)) {
        errno = EINVAL;
        goto cleanup;
    }

    suspend_evtchn = xenevtchn_bind_interdomain(xce, domid, port);
    if (suspend_evtchn < 0) {
        ERROR("failed to bind suspend event channel: %d", suspend_evtchn);
        goto cleanup;
    }

    rc = xc_domain_subscribe_for_suspend(xch, domid, port);
    if (rc < 0) {
        ERROR("failed to subscribe to domain: %d", rc);
        goto cleanup;
    }

    return suspend_evtchn;

cleanup:
    xc_suspend_evtchn_release(xch, xce, domid, suspend_evtchn, lockfd);

    return -1;
}

int xc_suspend_evtchn_init_exclusive(xc_interface *xch, xenevtchn_handle *xce,
                                     uint32_t domid, int port, int *lockfd)
{
    int suspend_evtchn;

    suspend_evtchn = xc_suspend_evtchn_init_sane(xch, xce, domid, port, lockfd);
    if (suspend_evtchn < 0)
        return suspend_evtchn;

    /* event channel is pending immediately after binding */
    xc_await_suspend(xch, xce, suspend_evtchn);

    return suspend_evtchn;
}
