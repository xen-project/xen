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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "xc_private.h"
#include "xenguest.h"

#define SUSPEND_LOCK_FILE "/var/lib/xen/suspend_evtchn"
static int lock_suspend_event(xc_interface *xch, int domid)
{
    int fd, rc;
    mode_t mask;
    char buf[128];
    char suspend_file[256];

    snprintf(suspend_file, sizeof(suspend_file), "%s_%d_lock.d",
	    SUSPEND_LOCK_FILE, domid);
    mask = umask(022);
    fd = open(suspend_file, O_CREAT | O_EXCL | O_RDWR, 0666);
    if (fd < 0)
    {
        ERROR("Can't create lock file for suspend event channel %s\n",
		suspend_file);
        return -EINVAL;
    }
    umask(mask);
    snprintf(buf, sizeof(buf), "%10ld", (long)getpid());

    rc = write_exact(fd, buf, strlen(buf));
    close(fd);

    return rc;
}

static int unlock_suspend_event(xc_interface *xch, int domid)
{
    int fd, pid, n;
    char buf[128];
    char suspend_file[256];

    snprintf(suspend_file, sizeof(suspend_file), "%s_%d_lock.d",
	    SUSPEND_LOCK_FILE, domid);
    fd = open(suspend_file, O_RDWR);

    if (fd < 0)
        return -EINVAL;

    n = read(fd, buf, 127);

    close(fd);

    if (n > 0)
    {
        sscanf(buf, "%d", &pid);
        /* We are the owner, so we can simply delete the file */
        if (pid == getpid())
        {
            unlink(suspend_file);
            return 0;
        }
    }

    return -EPERM;
}

int xc_await_suspend(xc_interface *xch, int xce, int suspend_evtchn)
{
    int rc;

    do {
        rc = xc_evtchn_pending(xce);
        if (rc < 0) {
            ERROR("error polling suspend notification channel: %d", rc);
            return -1;
        }
    } while (rc != suspend_evtchn);

    /* harmless for one-off suspend */
    if (xc_evtchn_unmask(xce, suspend_evtchn) < 0)
        ERROR("failed to unmask suspend notification channel: %d", rc);

    return 0;
}

int xc_suspend_evtchn_release(xc_interface *xch, int xce, int domid, int suspend_evtchn)
{
    if (suspend_evtchn >= 0)
        xc_evtchn_unbind(xce, suspend_evtchn);

    return unlock_suspend_event(xch, domid);
}

int xc_suspend_evtchn_init(xc_interface *xch, int xce, int domid, int port)
{
    int rc, suspend_evtchn = -1;

    if (lock_suspend_event(xch, domid))
        return -EINVAL;

    suspend_evtchn = xc_evtchn_bind_interdomain(xce, domid, port);
    if (suspend_evtchn < 0) {
        ERROR("failed to bind suspend event channel: %d", suspend_evtchn);
        goto cleanup;
    }

    rc = xc_domain_subscribe_for_suspend(xch, domid, port);
    if (rc < 0) {
        ERROR("failed to subscribe to domain: %d", rc);
        goto cleanup;
    }

    /* event channel is pending immediately after binding */
    xc_await_suspend(xch, xce, suspend_evtchn);

    return suspend_evtchn;

cleanup:
    if (suspend_evtchn != -1)
        xc_suspend_evtchn_release(xch, xce, domid, suspend_evtchn);

    return -1;
}
