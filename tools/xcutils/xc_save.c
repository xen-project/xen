/* 
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file "COPYING" in the main directory of
 * this archive for more details.
 *
 * Copyright (C) 2005 by Christian Limpach
 *
 */

#include <err.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>

#include <xs.h>
#include <xenctrl.h>
#include <xenguest.h>

static struct suspendinfo {
    int xc_fd; /* libxc handle */
    int xce; /* event channel handle */
    int suspend_evtchn;
    int domid;
    unsigned int flags;
} si;

/**
 * Issue a suspend request through stdout, and receive the acknowledgement
 * from stdin.  This is handled by XendCheckpoint in the Python layer.
 */
static int compat_suspend(void)
{
    char ans[30];

    printf("suspend\n");
    fflush(stdout);

    return (fgets(ans, sizeof(ans), stdin) != NULL &&
            !strncmp(ans, "done\n", 5));
}

/**
 * Issue a suspend request to a dedicated event channel in the guest, and
 * receive the acknowledgement from the subscribe event channel. */
static int evtchn_suspend(void)
{
    int rc;

    rc = xc_evtchn_notify(si.xce, si.suspend_evtchn);
    if (rc < 0) {
        warnx("failed to notify suspend request channel: %d", rc);
        return 0;
    }

    if (xc_await_suspend(si.xce, si.suspend_evtchn) < 0) {
        warnx("suspend failed");
        return 0;
    }

    /* notify xend that it can do device migration */
    printf("suspended\n");
    fflush(stdout);

    return 1;
}

static int suspend(void)
{
    unsigned long sx_state = 0;

    /* Cannot notify guest to shut itself down if it's in ACPI sleep state. */
    if (si.flags & XCFLAGS_HVM)
        xc_get_hvm_param(si.xc_fd, si.domid,
                         HVM_PARAM_ACPI_S_STATE, &sx_state);

    if ((sx_state == 0) && (si.suspend_evtchn >= 0))
        return evtchn_suspend();

    return compat_suspend();
}

/* For HVM guests, there are two sources of dirty pages: the Xen shadow
 * log-dirty bitmap, which we get with a hypercall, and qemu's version.
 * The protocol for getting page-dirtying data from qemu uses a
 * double-buffered shared memory interface directly between xc_save and
 * qemu-dm. 
 *
 * xc_save calculates the size of the bitmaps and notifies qemu-dm 
 * through the store that it wants to share the bitmaps.  qemu-dm then 
 * starts filling in the 'active' buffer. 
 *
 * To change the buffers over, xc_save writes the other buffer number to
 * the store and waits for qemu to acknowledge that it is now writing to
 * the new active buffer.  xc_save can then process and clear the old
 * active buffer. */

static char *qemu_active_path;
static char *qemu_next_active_path;
static int qemu_shmid = -1;
static struct xs_handle *xs;


/* Mark the shared-memory segment for destruction */
static void qemu_destroy_buffer(void)
{
    if (qemu_shmid != -1)
        shmctl(qemu_shmid, IPC_RMID, NULL);
    qemu_shmid = -1;
}

/* Get qemu to change buffers. */
static void qemu_flip_buffer(int domid, int next_active)
{
    char digit = '0' + next_active;
    unsigned int len;
    char *active_str, **watch;
    struct timeval tv;
    fd_set fdset;

    /* Tell qemu that we want it to start writing log-dirty bits to the
     * other buffer */
    if (!xs_write(xs, XBT_NULL, qemu_next_active_path, &digit, 1))
        errx(1, "can't write next-active to store path (%s)\n", 
             qemu_next_active_path);

    /* Wait a while for qemu to signal that it has switched to the new 
     * active buffer */
 read_again: 
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    FD_ZERO(&fdset);
    FD_SET(xs_fileno(xs), &fdset);
    if ((select(xs_fileno(xs) + 1, &fdset, NULL, NULL, &tv)) != 1)
        errx(1, "timed out waiting for qemu to switch buffers\n");
    watch = xs_read_watch(xs, &len);
    free(watch);
    
    active_str = xs_read(xs, XBT_NULL, qemu_active_path, &len);
    if (active_str == NULL || active_str[0] - '0' != next_active) 
        /* Watch fired but value is not yet right */
        goto read_again;
}

static void *init_qemu_maps(int domid, unsigned int bitmap_size)
{
    key_t key;
    char key_ascii[17] = {0,};
    void *seg; 
    char *path, *p;

    /* Make a shared-memory segment */
    do {
        key = rand(); /* No security, just a sequence of numbers */
        qemu_shmid = shmget(key, 2 * bitmap_size, 
                       IPC_CREAT|IPC_EXCL|S_IRUSR|S_IWUSR);
        if (qemu_shmid == -1 && errno != EEXIST)
            errx(1, "can't get shmem to talk to qemu-dm");
    } while (qemu_shmid == -1);

    /* Remember to tidy up after ourselves */
    atexit(qemu_destroy_buffer);

    /* Map it into our address space */
    seg = shmat(qemu_shmid, NULL, 0);
    if (seg == (void *) -1) 
        errx(1, "can't map shmem to talk to qemu-dm");
    memset(seg, 0, 2 * bitmap_size);

    /* Write the size of it into the first 32 bits */
    *(uint32_t *)seg = bitmap_size;

    /* Tell qemu about it */
    if ((xs = xs_daemon_open()) == NULL)
        errx(1, "Couldn't contact xenstore");
    if (!(path = strdup("/local/domain/0/device-model/")))
        errx(1, "can't get domain path in store");
    if (!(path = realloc(path, strlen(path) 
                         + 10 
                         + strlen("/logdirty/next-active") + 1))) 
        errx(1, "no memory for constructing xenstore path");
    snprintf(path + strlen(path), 11, "%i", domid);
    strcat(path, "/logdirty/");
    p = path + strlen(path);

    strcpy(p, "key");
    snprintf(key_ascii, 17, "%16.16llx", (unsigned long long) key);
    if (!xs_write(xs, XBT_NULL, path, key_ascii, 16))
        errx(1, "can't write key (%s) to store path (%s)\n", key_ascii, path);

    /* Watch for qemu's indication of the active buffer, and request it 
     * to start writing to buffer 0 */
    strcpy(p, "active");
    if (!xs_watch(xs, path, "qemu-active-buffer"))
        errx(1, "can't set watch in store (%s)\n", path);
    if (!(qemu_active_path = strdup(path)))
        errx(1, "no memory for copying xenstore path");

    strcpy(p, "next-active");
    if (!(qemu_next_active_path = strdup(path)))
        errx(1, "no memory for copying xenstore path");

    qemu_flip_buffer(domid, 0);

    free(path);
    return seg;
}

int
main(int argc, char **argv)
{
    unsigned int maxit, max_f;
    int io_fd, ret, port;

    if (argc != 6)
        errx(1, "usage: %s iofd domid maxit maxf flags", argv[0]);

    si.xc_fd = xc_interface_open();
    if (si.xc_fd < 0)
        errx(1, "failed to open control interface");

    io_fd = atoi(argv[1]);
    si.domid = atoi(argv[2]);
    maxit = atoi(argv[3]);
    max_f = atoi(argv[4]);
    si.flags = atoi(argv[5]);

    si.suspend_evtchn = si.xce = -1;

    si.xce = xc_evtchn_open();
    if (si.xce < 0)
        warnx("failed to open event channel handle");

    if (si.xce > 0)
    {
        port = xs_suspend_evtchn_port(si.domid);

        if (port < 0)
            warnx("failed to get the suspend evtchn port\n");
        else
        {
            si.suspend_evtchn =
              xc_suspend_evtchn_init(si.xc_fd, si.xce, si.domid, port);

            if (si.suspend_evtchn < 0)
                warnx("suspend event channel initialization failed"
                       "using slow path");
        }
    }
    ret = xc_domain_save(si.xc_fd, io_fd, si.domid, maxit, max_f, si.flags, 
                         &suspend, !!(si.flags & XCFLAGS_HVM),
                         &init_qemu_maps, &qemu_flip_buffer);

    if (si.suspend_evtchn > 0)
        xc_suspend_evtchn_release(si.xce, si.suspend_evtchn);

    if (si.xce > 0)
        xc_evtchn_close(si.xce);

    xc_interface_close(si.xc_fd);

    return ret;
}
