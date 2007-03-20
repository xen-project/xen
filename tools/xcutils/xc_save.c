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

#include <xs.h>
#include <xenctrl.h>
#include <xenguest.h>

/**
 * Issue a suspend request through stdout, and receive the acknowledgement
 * from stdin.  This is handled by XendCheckpoint in the Python layer.
 */
static int suspend(int domid)
{
    char ans[30];

    printf("suspend\n");
    fflush(stdout);

    return (fgets(ans, sizeof(ans), stdin) != NULL &&
            !strncmp(ans, "done\n", 5));
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
static struct xs_handle *xs;

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
    if (!xs_write(xs, XBT_NULL, qemu_next_active_path, &digit, 1)) {
        errx(1, "can't write next-active to store path (%s)\n", 
              qemu_next_active_path);
        exit(1);
    }

    /* Wait a while for qemu to signal that it has switched to the new 
     * active buffer */
 read_again: 
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    FD_ZERO(&fdset);
    FD_SET(xs_fileno(xs), &fdset);
    if ((select(xs_fileno(xs) + 1, &fdset, NULL, NULL, &tv)) != 1) {
        errx(1, "timed out waiting for qemu to switch buffers\n");
        exit(1);
    }
    watch = xs_read_watch(xs, &len);
    free(watch);
    
    active_str = xs_read(xs, XBT_NULL, qemu_active_path, &len);
    if (active_str == NULL || active_str[0] - '0' != next_active) 
        /* Watch fired but value is not yet right */
        goto read_again;
}

static void * init_qemu_maps(int domid, unsigned int bitmap_size)
{
    key_t key;
    char key_ascii[17] = {0,};
    int shmid = -1;
    void *seg; 
    char *path, *p;

    /* Make a shared-memory segment */
    while (shmid == -1)
    {
        key = rand(); /* No security, just a sequence of numbers */
        shmid = shmget(key, 2 * bitmap_size, 
                       IPC_CREAT|IPC_EXCL|S_IRUSR|S_IWUSR);
        if (shmid == -1 && errno != EEXIST)
            errx(1, "can't get shmem to talk to qemu-dm");
    }

    /* Map it into our address space */
    seg = shmat(shmid, NULL, 0);
    if (seg == (void *) -1) 
        errx(1, "can't map shmem to talk to qemu-dm");
    memset(seg, 0, 2 * bitmap_size);

    /* Write the size of it into the first 32 bits */
    *(uint32_t *)seg = bitmap_size;

    /* Tell qemu about it */
    if ((xs = xs_daemon_open()) == NULL)
        errx(1, "Couldn't contact xenstore");
    if (!(path = xs_get_domain_path(xs, domid)))
        errx(1, "can't get domain path in store");
    if (!(path = realloc(path, strlen(path) 
                         + strlen("/logdirty/next-active") + 1))) 
        errx(1, "no memory for constructing xenstore path");
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
    unsigned int xc_fd, io_fd, domid, maxit, max_f, flags; 
    int ret;

    if (argc != 6)
	errx(1, "usage: %s iofd domid maxit maxf flags", argv[0]);

    xc_fd = xc_interface_open();
    if (xc_fd < 0)
        errx(1, "failed to open control interface");

    io_fd = atoi(argv[1]);
    domid = atoi(argv[2]);
    maxit = atoi(argv[3]);
    max_f = atoi(argv[4]);
    flags = atoi(argv[5]);

    if (flags & XCFLAGS_HVM)
        ret = xc_hvm_save(xc_fd, io_fd, domid, maxit, max_f, flags, 
                          &suspend, &init_qemu_maps, &qemu_flip_buffer);
    else 
        ret = xc_linux_save(xc_fd, io_fd, domid, maxit, max_f, flags, 
                            &suspend);

    xc_interface_close(xc_fd);

    return ret;
}
