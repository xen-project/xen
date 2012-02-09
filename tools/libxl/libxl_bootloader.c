/*
 * Copyright (C) 2010      Citrix Ltd.
 * Author Ian Campbell <ian.campbell@citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_osdeps.h" /* must come before any other headers */

#include <termios.h>

#include "libxl_internal.h"

#define XENCONSOLED_BUF_SIZE 16
#define BOOTLOADER_BUF_SIZE 4096
#define BOOTLOADER_TIMEOUT 1

static char **make_bootloader_args(libxl__gc *gc,
                                   libxl_domain_build_info *info,
                                   uint32_t domid,
                                   const char *fifo, char *disk)
{
    flexarray_t *args;
    int nr = 0;

    args = flexarray_make(1, 1);
    if (!args)
        return NULL;

    flexarray_set(args, nr++, (char *)info->u.pv.bootloader);

    if (info->u.pv.kernel.path)
        flexarray_set(args, nr++, libxl__sprintf(gc, "--kernel=%s",
                                                 info->u.pv.kernel.path));
    if (info->u.pv.ramdisk.path)
        flexarray_set(args, nr++, libxl__sprintf(gc, "--ramdisk=%s", info->u.pv.ramdisk.path));
    if (info->u.pv.cmdline && *info->u.pv.cmdline != '\0')
        flexarray_set(args, nr++, libxl__sprintf(gc, "--args=%s", info->u.pv.cmdline));

    flexarray_set(args, nr++, libxl__sprintf(gc, "--output=%s", fifo));
    flexarray_set(args, nr++, "--output-format=simple0");
    flexarray_set(args, nr++, libxl__sprintf(gc, "--output-directory=%s", "/var/run/libxl/"));

    if (info->u.pv.bootloader_args) {
        char **p = info->u.pv.bootloader_args;
        while (*p) {
            flexarray_set(args, nr++, *p);
            p++;
        }
    }

    flexarray_set(args, nr++, disk);

    /* Sentinal for execv */
    flexarray_set(args, nr++, NULL);

    return (char **) flexarray_contents(args); /* Frees args */
}

static int open_xenconsoled_pty(int *master, int *slave, char *slave_path, size_t slave_path_len)
{
    struct termios termattr;
    int ret;

    ret = openpty(master, slave, NULL, NULL, NULL);
    if (ret < 0)
        return -1;

    ret = ttyname_r(*slave, slave_path, slave_path_len);
    if (ret == -1) {
        close(*master);
        close(*slave);
        *master = *slave = -1;
        return -1;
    }

    /*
     * On Solaris, the pty master side will get cranky if we try
     * to write to it while there is no slave. To work around this,
     * keep the slave descriptor open until we're done. Set it
     * to raw terminal parameters, otherwise it will echo back
     * characters, which will confuse the I/O loop below.
     * Furthermore, a raw master pty device has no terminal
     * semantics on Solaris, so don't try to set any attributes
     * for it.
     */
#if !defined(__sun__) && !defined(__NetBSD__)
    tcgetattr(*master, &termattr);
    cfmakeraw(&termattr);
    tcsetattr(*master, TCSANOW, &termattr);

    close(*slave);
    *slave = -1;
#else
    tcgetattr(*slave, &termattr);
    cfmakeraw(&termattr);
    tcsetattr(*slave, TCSANOW, &termattr);
#endif

    fcntl(*master, F_SETFL, O_NDELAY);
    fcntl(*master, F_SETFD, FD_CLOEXEC);

    return 0;
}

static pid_t fork_exec_bootloader(int *master, const char *arg0, char **args)
{
    struct termios termattr;
    pid_t pid = forkpty(master, NULL, NULL, NULL);
    if (pid == -1)
        return -1;
    else if (pid == 0) {
        setenv("TERM", "vt100", 1);
        libxl__exec(-1, -1, -1, arg0, args);
        return -1;
    }

    /*
     * On Solaris, the master pty side does not have terminal semantics,
     * so don't try to set any attributes, as it will fail.
     */
#if !defined(__sun__)
    tcgetattr(*master, &termattr);
    cfmakeraw(&termattr);
    tcsetattr(*master, TCSANOW, &termattr);
#endif

    fcntl(*master, F_SETFL, O_NDELAY);

    return pid;
}

/*
 * filedescriptors:
 *   fifo_fd        - bootstring output from the bootloader
 *   xenconsoled_fd - input/output from/to xenconsole
 *   bootloader_fd  - input/output from/to pty that controls the bootloader
 * The filedescriptors are NDELAY, so it's ok to try to read
 * bigger chunks than may be available, to keep e.g. curses
 * screen redraws in the bootloader efficient. xenconsoled_fd is the side that
 * gets xenconsole input, which will be keystrokes, so a small number
 * is sufficient. bootloader_fd is pygrub output, which will be curses screen
 * updates, so a larger number (1024) is appropriate there.
 *
 * For writeable descriptors, only include them in the set for select
 * if there is actual data to write, otherwise this would loop too fast,
 * eating up CPU time.
 */
static char * bootloader_interact(libxl__gc *gc, int xenconsoled_fd, int bootloader_fd, int fifo_fd)
{
    int ret;

    size_t nr_out = 0, size_out = 0;
    char *output = NULL;
    struct timeval wait;

    /* input from xenconsole. read on xenconsoled_fd write to bootloader_fd */
    int xenconsoled_prod = 0, xenconsoled_cons = 0;
    char xenconsoled_buf[XENCONSOLED_BUF_SIZE];
    /* output from bootloader. read on bootloader_fd write to xenconsoled_fd */
    int bootloader_prod = 0, bootloader_cons = 0;
    char bootloader_buf[BOOTLOADER_BUF_SIZE];

    while(1) {
        fd_set wsel, rsel;
        int nfds;

        /* Set timeout to 1s before starting to discard data */
        wait.tv_sec = BOOTLOADER_TIMEOUT;
        wait.tv_usec = 0;

        /* Move buffers around to drop already consumed data */
        if (xenconsoled_cons > 0) {
            xenconsoled_prod -= xenconsoled_cons;
            memmove(xenconsoled_buf, &xenconsoled_buf[xenconsoled_cons],
                    xenconsoled_prod);
            xenconsoled_cons = 0;
        }
        if (bootloader_cons > 0) {
            bootloader_prod -= bootloader_cons;
            memmove(bootloader_buf, &bootloader_buf[bootloader_cons],
                    bootloader_prod);
            bootloader_cons = 0;
        }

        FD_ZERO(&rsel);
        FD_SET(fifo_fd, &rsel);
        nfds = fifo_fd + 1;
        if (xenconsoled_prod < XENCONSOLED_BUF_SIZE) {
            /* The buffer is not full, try to read more data */
            FD_SET(xenconsoled_fd, &rsel);
            nfds = xenconsoled_fd + 1 > nfds ? xenconsoled_fd + 1 : nfds;
        } 
        if (bootloader_prod < BOOTLOADER_BUF_SIZE) {
            /* The buffer is not full, try to read more data */
            FD_SET(bootloader_fd, &rsel);
            nfds = bootloader_fd + 1 > nfds ? bootloader_fd + 1 : nfds;
        }

        FD_ZERO(&wsel);
        if (bootloader_prod > 0) {
            /* The buffer has data to consume */
            FD_SET(xenconsoled_fd, &wsel);
            nfds = xenconsoled_fd + 1 > nfds ? xenconsoled_fd + 1 : nfds;
        }
        if (xenconsoled_prod > 0) {
            /* The buffer has data to consume */
            FD_SET(bootloader_fd, &wsel);
            nfds = bootloader_fd + 1 > nfds ? bootloader_fd + 1 : nfds;
        }

        if (xenconsoled_prod == XENCONSOLED_BUF_SIZE ||
            bootloader_prod == BOOTLOADER_BUF_SIZE)
            ret = select(nfds, &rsel, &wsel, NULL, &wait);
        else
            ret = select(nfds, &rsel, &wsel, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            goto out_err;
        }

        /* Input from xenconsole, read xenconsoled_fd, write bootloader_fd */
        if (ret == 0 && xenconsoled_prod == XENCONSOLED_BUF_SIZE) {
            /* Drop the buffer */
            xenconsoled_prod = 0;
            xenconsoled_cons = 0;
        } else if (FD_ISSET(xenconsoled_fd, &rsel)) {
            ret = read(xenconsoled_fd, &xenconsoled_buf[xenconsoled_prod], XENCONSOLED_BUF_SIZE - xenconsoled_prod);
            if (ret < 0 && errno != EIO && errno != EAGAIN)
                goto out_err;
            if (ret > 0)
                xenconsoled_prod += ret;
        }
        if (FD_ISSET(bootloader_fd, &wsel)) {
            ret = write(bootloader_fd, &xenconsoled_buf[xenconsoled_cons], xenconsoled_prod - xenconsoled_cons);
            if (ret < 0 && errno != EIO && errno != EAGAIN)
                goto out_err;
            if (ret > 0)
                xenconsoled_cons += ret;
        }

        /* Input from bootloader, read bootloader_fd, write xenconsoled_fd */
        if (ret == 0 && bootloader_prod == BOOTLOADER_BUF_SIZE) {
            /* Drop the buffer */
            bootloader_prod = 0;
            bootloader_cons = 0;
        } else if (FD_ISSET(bootloader_fd, &rsel)) {
            ret = read(bootloader_fd, &bootloader_buf[bootloader_prod], BOOTLOADER_BUF_SIZE - bootloader_prod);
            if (ret < 0 && errno != EIO && errno != EAGAIN)
                goto out_err;
            if (ret > 0)
                bootloader_prod += ret;
        }
        if (FD_ISSET(xenconsoled_fd, &wsel)) {
            ret = write(xenconsoled_fd, &bootloader_buf[bootloader_cons], bootloader_prod - bootloader_cons);
            if (ret < 0 && errno != EIO && errno != EAGAIN)
                goto out_err;
            if (ret > 0)
                bootloader_cons += ret;
        }

        if (FD_ISSET(fifo_fd, &rsel)) {
            if (size_out - nr_out < 256) {
                char *temp;
                size_t new_size = size_out == 0 ? 32 : size_out * 2;

                temp = realloc(output, new_size);
                if (temp == NULL)
                    goto out_err;
                output = temp;
                memset(output + size_out, 0, new_size - size_out);
                size_out = new_size;
            }

            ret = read(fifo_fd, output + nr_out, size_out - nr_out);
            if (ret > 0)
                  nr_out += ret;
            if (ret == 0)
                break;
        }
    }

    libxl__ptr_add(gc, output);
    return output;

out_err:
    free(output);
    return NULL;
}

static void parse_bootloader_result(libxl__gc *gc,
                                    libxl_domain_build_info *info,
                                    const char *o)
{
    while (*o != '\0') {
        if (strncmp("kernel ", o, strlen("kernel ")) == 0) {
            free(info->u.pv.kernel.path);
            info->u.pv.kernel.path = strdup(o + strlen("kernel "));
            libxl__file_reference_map(&info->u.pv.kernel);
            unlink(info->u.pv.kernel.path);
        } else if (strncmp("ramdisk ", o, strlen("ramdisk ")) == 0) {
            free(info->u.pv.ramdisk.path);
            info->u.pv.ramdisk.path = strdup(o + strlen("ramdisk "));
            libxl__file_reference_map(&info->u.pv.ramdisk);
            unlink(info->u.pv.ramdisk.path);
        } else if (strncmp("args ", o, strlen("args ")) == 0) {
            free(info->u.pv.cmdline);
            info->u.pv.cmdline = strdup(o + strlen("args "));
        }

        o = o + strlen(o) + 1;
    }
}

int libxl_run_bootloader(libxl_ctx *ctx,
                         libxl_domain_build_info *info,
                         libxl_device_disk *disk,
                         uint32_t domid)
{
    GC_INIT(ctx);
    int ret, rc = 0;
    char *fifo = NULL;
    char *diskpath = NULL;
    char **args = NULL;

    char tempdir_template[] = "/var/run/libxl/bl.XXXXXX";
    char *tempdir;

    char *dom_console_xs_path;
    char dom_console_slave_tty_path[PATH_MAX];

    int xenconsoled_fd = -1, xenconsoled_slave = -1;
    int bootloader_fd = -1, fifo_fd = -1;

    int blrc;
    pid_t pid;
    char *blout;

    struct stat st_buf;

    if (info->type != LIBXL_DOMAIN_TYPE_PV || !info->u.pv.bootloader)
        goto out;

    rc = ERROR_INVAL;
    if (!disk)
        goto out;

    rc = ERROR_FAIL;
    ret = mkdir("/var/run/libxl/", S_IRWXU);
    if (ret < 0 && errno != EEXIST)
        goto out;

    ret = stat("/var/run/libxl/", &st_buf);
    if (ret < 0)
        goto out;

    if (!S_ISDIR(st_buf.st_mode))
        goto out;

    tempdir = mkdtemp(tempdir_template);
    if (tempdir == NULL)
        goto out;

    ret = asprintf(&fifo, "%s/fifo", tempdir);
    if (ret < 0) {
        fifo = NULL;
        goto out_close;
    }

    ret = mkfifo(fifo, 0600);
    if (ret < 0) {
        goto out_close;
    }

    diskpath = libxl_device_disk_local_attach(ctx, disk);
    if (!diskpath) {
        goto out_close;
    }

    args = make_bootloader_args(gc, info, domid, fifo, diskpath);
    if (args == NULL) {
        rc = ERROR_NOMEM;
        goto out_close;
    }

    /*
     * We need to present the bootloader's tty as a pty slave that xenconsole
     * can access.  Since the bootloader itself needs a pty slave,
     * we end up with a connection like this:
     *
     * xenconsole -- (slave pty1 master) <-> (master pty2 slave) -- bootloader
     *
     * where we copy characters between the two master fds, as well as
     * listening on the bootloader's fifo for the results.
     */
    ret = open_xenconsoled_pty(&xenconsoled_fd, &xenconsoled_slave,
                               &dom_console_slave_tty_path[0],
                               sizeof(dom_console_slave_tty_path));
    if (ret < 0) {
        goto out_close;
    }

    dom_console_xs_path = libxl__sprintf(gc, "%s/console/tty", libxl__xs_get_dompath(gc, domid));
    libxl__xs_write(gc, XBT_NULL, dom_console_xs_path, "%s", dom_console_slave_tty_path);

    pid = fork_exec_bootloader(&bootloader_fd, info->u.pv.bootloader, args);
    if (pid < 0) {
        goto out_close;
    }

    while (1) {
        if (waitpid(pid, &blrc, WNOHANG) == pid)
            goto out_close;

        fifo_fd = open(fifo, O_RDONLY);
        if (fifo_fd > -1)
            break;

        if (errno == EINTR)
            continue;

        goto out_close;
    }

    fcntl(fifo_fd, F_SETFL, O_NDELAY);

    blout = bootloader_interact(gc, xenconsoled_fd, bootloader_fd, fifo_fd);
    if (blout == NULL) {
        goto out_close;
    }

    pid = waitpid(pid, &blrc, 0);
    if (pid == -1 || (pid > 0 && WIFEXITED(blrc) && WEXITSTATUS(blrc) != 0)) {
        goto out_close;
    }

    parse_bootloader_result(gc, info, blout);

    rc = 0;
out_close:
    if (diskpath) {
        libxl_device_disk_local_detach(ctx, disk);
        free(diskpath);
    }
    if (fifo_fd > -1)
        close(fifo_fd);
    if (bootloader_fd > -1)
        close(bootloader_fd);
    if (xenconsoled_fd > -1)
        close(xenconsoled_fd);
    if (xenconsoled_slave > -1)
        close(xenconsoled_slave);

    if (fifo) {
        unlink(fifo);
        free(fifo);
    }

    rmdir(tempdir);

    free(args);

out:
    GC_FREE;
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
