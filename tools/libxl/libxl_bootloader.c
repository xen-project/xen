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
#include <utmp.h>

#ifdef INCLUDE_LIBUTIL_H
#include INCLUDE_LIBUTIL_H
#endif

#include "libxl_internal.h"

#define BOOTLOADER_BUF_OUT 65536
#define BOOTLOADER_BUF_IN   4096

static void bootloader_gotptys(libxl__egc *egc, libxl__openpty_state *op);
static void bootloader_keystrokes_copyfail(libxl__egc *egc,
       libxl__datacopier_state *dc, int onwrite, int errnoval);
static void bootloader_display_copyfail(libxl__egc *egc,
       libxl__datacopier_state *dc, int onwrite, int errnoval);
static void bootloader_finished(libxl__egc *egc, libxl__ev_child *child,
                                pid_t pid, int status);

/*----- bootloader arguments -----*/

static void bootloader_arg(libxl__bootloader_state *bl, const char *arg)
{
    assert(bl->nargs < bl->argsspace);
    bl->args[bl->nargs++] = arg;
}

static void make_bootloader_args(libxl__gc *gc, libxl__bootloader_state *bl)
{
    const libxl_domain_build_info *info = bl->info;

    bl->argsspace = 7 + libxl_string_list_length(&info->u.pv.bootloader_args);

    GCNEW_ARRAY(bl->args, bl->argsspace);

#define ARG(arg) bootloader_arg(bl, (arg))

    ARG(info->u.pv.bootloader);

    if (info->u.pv.kernel.path)
        ARG(libxl__sprintf(gc, "--kernel=%s", info->u.pv.kernel.path));
    if (info->u.pv.ramdisk.path)
        ARG(libxl__sprintf(gc, "--ramdisk=%s", info->u.pv.ramdisk.path));
    if (info->u.pv.cmdline && *info->u.pv.cmdline != '\0')
        ARG(libxl__sprintf(gc, "--args=%s", info->u.pv.cmdline));

    ARG(libxl__sprintf(gc, "--output=%s", bl->outputpath));
    ARG("--output-format=simple0");
    ARG(libxl__sprintf(gc, "--output-directory=%s", bl->outputdir));

    if (info->u.pv.bootloader_args) {
        char **p = info->u.pv.bootloader_args;
        while (*p) {
            ARG(*p);
            p++;
        }
    }

    ARG(bl->diskpath);

    /* Sentinel for execv */
    ARG(NULL);

#undef ARG
}

/*----- synchronous subroutines -----*/

static int setup_xenconsoled_pty(libxl__egc *egc, libxl__bootloader_state *bl,
                                 char *slave_path, size_t slave_path_len)
{
    STATE_AO_GC(bl->ao);
    struct termios termattr;
    int r, rc;
    int slave = libxl__carefd_fd(bl->ptys[1].slave);
    int master = libxl__carefd_fd(bl->ptys[1].master);

    r = ttyname_r(slave, slave_path, slave_path_len);
    if (r == -1) {
        LOGE(ERROR,"ttyname_r failed");
        rc = ERROR_FAIL;
        goto out;
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
    tcgetattr(master, &termattr);
    cfmakeraw(&termattr);
    tcsetattr(master, TCSANOW, &termattr);

    return 0;

 out:
    return rc;
}

static const char *bootloader_result_command(libxl__gc *gc, const char *buf,
                         const char *prefix, size_t prefixlen) {
    if (strncmp(buf, prefix, prefixlen))
        return 0;

    const char *rhs = buf + prefixlen;
    if (!CTYPE(isspace,*rhs))
        return 0;

    while (CTYPE(isspace,*rhs))
        rhs++;

    LOG(DEBUG,"bootloader output contained %s %s", prefix, rhs);

    return rhs;
}

static int parse_bootloader_result(libxl__egc *egc,
                                   libxl__bootloader_state *bl)
{
    STATE_AO_GC(bl->ao);
    char buf[PATH_MAX*2];
    FILE *f = 0;
    int rc = ERROR_FAIL;
    libxl_domain_build_info *info = bl->info;

    f = fopen(bl->outputpath, "r");
    if (!f) {
        LOGE(ERROR,"open bootloader output file %s", bl->outputpath);
        goto out;
    }

    for (;;) {
        /* Read a nul-terminated "line" and put the result in
         * buf, and its length (not including the nul) in l */
        int l = 0, c;
        while ((c = getc(f)) != EOF && c != '\0') {
            if (l < sizeof(buf)-1)
                buf[l] = c;
            l++;
        }
        if (c == EOF) {
            if (ferror(f)) {
                LOGE(ERROR,"read bootloader output file %s", bl->outputpath);
                goto out;
            }
            if (!l)
                break;
        }
        if (l >= sizeof(buf)) {
            LOG(WARN,"bootloader output contained"
                " overly long item `%.150s...'", buf);
            continue;
        }
        buf[l] = 0;

        const char *rhs;
#define COMMAND(s) ((rhs = bootloader_result_command(gc, buf, s, sizeof(s)-1)))

        if (COMMAND("kernel")) {
            free(info->u.pv.kernel.path);
            info->u.pv.kernel.path = libxl__strdup(NULL, rhs);
            libxl__file_reference_map(&info->u.pv.kernel);
            unlink(info->u.pv.kernel.path);
        } else if (COMMAND("ramdisk")) {
            free(info->u.pv.ramdisk.path);
            info->u.pv.ramdisk.path = libxl__strdup(NULL, rhs);
            libxl__file_reference_map(&info->u.pv.ramdisk);
            unlink(info->u.pv.ramdisk.path);
        } else if (COMMAND("args")) {
            free(info->u.pv.cmdline);
            info->u.pv.cmdline = libxl__strdup(NULL, rhs);
        } else if (l) {
            LOG(WARN, "unexpected output from bootloader: `%s'", buf);
        }
    }
    rc = 0;

 out:
    if (f) fclose(f);
    return rc;
}


/*----- init and cleanup -----*/

void libxl__bootloader_init(libxl__bootloader_state *bl)
{
    assert(bl->ao);
    bl->diskpath = NULL;
    bl->openpty.ao = bl->ao;
    bl->ptys[0].master = bl->ptys[0].slave = 0;
    bl->ptys[1].master = bl->ptys[1].slave = 0;
    libxl__ev_child_init(&bl->child);
    bl->keystrokes.ao = bl->ao;  libxl__datacopier_init(&bl->keystrokes);
    bl->display.ao = bl->ao;     libxl__datacopier_init(&bl->display);
}

static void bootloader_cleanup(libxl__egc *egc, libxl__bootloader_state *bl)
{
    STATE_AO_GC(bl->ao);
    int i;

    if (bl->outputpath) libxl__remove_file(gc, bl->outputpath);
    if (bl->outputdir) libxl__remove_directory(gc, bl->outputdir);

    if (bl->diskpath) {
        libxl_device_disk_local_detach(CTX, bl->disk);
        free(bl->diskpath);
        bl->diskpath = 0;
    }
    libxl__datacopier_kill(&bl->keystrokes);
    libxl__datacopier_kill(&bl->display);
    for (i=0; i<2; i++) {
        libxl__carefd_close(bl->ptys[i].master);
        libxl__carefd_close(bl->ptys[i].slave);
    }
    if (bl->display.log) {
        fclose(bl->display.log);
        bl->display.log = NULL;
    }
}

static void bootloader_setpaths(libxl__gc *gc, libxl__bootloader_state *bl)
{
    uint32_t domid = bl->domid;
    bl->outputdir = GCSPRINTF(XEN_RUN_DIR "/bootloader.%"PRIu32".d", domid);
    bl->outputpath = GCSPRINTF(XEN_RUN_DIR "/bootloader.%"PRIu32".out", domid);
}

static void bootloader_callback(libxl__egc *egc, libxl__bootloader_state *bl,
                                int rc)
{
    bootloader_cleanup(egc, bl);
    bl->callback(egc, bl, rc);
}

/*----- main flow of control -----*/

void libxl__bootloader_run(libxl__egc *egc, libxl__bootloader_state *bl)
{
    STATE_AO_GC(bl->ao);
    libxl_domain_build_info *info = bl->info;
    uint32_t domid = bl->domid;
    char *logfile_tmp = NULL;
    int rc, r;

    libxl__bootloader_init(bl);

    if (info->type != LIBXL_DOMAIN_TYPE_PV || !info->u.pv.bootloader) {
        rc = 0;
        goto out_ok;
    }

    bootloader_setpaths(gc, bl);

    const char *logfile_leaf = GCSPRINTF("bootloader.%"PRIu32, domid);
    rc = libxl_create_logfile(CTX, logfile_leaf, &logfile_tmp);
    if (rc) goto out;

    /* Transfer ownership of log filename to bl and the gc */
    bl->logfile = logfile_tmp;
    libxl__ptr_add(gc, logfile_tmp);
    logfile_tmp = NULL;

    bl->display.log = fopen(bl->logfile, "a");
    if (!bl->display.log) {
        LOGE(ERROR, "failed to create bootloader logfile %s", bl->logfile);
        rc = ERROR_FAIL;
        goto out;
    }

    for (;;) {
        r = mkdir(bl->outputdir, 0600);
        if (!r) break;
        if (errno == EINTR) continue;
        if (errno == EEXIST) break;
        LOGE(ERROR, "failed to create bootloader dir %s", bl->outputdir);
        rc = ERROR_FAIL;
        goto out;
    }

    for (;;) {
        r = open(bl->outputpath, O_WRONLY|O_CREAT|O_TRUNC, 0600);
        if (r>=0) { close(r); break; }
        if (errno == EINTR) continue;
        LOGE(ERROR, "failed to precreate bootloader output %s", bl->outputpath);
        rc = ERROR_FAIL;
        goto out;
    }

    bl->diskpath = libxl_device_disk_local_attach(CTX, bl->disk);
    if (!bl->diskpath) {
        rc = ERROR_FAIL;
        goto out;
    }

    make_bootloader_args(gc, bl);

    bl->openpty.ao = ao;
    bl->openpty.callback = bootloader_gotptys;
    bl->openpty.count = 2;
    bl->openpty.results = bl->ptys;
    rc = libxl__openptys(&bl->openpty, 0,0);
    if (rc) goto out;

    return;

 out:
    assert(rc);
 out_ok:
    free(logfile_tmp);
    bootloader_callback(egc, bl, rc);
}

static void bootloader_gotptys(libxl__egc *egc, libxl__openpty_state *op)
{
    libxl__bootloader_state *bl = CONTAINER_OF(op, *bl, openpty);
    STATE_AO_GC(bl->ao);
    int rc, r;

    if (bl->openpty.rc) {
        rc = bl->openpty.rc;
        goto out;
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

    char *dom_console_xs_path;
    char dom_console_slave_tty_path[PATH_MAX];
    rc = setup_xenconsoled_pty(egc, bl,
                               &dom_console_slave_tty_path[0],
                               sizeof(dom_console_slave_tty_path));
    if (rc) goto out;

    char *dompath = libxl__xs_get_dompath(gc, bl->domid);
    if (!dompath) { rc = ERROR_FAIL; goto out; }

    dom_console_xs_path = GCSPRINTF("%s/console/tty", dompath);

    rc = libxl__xs_write(gc, XBT_NULL, dom_console_xs_path, "%s",
                         dom_console_slave_tty_path);
    if (rc) {
        LOGE(ERROR,"xs write console path %s := %s failed",
             dom_console_xs_path, dom_console_slave_tty_path);
        rc = ERROR_FAIL;
        goto out;
    }

    int bootloader_master = libxl__carefd_fd(bl->ptys[0].master);
    int xenconsole_master = libxl__carefd_fd(bl->ptys[1].master);

    libxl_fd_set_nonblock(CTX, bootloader_master, 1);
    libxl_fd_set_nonblock(CTX, xenconsole_master, 1);

    bl->keystrokes.writefd   = bl->display.readfd   = bootloader_master;
    bl->keystrokes.writewhat = bl->display.readwhat = "bootloader pty";

    bl->keystrokes.readfd   = bl->display.writefd   = xenconsole_master;
    bl->keystrokes.readwhat = bl->display.writewhat = "xenconsole client pty";

    bl->keystrokes.ao = ao;
    bl->keystrokes.maxsz = BOOTLOADER_BUF_OUT;
    bl->keystrokes.copywhat =
        GCSPRINTF("bootloader input for domain %"PRIu32, bl->domid);
    bl->keystrokes.callback = bootloader_keystrokes_copyfail;
    rc = libxl__datacopier_start(&bl->keystrokes);
    if (rc) goto out;

    bl->display.ao = ao;
    bl->display.maxsz = BOOTLOADER_BUF_IN;
    bl->display.copywhat =
        GCSPRINTF("bootloader output for domain %"PRIu32, bl->domid);
    bl->display.callback = bootloader_display_copyfail;
    rc = libxl__datacopier_start(&bl->display);
    if (rc) goto out;

    LOG(DEBUG, "executing bootloader: %s", bl->args[0]);
    for (const char **blarg = bl->args;
         *blarg;
         blarg++)
        LOG(DEBUG, "  bootloader arg: %s", *blarg);

    struct termios termattr;

    pid_t pid = libxl__ev_child_fork(gc, &bl->child, bootloader_finished);
    if (pid == -1) {
        rc = ERROR_FAIL;
        goto out;
    }

    if (!pid) {
        /* child */
        r = login_tty(libxl__carefd_fd(bl->ptys[0].slave));
        if (r) { LOGE(ERROR, "login_tty failed"); exit(-1); }
        setenv("TERM", "vt100", 1);
        libxl__exec(-1, -1, -1, bl->args[0], (char**)bl->args);
        exit(-1);
    }

    /* parent */

    /*
     * On Solaris, the master pty side does not have terminal semantics,
     * so don't try to set any attributes, as it will fail.
     */
#if !defined(__sun__)
    tcgetattr(bootloader_master, &termattr);
    cfmakeraw(&termattr);
    tcsetattr(bootloader_master, TCSANOW, &termattr);
#endif

    return;

 out:
    bootloader_callback(egc, bl, rc);
}

/* perhaps one of these will be called, but perhaps not */
static void bootloader_copyfail(libxl__egc *egc, const char *which,
       libxl__bootloader_state *bl, int onwrite, int errnoval)
{
    STATE_AO_GC(bl->ao);
    int r;

    if (!onwrite && !errnoval)
        LOG(ERROR, "unexpected eof copying %s", which);
    libxl__datacopier_kill(&bl->keystrokes);
    libxl__datacopier_kill(&bl->display);
    if (libxl__ev_child_inuse(&bl->child)) {
        r = kill(bl->child.pid, SIGTERM);
        if (r) LOGE(WARN, "after failure, failed to kill bootloader [%lu]",
                    (unsigned long)bl->child.pid);
    }
    bl->rc = ERROR_FAIL;
}
static void bootloader_keystrokes_copyfail(libxl__egc *egc,
       libxl__datacopier_state *dc, int onwrite, int errnoval)
{
    libxl__bootloader_state *bl = CONTAINER_OF(dc, *bl, keystrokes);
    bootloader_copyfail(egc, "bootloader input", bl, onwrite, errnoval);
}
static void bootloader_display_copyfail(libxl__egc *egc,
       libxl__datacopier_state *dc, int onwrite, int errnoval)
{
    libxl__bootloader_state *bl = CONTAINER_OF(dc, *bl, display);
    bootloader_copyfail(egc, "bootloader output", bl, onwrite, errnoval);
}

static void bootloader_finished(libxl__egc *egc, libxl__ev_child *child,
                                pid_t pid, int status)
{
    libxl__bootloader_state *bl = CONTAINER_OF(child, *bl, child);
    STATE_AO_GC(bl->ao);
    int rc;

    libxl__datacopier_kill(&bl->keystrokes);
    libxl__datacopier_kill(&bl->display);

    if (status) {
        LOG(ERROR, "bootloader failed - consult logfile %s", bl->logfile);
        libxl_report_child_exitstatus(CTX, XTL_ERROR, "bootloader",
                                      pid, status);
        rc = ERROR_FAIL;
        goto out;
    } else {
        LOG(DEBUG, "bootloader completed");
    }

    if (bl->rc) {
        /* datacopier went wrong */
        rc = bl->rc;
        goto out;
    }

    rc = parse_bootloader_result(egc, bl);
    if (rc) goto out;

    rc = 0;
    LOG(DEBUG, "bootloader execution successful");

 out:
    bootloader_callback(egc, bl, rc);
}

/*----- entrypoint for external callers -----*/

static void run_bootloader_done(libxl__egc *egc,
                                libxl__bootloader_state *st, int rc)
{
    libxl__ao_complete(egc, st->ao, rc);
}

int libxl_run_bootloader(libxl_ctx *ctx,
                         libxl_domain_build_info *info,
                         libxl_device_disk *disk,
                         uint32_t domid,
                         libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx,domid,ao_how);
    libxl__bootloader_state *bl;

    GCNEW(bl);
    bl->ao = ao;
    bl->callback = run_bootloader_done;
    bl->info = info;
    bl->disk = disk;
    bl->domid = domid;
    libxl__bootloader_run(egc, bl);
    return AO_INPROGRESS;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
