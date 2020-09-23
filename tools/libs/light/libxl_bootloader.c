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
#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif

#ifdef INCLUDE_LIBUTIL_H
#include INCLUDE_LIBUTIL_H
#endif

#include "libxl_internal.h"

#define BOOTLOADER_BUF_OUT 65536
#define BOOTLOADER_BUF_IN   4096

static void bootloader_gotptys(libxl__egc *egc, libxl__openpty_state *op);
static void bootloader_keystrokes_copyfail(libxl__egc *egc,
       libxl__datacopier_state *dc, int rc, int onwrite, int errnoval);
static void bootloader_display_copyfail(libxl__egc *egc,
       libxl__datacopier_state *dc, int rc, int onwrite, int errnoval);
static void bootloader_domaindeath(libxl__egc*, libxl__domaindeathcheck *dc,
                                   int rc);
static void bootloader_finished(libxl__egc *egc, libxl__ev_child *child,
                                pid_t pid, int status);

/*----- bootloader arguments -----*/

static void bootloader_arg(libxl__bootloader_state *bl, const char *arg)
{
    assert(bl->nargs < bl->argsspace);
    bl->args[bl->nargs++] = arg;
}

static void make_bootloader_args(libxl__gc *gc, libxl__bootloader_state *bl,
                                 const char *bootloader_path)
{
    const libxl_domain_build_info *info = bl->info;

    bl->argsspace = 9 + libxl_string_list_length(&info->bootloader_args);

    GCNEW_ARRAY(bl->args, bl->argsspace);

#define ARG(arg) bootloader_arg(bl, (arg))

    ARG(bootloader_path);

    if (info->kernel)
        ARG(GCSPRINTF("--kernel=%s", info->kernel));
    if (info->ramdisk)
        ARG(GCSPRINTF("--ramdisk=%s", info->ramdisk));
    if (info->cmdline && *info->cmdline != '\0')
        ARG(GCSPRINTF("--args=%s", info->cmdline));

    ARG(GCSPRINTF("--output=%s", bl->outputpath));
    ARG("--output-format=simple0");
    ARG(GCSPRINTF("--output-directory=%s", bl->outputdir));

    if (info->bootloader_args) {
        char **p = info->bootloader_args;
        while (*p) {
            ARG(*p);
            p++;
        }
    }

    ARG(bl->dls.diskpath);

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
        LOGED(ERROR, bl->domid, "ttyname_r failed");
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
                         const char *prefix, size_t prefixlen, uint32_t domid) {
    if (strncmp(buf, prefix, prefixlen))
        return 0;

    const char *rhs = buf + prefixlen;
    if (!CTYPE(isspace,*rhs))
        return 0;

    while (CTYPE(isspace,*rhs))
        rhs++;

    LOGD(DEBUG, domid, "bootloader output contained %s %s", prefix, rhs);

    return rhs;
}

static int parse_bootloader_result(libxl__egc *egc,
                                   libxl__bootloader_state *bl)
{
    STATE_AO_GC(bl->ao);
    char buf[PATH_MAX*2];
    FILE *f = 0;
    int rc = ERROR_FAIL;

    f = fopen(bl->outputpath, "r");
    if (!f) {
        LOGED(ERROR, bl->domid, "open bootloader output file %s",
              bl->outputpath);
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
                LOGED(ERROR, bl->domid, "read bootloader output file %s",
                      bl->outputpath);
                goto out;
            }
            if (!l)
                break;
        }
        if (l >= sizeof(buf)) {
            LOGD(WARN, bl->domid, "bootloader output contained"
                 " overly long item `%.150s...'", buf);
            continue;
        }
        buf[l] = 0;

        const char *rhs;
#define COMMAND(s) ((rhs = bootloader_result_command(gc, buf, s, sizeof(s)-1, bl->domid)))

        if (COMMAND("kernel")) {
            bl->kernel->path = libxl__strdup(gc, rhs);
            libxl__file_reference_map(bl->kernel);
            unlink(bl->kernel->path);
        } else if (COMMAND("ramdisk")) {
            bl->ramdisk->path = libxl__strdup(gc, rhs);
            libxl__file_reference_map(bl->ramdisk);
            unlink(bl->ramdisk->path);
        } else if (COMMAND("args")) {
            bl->cmdline = libxl__strdup(gc, rhs);
        } else if (l) {
            LOGD(WARN, bl->domid,
                 "unexpected output from bootloader: `%s'", buf);
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
    bl->rc = 0;
    bl->dls.diskpath = NULL;
    bl->openpty.ao = bl->ao;
    bl->dls.ao = bl->ao;
    bl->ptys[0].master = bl->ptys[0].slave = 0;
    bl->ptys[1].master = bl->ptys[1].slave = 0;
    libxl__ev_child_init(&bl->child);
    libxl__domaindeathcheck_init(&bl->deathcheck);
    bl->keystrokes.ao = bl->ao;  libxl__datacopier_init(&bl->keystrokes);
    bl->display.ao = bl->ao;     libxl__datacopier_init(&bl->display);
    bl->got_pollhup = 0;
}

static void bootloader_cleanup(libxl__egc *egc, libxl__bootloader_state *bl)
{
    STATE_AO_GC(bl->ao);
    int i;

    if (bl->outputpath) libxl__remove_file(gc, bl->outputpath);
    if (bl->outputdir) libxl__remove_directory(gc, bl->outputdir);

    libxl__domaindeathcheck_stop(gc,&bl->deathcheck);
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

/* Callbacks */

static void bootloader_local_detached_cb(libxl__egc *egc,
                                         libxl__disk_local_state *dls,
                                         int rc);

static void bootloader_callback(libxl__egc *egc, libxl__bootloader_state *bl,
                                int rc)
{
    if (!bl->rc)
        bl->rc = rc;

    bootloader_cleanup(egc, bl);

    bl->dls.callback = bootloader_local_detached_cb;
    libxl__device_disk_local_initiate_detach(egc, &bl->dls);
}

static void bootloader_local_detached_cb(libxl__egc *egc,
                                         libxl__disk_local_state *dls,
                                         int rc)
{
    STATE_AO_GC(dls->ao);
    libxl__bootloader_state *bl = CONTAINER_OF(dls, *bl, dls);

    if (rc) {
        LOGD(ERROR, bl->domid,
             "unable to detach locally attached disk");
        if (!bl->rc)
            bl->rc = rc;
    }

    bl->callback(egc, bl, bl->rc);
}

/* might be called at any time, provided it's init'd */
static void bootloader_stop(libxl__egc *egc,
                             libxl__bootloader_state *bl, int rc)
{
    STATE_AO_GC(bl->ao);
    int r;

    libxl__datacopier_kill(&bl->keystrokes);
    libxl__datacopier_kill(&bl->display);
    if (libxl__ev_child_inuse(&bl->child)) {
        r = kill(bl->child.pid, SIGTERM);
        if (r) LOGED(WARN, bl->domid, "%sfailed to kill bootloader [%lu]",
                     rc ? "after failure, " : "", (unsigned long)bl->child.pid);
    }
    if (!bl->rc)
        bl->rc = rc;
}

/*----- main flow of control -----*/

/* Callbacks */

static void bootloader_disk_attached_cb(libxl__egc *egc,
                                        libxl__disk_local_state *dls,
                                        int rc);

void libxl__bootloader_run(libxl__egc *egc, libxl__bootloader_state *bl)
{
    STATE_AO_GC(bl->ao);
    const libxl_domain_build_info *info = bl->info;
    uint32_t domid = bl->domid;
    char *logfile_tmp = NULL;
    int rc, r;

    libxl__bootloader_init(bl);

    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        LOGD(DEBUG, domid, "not a PV/PVH domain, skipping bootloader");
        rc = 0;
        goto out_ok;
    }

    if (!info->bootloader) {
        LOGD(DEBUG, domid,
             "no bootloader configured, using user supplied kernel");
        bl->kernel->path = bl->info->kernel;
        bl->ramdisk->path = bl->info->ramdisk;
        bl->cmdline = bl->info->cmdline;
        rc = 0;
        goto out_ok;
    }

    if (!bl->disk) {
        LOGD(ERROR, domid, "cannot run bootloader with no boot disk");
        rc = ERROR_FAIL;
        goto out;
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
        LOGED(ERROR, domid,
              "failed to create bootloader logfile %s", bl->logfile);
        rc = ERROR_FAIL;
        goto out;
    }

    for (;;) {
        r = mkdir(bl->outputdir, 0600);
        if (!r) break;
        if (errno == EINTR) continue;
        if (errno == EEXIST) break;
        LOGED(ERROR, domid,
              "failed to create bootloader dir %s", bl->outputdir);
        rc = ERROR_FAIL;
        goto out;
    }

    for (;;) {
        r = open(bl->outputpath, O_WRONLY|O_CREAT|O_TRUNC, 0600);
        if (r>=0) { close(r); break; }
        if (errno == EINTR) continue;
        LOGED(ERROR, domid,
              "failed to precreate bootloader output %s", bl->outputpath);
        rc = ERROR_FAIL;
        goto out;
    }


    /* This sets the state of the dls struct from Undefined to Idle */
    libxl__device_disk_local_init(&bl->dls);
    bl->dls.ao = ao;
    bl->dls.in_disk = bl->disk;
    bl->dls.blkdev_start = info->blkdev_start;
    bl->dls.callback = bootloader_disk_attached_cb;
    libxl__device_disk_local_initiate_attach(egc, &bl->dls);
    return;

 out:
    assert(rc);
 out_ok:
    free(logfile_tmp);
    bootloader_callback(egc, bl, rc);
}

static void bootloader_disk_attached_cb(libxl__egc *egc,
                                        libxl__disk_local_state *dls,
                                        int rc)
{
    STATE_AO_GC(dls->ao);
    libxl__bootloader_state *bl = CONTAINER_OF(dls, *bl, dls);
    const libxl_domain_build_info *info = bl->info;
    const char *bootloader;

    if (rc) {
        LOGD(ERROR, bl->domid,
             "failed to attach local disk for bootloader execution");
        goto out;
    }

    LOGD(DEBUG, bl->domid,
         "Config bootloader value: %s", info->bootloader);

    if ( !strcmp(info->bootloader, "/usr/bin/pygrub") )
        LOGD(WARN, bl->domid,
             "bootloader='/usr/bin/pygrub' is deprecated; use " \
             "bootloader='pygrub' instead");

    bootloader = info->bootloader;

    /* If the full path is not specified, check in the libexec path */
    if ( bootloader[0] != '/' ) {
        const char *bltmp;
        struct stat st;

        bltmp = libxl__abs_path(gc, bootloader, libxl__private_bindir_path());
        /* Check to see if the file exists in this location; if not,
         * fall back to checking the path */
        LOGD(DEBUG, bl->domid,
             "Checking for bootloader in libexec path: %s", bltmp);

        if ( lstat(bltmp, &st) )
            LOGD(DEBUG, bl->domid,
                 "%s doesn't exist, falling back to config path",
                 bltmp);
        else
            bootloader = bltmp;
    }

    make_bootloader_args(gc, bl, bootloader);

    bl->openpty.ao = ao;
    bl->openpty.callback = bootloader_gotptys;
    bl->openpty.count = 2;
    bl->openpty.results = bl->ptys;
    rc = libxl__openptys(&bl->openpty, 0,0);
    if (rc) goto out;

    return;

 out:
    assert(rc);
    bootloader_callback(egc, bl, rc);
}

static void bootloader_gotptys(libxl__egc *egc, libxl__openpty_state *op)
{
    libxl__bootloader_state *bl = CONTAINER_OF(op, *bl, openpty);
    STATE_AO_GC(bl->ao);
    int rc, r;
    char *const env[] = { "TERM", "vt100", NULL };

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

    rc = libxl__xs_printf(gc, XBT_NULL, dom_console_xs_path, "%s",
                          dom_console_slave_tty_path);
    if (rc) {
        LOGED(ERROR, bl->domid, "xs write console path %s := %s failed",
             dom_console_xs_path, dom_console_slave_tty_path);
        rc = ERROR_FAIL;
        goto out;
    }

    bl->deathcheck.what = "stopping bootloader";
    bl->deathcheck.domid = bl->domid;
    bl->deathcheck.callback = bootloader_domaindeath;
    rc = libxl__domaindeathcheck_start(ao, &bl->deathcheck);
    if (rc) goto out;

    if (bl->console_available)
        bl->console_available(egc, bl);

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
    bl->keystrokes.bytes_to_read = -1;
    bl->keystrokes.copywhat =
        GCSPRINTF("bootloader input for domain %"PRIu32, bl->domid);
    bl->keystrokes.callback =         bootloader_keystrokes_copyfail;
    bl->keystrokes.callback_pollhup = bootloader_keystrokes_copyfail;
        /* pollhup gets called with errnoval==-1 which is not otherwise
         * possible since errnos are nonnegative, so it's unambiguous */
    rc = libxl__datacopier_start(&bl->keystrokes);
    if (rc) goto out;

    bl->display.ao = ao;
    bl->display.maxsz = BOOTLOADER_BUF_IN;
    bl->display.bytes_to_read = -1;
    bl->display.copywhat =
        GCSPRINTF("bootloader output for domain %"PRIu32, bl->domid);
    bl->display.callback =         bootloader_display_copyfail;
    bl->display.callback_pollhup = bootloader_display_copyfail;
    rc = libxl__datacopier_start(&bl->display);
    if (rc) goto out;

    LOGD(DEBUG, bl->domid, "executing bootloader: %s", bl->args[0]);
    for (const char **blarg = bl->args;
         *blarg;
         blarg++)
        LOGD(DEBUG, bl->domid, "  bootloader arg: %s", *blarg);

    struct termios termattr;

    pid_t pid = libxl__ev_child_fork(gc, &bl->child, bootloader_finished);
    if (pid == -1) {
        rc = ERROR_FAIL;
        goto out;
    }

    if (!pid) {
        /* child */
        r = login_tty(libxl__carefd_fd(bl->ptys[0].slave));
        if (r) { LOGED(ERROR, bl->domid, "login_tty failed"); exit(-1); }
        libxl__exec(gc, -1, -1, -1, bl->args[0], (char **) bl->args, env);
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
        libxl__bootloader_state *bl, int ondisplay,
        int rc, int onwrite, int errnoval)
{
    STATE_AO_GC(bl->ao);

    if (errnoval==-1) {
        /* POLLHUP */
        if (!!ondisplay != !!onwrite) {
            rc = 0;
            bl->got_pollhup = 1;
        } else {
            LOGD(ERROR, bl->domid, "unexpected POLLHUP on %s", which);
        }
    } else if (!rc) {
        LOGD(ERROR, bl->domid, "unexpected eof copying %s", which);
        rc = ERROR_FAIL;
    }

    bootloader_stop(egc, bl, rc);
}
static void bootloader_keystrokes_copyfail(libxl__egc *egc,
       libxl__datacopier_state *dc, int rc, int onwrite, int errnoval)
{
    libxl__bootloader_state *bl = CONTAINER_OF(dc, *bl, keystrokes);
    bootloader_copyfail(egc, "bootloader input", bl, 0, rc,onwrite,errnoval);
}
static void bootloader_display_copyfail(libxl__egc *egc,
       libxl__datacopier_state *dc, int rc, int onwrite, int errnoval)
{
    libxl__bootloader_state *bl = CONTAINER_OF(dc, *bl, display);
    bootloader_copyfail(egc, "bootloader output", bl, 1, rc,onwrite,errnoval);
}

static void bootloader_domaindeath(libxl__egc *egc,
                                   libxl__domaindeathcheck *dc,
                                   int rc)
{
    libxl__bootloader_state *bl = CONTAINER_OF(dc, *bl, deathcheck);
    bootloader_stop(egc, bl, rc);
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
        if (bl->got_pollhup && WIFSIGNALED(status) && WTERMSIG(status)==SIGTERM)
            LOGD(ERROR, bl->domid, "got POLLHUP, sent SIGTERM");
        LOGD(ERROR, bl->domid,
             "bootloader failed - consult logfile %s", bl->logfile);
        libxl_report_child_exitstatus(CTX, XTL_ERROR, "bootloader",
                                      pid, status);
        rc = ERROR_FAIL;
        goto out;
    } else {
        LOGD(DEBUG, bl->domid, "bootloader completed");
    }

    if (bl->rc) {
        /* datacopier went wrong */
        rc = bl->rc;
        goto out;
    }

    rc = parse_bootloader_result(egc, bl);
    if (rc) goto out;

    rc = 0;
    LOGD(DEBUG, bl->domid, "bootloader execution successful");

 out:
    bootloader_callback(egc, bl, rc);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
