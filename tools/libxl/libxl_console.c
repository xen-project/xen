/*
 * Copyright 2009-2017 Citrix Ltd and other contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_osdeps.h"

#include "libxl_internal.h"

static int libxl__console_tty_path(libxl__gc *gc, uint32_t domid, int cons_num,
                                   libxl_console_type type, char **tty_path)
{
    int rc;
    char *dom_path;

    dom_path = libxl__xs_get_dompath(gc, domid);
    if (!dom_path) {
        rc = ERROR_FAIL;
        goto out;
    }

    switch (type) {
    case LIBXL_CONSOLE_TYPE_SERIAL:
        *tty_path = GCSPRINTF("%s/serial/%d/tty", dom_path, cons_num);
        rc = 0;
        break;
    case LIBXL_CONSOLE_TYPE_PV:
        if (cons_num == 0)
            *tty_path = GCSPRINTF("%s/console/tty", dom_path);
        else
            *tty_path = GCSPRINTF("%s/tty",
                                  libxl__domain_device_frontend_path(gc, domid,
                                  cons_num, LIBXL__DEVICE_KIND_CONSOLE));
        rc = 0;
        break;
    default:
        rc = ERROR_INVAL;
        goto out;
    }

out:
    return rc;
}

int libxl_console_exec(libxl_ctx *ctx, uint32_t domid, int cons_num,
                       libxl_console_type type, int notify_fd)
{
    GC_INIT(ctx);
    char *p = GCSPRINTF("%s/xenconsole", libxl__private_bindir_path());
    char *domid_s = GCSPRINTF("%d", domid);
    char *cons_num_s = GCSPRINTF("%d", cons_num);
    char *notify_fd_s;
    char *cons_type_s;

    switch (type) {
    case LIBXL_CONSOLE_TYPE_PV:
        cons_type_s = "pv";
        break;
    case LIBXL_CONSOLE_TYPE_SERIAL:
        cons_type_s = "serial";
        break;
    case LIBXL_CONSOLE_TYPE_VUART:
        cons_type_s = "vuart";
        break;
    default:
        goto out;
    }

    if (notify_fd != -1) {
        notify_fd_s = GCSPRINTF("%d", notify_fd);
        execl(p, p, domid_s, "--num", cons_num_s, "--type", cons_type_s,
              "--start-notify-fd", notify_fd_s, (void *)NULL);
    } else {
        execl(p, p, domid_s, "--num", cons_num_s, "--type", cons_type_s,
              (void *)NULL);
    }

out:
    GC_FREE;
    return ERROR_FAIL;
}

int libxl_console_get_tty(libxl_ctx *ctx, uint32_t domid, int cons_num,
                          libxl_console_type type, char **path)
{
    GC_INIT(ctx);
    char *tty_path;
    char *tty;
    int rc;

    rc = libxl__console_tty_path(gc, domid, cons_num, type, &tty_path);
    if (rc) {
        LOGD(ERROR, domid, "Failed to get tty path\n");
        goto out;
    }

    tty = libxl__xs_read(gc, XBT_NULL, tty_path);
    if (!tty || tty[0] == '\0') {
       LOGED(ERROR, domid, "Unable to read console tty path `%s'",
             tty_path);
       rc = ERROR_FAIL;
       goto out;
    }

    *path = libxl__strdup(NOGC, tty);
    rc = 0;
out:
    GC_FREE;
    return rc;
}

static int libxl__primary_console_find(libxl_ctx *ctx, uint32_t domid_vm,
                                       uint32_t *domid, int *cons_num,
                                       libxl_console_type *type)
{
    GC_INIT(ctx);
    uint32_t stubdomid = libxl_get_stubdom_id(ctx, domid_vm);
    int rc;

    if (stubdomid) {
        *domid = stubdomid;
        *cons_num = STUBDOM_CONSOLE_SERIAL;
        *type = LIBXL_CONSOLE_TYPE_PV;
    } else {
        switch (libxl__domain_type(gc, domid_vm)) {
        case LIBXL_DOMAIN_TYPE_HVM:
            *domid = domid_vm;
            *cons_num = 0;
            *type = LIBXL_CONSOLE_TYPE_SERIAL;
            break;
        case LIBXL_DOMAIN_TYPE_PVH:
        case LIBXL_DOMAIN_TYPE_PV:
            *domid = domid_vm;
            *cons_num = 0;
            *type = LIBXL_CONSOLE_TYPE_PV;
            break;
        case LIBXL_DOMAIN_TYPE_INVALID:
            rc = ERROR_INVAL;
            goto out;
        default: abort();
        }
    }

    rc = 0;
out:
    GC_FREE;
    return rc;
}

int libxl_primary_console_exec(libxl_ctx *ctx, uint32_t domid_vm, int notify_fd)
{
    uint32_t domid;
    int cons_num;
    libxl_console_type type;
    int rc;

    rc = libxl__primary_console_find(ctx, domid_vm, &domid, &cons_num, &type);
    if ( rc ) return rc;
    return libxl_console_exec(ctx, domid, cons_num, type, notify_fd);
}

int libxl_primary_console_get_tty(libxl_ctx *ctx, uint32_t domid_vm,
                                  char **path)
{
    uint32_t domid;
    int cons_num;
    libxl_console_type type;
    int rc;

    rc = libxl__primary_console_find(ctx, domid_vm, &domid, &cons_num, &type);
    if ( rc ) return rc;
    return libxl_console_get_tty(ctx, domid, cons_num, type, path);
}

int libxl_vncviewer_exec(libxl_ctx *ctx, uint32_t domid, int autopass)
{
    GC_INIT(ctx);
    const char *vnc_port;
    const char *vnc_listen = NULL, *vnc_pass = NULL;
    int port = 0, autopass_fd = -1;
    char *vnc_bin, *args[] = {
        "vncviewer",
        NULL, /* hostname:display */
        NULL, /* -autopass */
        NULL,
    };

    vnc_port = libxl__xs_read(gc, XBT_NULL,
                            GCSPRINTF(
                            "/local/domain/%d/console/vnc-port", domid));
    if (!vnc_port) {
        LOGD(ERROR, domid, "Cannot get vnc-port");
        goto x_fail;
    }

    port = atoi(vnc_port) - 5900;

    vnc_listen = libxl__xs_read(gc, XBT_NULL,
                                GCSPRINTF("/local/domain/%d/console/vnc-listen",
                                          domid));

    if ( autopass )
        vnc_pass = libxl__xs_read(gc, XBT_NULL,
                                  GCSPRINTF("/local/domain/%d/console/vnc-pass",
                                            domid));

    if ( NULL == vnc_listen )
        vnc_listen = "localhost";

    if ( (vnc_bin = getenv("VNCVIEWER")) )
        args[0] = vnc_bin;

    args[1] = GCSPRINTF("%s:%d", vnc_listen, port);

    if ( vnc_pass ) {
        char tmpname[] = "/tmp/vncautopass.XXXXXX";
        autopass_fd = mkstemp(tmpname);
        if ( autopass_fd < 0 ) {
            LOGED(ERROR, domid, "mkstemp %s failed", tmpname);
            goto x_fail;
        }

        if ( unlink(tmpname) ) {
            /* should never happen */
            LOGED(ERROR, domid, "unlink %s failed", tmpname);
            goto x_fail;
        }

        if ( libxl_write_exactly(ctx, autopass_fd, vnc_pass, strlen(vnc_pass),
                                    tmpname, "vnc password") )
            goto x_fail;

        if ( lseek(autopass_fd, SEEK_SET, 0) ) {
            LOGED(ERROR, domid, "rewind %s (autopass) failed", tmpname);
            goto x_fail;
        }

        args[2] = "-autopass";
    }

    libxl__exec(gc, autopass_fd, -1, -1, args[0], args, NULL);

 x_fail:
    GC_FREE;
    return ERROR_FAIL;
}

int libxl__device_console_add(libxl__gc *gc, uint32_t domid,
                              libxl__device_console *console,
                              libxl__domain_build_state *state,
                              libxl__device *device)
{
    flexarray_t *front, *ro_front;
    flexarray_t *back;
    int rc;

    if (console->devid && state) {
        rc = ERROR_INVAL;
        goto out;
    }
    if (!console->devid && (console->name || console->path)) {
        LOGD(ERROR, domid, "Primary console has invalid configuration");
        rc = ERROR_INVAL;
        goto out;
    }

    front = flexarray_make(gc, 16, 1);
    ro_front = flexarray_make(gc, 16, 1);
    back = flexarray_make(gc, 16, 1);

    device->backend_devid = console->devid;
    device->backend_domid = console->backend_domid;
    device->backend_kind = LIBXL__DEVICE_KIND_CONSOLE;
    device->devid = console->devid;
    device->domid = domid;
    device->kind = LIBXL__DEVICE_KIND_CONSOLE;

    flexarray_append(back, "frontend-id");
    flexarray_append(back, GCSPRINTF("%d", domid));
    flexarray_append(back, "online");
    flexarray_append(back, "1");
    flexarray_append(back, "state");
    flexarray_append(back, GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append(back, "protocol");
    flexarray_append(back, LIBXL_XENCONSOLE_PROTOCOL);

    if (console->name) {
        flexarray_append(ro_front, "name");
        flexarray_append(ro_front, console->name);
        flexarray_append(back, "name");
        flexarray_append(back, console->name);
    }
    if (console->connection) {
        flexarray_append(back, "connection");
        flexarray_append(back, console->connection);
    }
    if (console->path) {
        flexarray_append(back, "path");
        flexarray_append(back, console->path);
    }

    flexarray_append(front, "backend-id");
    flexarray_append(front, GCSPRINTF("%d", console->backend_domid));

    flexarray_append(ro_front, "limit");
    flexarray_append(ro_front, GCSPRINTF("%d", LIBXL_XENCONSOLE_LIMIT));
    flexarray_append(ro_front, "type");
    if (console->consback == LIBXL__CONSOLE_BACKEND_XENCONSOLED)
        flexarray_append(ro_front, "xenconsoled");
    else
        flexarray_append(ro_front, "ioemu");
    flexarray_append(ro_front, "output");
    flexarray_append(ro_front, console->output);
    flexarray_append(ro_front, "tty");
    if (state && state->console_tty)
        flexarray_append(ro_front, state->console_tty);
    else
        flexarray_append(ro_front, "");

    if (state) {
        flexarray_append(ro_front, "port");
        flexarray_append(ro_front, GCSPRINTF("%"PRIu32, state->console_port));
        flexarray_append(ro_front, "ring-ref");
        flexarray_append(ro_front, GCSPRINTF("%lu", state->console_mfn));
    } else {
        flexarray_append(front, "state");
        flexarray_append(front, GCSPRINTF("%d", XenbusStateInitialising));
        flexarray_append(front, "protocol");
        flexarray_append(front, LIBXL_XENCONSOLE_PROTOCOL);
    }
    libxl__device_generic_add(gc, XBT_NULL, device,
                              libxl__xs_kvs_of_flexarray(gc, back),
                              libxl__xs_kvs_of_flexarray(gc, front),
                              libxl__xs_kvs_of_flexarray(gc, ro_front));
    rc = 0;
out:
    return rc;
}

int libxl__device_vuart_add(libxl__gc *gc, uint32_t domid,
                            libxl__device_console *console,
                            libxl__domain_build_state *state)
{
    libxl__device device;
    flexarray_t *ro_front;
    flexarray_t *back;
    int rc;

    ro_front = flexarray_make(gc, 16, 1);
    back = flexarray_make(gc, 16, 1);

    device.backend_devid = console->devid;
    device.backend_domid = console->backend_domid;
    device.backend_kind = LIBXL__DEVICE_KIND_VUART;
    device.devid = console->devid;
    device.domid = domid;
    device.kind = LIBXL__DEVICE_KIND_VUART;

    flexarray_append(back, "frontend-id");
    flexarray_append(back, GCSPRINTF("%d", domid));
    flexarray_append(back, "online");
    flexarray_append(back, "1");
    flexarray_append(back, "state");
    flexarray_append(back, GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append(back, "protocol");
    flexarray_append(back, LIBXL_XENCONSOLE_PROTOCOL);

    flexarray_append(ro_front, "port");
    flexarray_append(ro_front, GCSPRINTF("%"PRIu32, state->vuart_port));
    flexarray_append(ro_front, "ring-ref");
    flexarray_append(ro_front, GCSPRINTF("%"PRIu_xen_pfn, state->vuart_gfn));
    flexarray_append(ro_front, "limit");
    flexarray_append(ro_front, GCSPRINTF("%d", LIBXL_XENCONSOLE_LIMIT));
    flexarray_append(ro_front, "type");
    flexarray_append(ro_front, "xenconsoled");

    rc = libxl__device_generic_add(gc, XBT_NULL, &device,
                                   libxl__xs_kvs_of_flexarray(gc, back),
                                   NULL,
                                   libxl__xs_kvs_of_flexarray(gc, ro_front));
    return rc;
}

int libxl__init_console_from_channel(libxl__gc *gc,
                                     libxl__device_console *console,
                                     int dev_num,
                                     libxl_device_channel *channel)
{
    int rc;

    libxl__device_console_init(console);

    /* Perform validation first, allocate second. */

    if (channel->devid == -1)
        channel->devid = dev_num;

    if (!channel->name) {
        LOG(ERROR, "channel %d has no name", channel->devid);
        return ERROR_INVAL;
    }

    if (channel->backend_domname) {
        rc = libxl_domain_qualifier_to_domid(CTX, channel->backend_domname,
                                             &channel->backend_domid);
        if (rc < 0) return rc;
    }

    /* The xenstore 'output' node tells the backend what to connect the console
       to. If the channel has "connection = pty" then the "output" node will be
       set to "pty". If the channel has "connection = socket" then the "output"
       node will be set to "chardev:libxl-channel%d". This tells the qemu
       backend to proxy data between the console ring and the character device
       with id "libxl-channel%d". These character devices are currently defined
       on the qemu command-line via "-chardev" options in libxl_dm.c */

    switch (channel->connection) {
        case LIBXL_CHANNEL_CONNECTION_UNKNOWN:
            LOG(ERROR, "channel %d has no defined connection; "
                "to where should it be connected?", channel->devid);
            return ERROR_INVAL;
        case LIBXL_CHANNEL_CONNECTION_PTY:
            console->connection = libxl__strdup(NOGC, "pty");
            console->output = libxl__sprintf(NOGC, "pty");
            break;
        case LIBXL_CHANNEL_CONNECTION_SOCKET:
            if (!channel->u.socket.path) {
                LOG(ERROR, "channel %d has no path", channel->devid);
                return ERROR_INVAL;
            }
            console->connection = libxl__strdup(NOGC, "socket");
            console->path = libxl__strdup(NOGC, channel->u.socket.path);
            console->output = libxl__sprintf(NOGC, "chardev:libxl-channel%d",
                                             channel->devid);
            break;
        default:
            /* We've forgotten to add the clause */
            LOG(ERROR, "%s: missing implementation for channel connection %d",
                __func__, channel->connection);
            abort();
    }

    console->devid = channel->devid;
    console->consback = LIBXL__CONSOLE_BACKEND_IOEMU;
    console->backend_domid = channel->backend_domid;
    console->name = libxl__strdup(NOGC, channel->name);

    return 0;
}

static int libxl__device_channel_from_xenstore(libxl__gc *gc,
                                            const char *libxl_path,
                                            libxl_device_channel *channel)
{
    const char *tmp;
    int rc;

    libxl_device_channel_init(channel);

    rc = libxl__xs_read_checked(NOGC, XBT_NULL,
                                GCSPRINTF("%s/name", libxl_path),
                                (const char **)(&channel->name));
    if (rc) goto out;
    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/connection", libxl_path), &tmp);
    if (rc) goto out;
    if (!strcmp(tmp, "pty")) {
        channel->connection = LIBXL_CHANNEL_CONNECTION_PTY;
    } else if (!strcmp(tmp, "socket")) {
        channel->connection = LIBXL_CHANNEL_CONNECTION_SOCKET;
        rc = libxl__xs_read_checked(NOGC, XBT_NULL,
                                    GCSPRINTF("%s/path", libxl_path),
                                    (const char **)(&channel->u.socket.path));
        if (rc) goto out;
    } else {
        rc = ERROR_INVAL;
        goto out;
    }

    rc = 0;
 out:
    return rc;
}

static int libxl__append_channel_list(libxl__gc *gc,
                                              uint32_t domid,
                                              libxl_device_channel **channels,
                                              int *nchannels)
{
    char *libxl_dir_path = NULL;
    char **dir = NULL;
    unsigned int n = 0, devid = 0;
    libxl_device_channel *next = NULL;
    int rc = 0, i;

    libxl_dir_path = GCSPRINTF("%s/device/%s",
                               libxl__xs_libxl_path(gc, domid),
                               libxl__device_kind_to_string(
                               LIBXL__DEVICE_KIND_CONSOLE));
    dir = libxl__xs_directory(gc, XBT_NULL, libxl_dir_path, &n);
    if (!dir || !n)
      goto out;

    for (i = 0; i < n; i++) {
        const char *libxl_path, *name;
        libxl_device_channel *tmp;

        libxl_path = GCSPRINTF("%s/%s", libxl_dir_path, dir[i]);
        name = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/name", libxl_path));
        /* 'channels' are consoles with names, so ignore all consoles
           without names */
        if (!name) continue;
        tmp = realloc(*channels,
                      sizeof(libxl_device_channel) * (*nchannels + devid + 1));
        if (!tmp) {
          rc = ERROR_NOMEM;
          goto out;
        }
        *channels = tmp;
        next = *channels + *nchannels + devid;
        rc = libxl__device_channel_from_xenstore(gc, libxl_path, next);
        if (rc) goto out;
        next->devid = devid;
        devid++;
    }
    *nchannels += devid;
    return 0;

 out:
    return rc;
}

libxl_device_channel *libxl_device_channel_list(libxl_ctx *ctx,
                                                uint32_t domid,
                                                int *num)
{
    GC_INIT(ctx);
    libxl_device_channel *channels = NULL;
    int rc;

    *num = 0;

    rc = libxl__append_channel_list(gc, domid, &channels, num);
    if (rc) goto out_err;

    GC_FREE;
    return channels;

out_err:
    LOGD(ERROR, domid, "Unable to list channels");
    while (*num) {
        (*num)--;
        libxl_device_channel_dispose(&channels[*num]);
    }
    free(channels);
    return NULL;
}

int libxl_device_channel_getinfo(libxl_ctx *ctx, uint32_t domid,
                                 libxl_device_channel *channel,
                                 libxl_channelinfo *channelinfo)
{
    GC_INIT(ctx);
    char *fe_path, *libxl_path;
    char *val;
    int rc;

    channelinfo->devid = channel->devid;

    fe_path = libxl__domain_device_frontend_path(gc, domid,
                                                 channelinfo->devid + 1,
                                                 LIBXL__DEVICE_KIND_CONSOLE);
    libxl_path = libxl__domain_device_libxl_path(gc, domid,
                                                 channelinfo->devid + 1,
                                                 LIBXL__DEVICE_KIND_CONSOLE);

    channelinfo->backend = xs_read(ctx->xsh, XBT_NULL,
                                   GCSPRINTF("%s/backend", libxl_path), NULL);
    if (!channelinfo->backend) {
        GC_FREE;
        return ERROR_FAIL;
    }
    rc = libxl__backendpath_parse_domid(gc, channelinfo->backend,
                                        &channelinfo->backend_id);
    if (rc) goto out;

    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/state", fe_path));
    channelinfo->state = val ? strtoul(val, NULL, 10) : -1;
    channelinfo->frontend = libxl__strdup(NOGC, fe_path);
    channelinfo->frontend_id = domid;
    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/ring-ref", fe_path));
    channelinfo->rref = val ? strtoul(val, NULL, 10) : -1;
    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/port", fe_path));
    channelinfo->evtch = val ? strtoul(val, NULL, 10) : -1;

    channelinfo->connection = channel->connection;
    switch (channel->connection) {
         case LIBXL_CHANNEL_CONNECTION_PTY:
             val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/tty", fe_path));
             /*
              * It is obviously very wrong for this value to be in the
              * frontend.  But in XSA-175 we don't want to re-engineer
              * this because other xenconsole code elsewhere (some
              * even out of tree, perhaps) expects this node to be
              * here.
              *
              * FE/pty is readonly for the guest.  It always exists if
              * FE does because libxl__device_console_add
              * unconditionally creates it and nothing deletes it.
              *
              * The guest can delete the whole FE (which it has write
              * privilege on) but the containing directories
              * /local/GUEST[/device[/console]] are also RO for the
              * guest.  So if the guest deletes FE it cannot recreate
              * it.
              *
              * Therefore the guest cannot cause FE/pty to contain bad
              * data, although it can cause it to not exist.
              */
             if (!val) val = "/NO-SUCH-PATH";
             channelinfo->u.pty.path = strdup(val);
             break;
         default:
             break;
    }
    rc = 0;
 out:
    GC_FREE;
    return rc;
}

static int libxl__device_vkb_setdefault(libxl__gc *gc, uint32_t domid,
                                        libxl_device_vkb *vkb, bool hotplug)
{
    return libxl__resolve_domid(gc, vkb->backend_domname, &vkb->backend_domid);
}

static int libxl__device_from_vkb(libxl__gc *gc, uint32_t domid,
                                  libxl_device_vkb *vkb,
                                  libxl__device *device)
{
    device->backend_devid = vkb->devid;
    device->backend_domid = vkb->backend_domid;
    device->backend_kind = LIBXL__DEVICE_KIND_VKBD;
    device->devid = vkb->devid;
    device->domid = domid;
    device->kind = LIBXL__DEVICE_KIND_VKBD;

    return 0;
}

int libxl_device_vkb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vkb *vkb,
                         const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int rc;

    rc = libxl__device_add(gc, domid, &libxl__vkb_devtype, vkb);
    if (rc) {
        LOGD(ERROR, domid, "Unable to add vkb device");
        goto out;
    }

out:
    libxl__ao_complete(egc, ao, rc);
    return AO_INPROGRESS;
}

static LIBXL_DEFINE_UPDATE_DEVID(vkb)

static int libxl__device_vfb_setdefault(libxl__gc *gc, uint32_t domid,
                                        libxl_device_vfb *vfb, bool hotplug)
{
    int rc;

    libxl_defbool_setdefault(&vfb->vnc.enable, true);
    if (libxl_defbool_val(vfb->vnc.enable)) {
        if (!vfb->vnc.listen) {
            vfb->vnc.listen = strdup("127.0.0.1");
            if (!vfb->vnc.listen) return ERROR_NOMEM;
        }

        libxl_defbool_setdefault(&vfb->vnc.findunused, true);
    } else {
        libxl_defbool_setdefault(&vfb->vnc.findunused, false);
    }

    libxl_defbool_setdefault(&vfb->sdl.enable, false);
    libxl_defbool_setdefault(&vfb->sdl.opengl, false);

    rc = libxl__resolve_domid(gc, vfb->backend_domname, &vfb->backend_domid);
    return rc;
}

int libxl_device_vfb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vfb *vfb,
                         const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int rc;

    rc = libxl__device_add(gc, domid, &libxl__vfb_devtype, vfb);
    if (rc) {
        LOGD(ERROR, domid, "Unable to add vfb device");
        goto out;
    }

out:
    libxl__ao_complete(egc, ao, rc);
    return AO_INPROGRESS;
}

static int libxl__set_xenstore_vfb(libxl__gc *gc, uint32_t domid,
                                   libxl_device_vfb *vfb,
                                  flexarray_t *back, flexarray_t *front,
                                  flexarray_t *ro_front)
{
    flexarray_append_pair(back, "vnc",
                          libxl_defbool_val(vfb->vnc.enable) ? "1" : "0");
    flexarray_append_pair(back, "vnclisten", vfb->vnc.listen);
    flexarray_append_pair(back, "vncpasswd", vfb->vnc.passwd);
    flexarray_append_pair(back, "vncdisplay",
                          GCSPRINTF("%d", vfb->vnc.display));
    flexarray_append_pair(back, "vncunused",
                          libxl_defbool_val(vfb->vnc.findunused) ? "1" : "0");
    flexarray_append_pair(back, "sdl",
                          libxl_defbool_val(vfb->sdl.enable) ? "1" : "0");
    flexarray_append_pair(back, "opengl",
                          libxl_defbool_val(vfb->sdl.opengl) ? "1" : "0");
    if (vfb->sdl.xauthority) {
        flexarray_append_pair(back, "xauthority", vfb->sdl.xauthority);
    }
    if (vfb->sdl.display) {
        flexarray_append_pair(back, "display", vfb->sdl.display);
    }

    return 0;
}

/* The following functions are defined:
 * libxl_device_vkb_remove
 * libxl_device_vkb_destroy
 * libxl_device_vfb_remove
 * libxl_device_vfb_destroy
 */

/* channel/console hotunplug is not implemented. There are 2 possibilities:
 * 1. add support for secondary consoles to xenconsoled
 * 2. dynamically add/remove qemu chardevs via qmp messages. */

/* vkb */

#define libxl__add_vkbs NULL
#define libxl_device_vkb_list NULL
#define libxl_device_vkb_compare NULL

LIBXL_DEFINE_DEVICE_REMOVE(vkb)

DEFINE_DEVICE_TYPE_STRUCT(vkb, VKBD,
    .skip_attach = 1
);

#define libxl__add_vfbs NULL
#define libxl_device_vfb_list NULL
#define libxl_device_vfb_compare NULL

static LIBXL_DEFINE_UPDATE_DEVID(vfb)
static LIBXL_DEFINE_DEVICE_FROM_TYPE(vfb)

/* vfb */
LIBXL_DEFINE_DEVICE_REMOVE(vfb)

DEFINE_DEVICE_TYPE_STRUCT(vfb, VFB,
    .skip_attach = 1,
    .set_xenstore_config = (device_set_xenstore_config_fn_t)
                           libxl__set_xenstore_vfb,
);

libxl_xen_console_reader *
    libxl_xen_console_read_start(libxl_ctx *ctx, int clear)
{
    GC_INIT(ctx);
    libxl_xen_console_reader *cr;
    unsigned int size = 16384;

    cr = libxl__zalloc(NOGC, sizeof(libxl_xen_console_reader));
    cr->buffer = libxl__zalloc(NOGC, size);
    cr->size = size;
    cr->count = size;
    cr->clear = clear;
    cr->incremental = 1;

    GC_FREE;
    return cr;
}

/* return values:                                          *line_r
 *   1          success, whole line obtained from buffer    non-0
 *   0          no more lines available right now           0
 *   negative   error code ERROR_*                          0
 * On success *line_r is updated to point to a nul-terminated
 * string which is valid until the next call on the same console
 * reader.  The libxl caller may overwrite parts of the string
 * if it wishes. */
int libxl_xen_console_read_line(libxl_ctx *ctx,
                                libxl_xen_console_reader *cr,
                                char **line_r)
{
    int ret;
    GC_INIT(ctx);

    memset(cr->buffer, 0, cr->size);
    ret = xc_readconsolering(ctx->xch, cr->buffer, &cr->count,
                             cr->clear, cr->incremental, &cr->index);
    if (ret < 0) {
        LOGE(ERROR, "reading console ring buffer");
        GC_FREE;
        return ERROR_FAIL;
    }
    if (!ret) {
        if (cr->count) {
            *line_r = cr->buffer;
            ret = 1;
        } else {
            *line_r = NULL;
            ret = 0;
        }
    }

    GC_FREE;
    return ret;
}

void libxl_xen_console_read_finish(libxl_ctx *ctx,
                                   libxl_xen_console_reader *cr)
{
    free(cr->buffer);
    free(cr);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
