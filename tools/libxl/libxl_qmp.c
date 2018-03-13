/*
 * Copyright (C) 2011      Citrix Ltd.
 * Author Anthony PERARD <anthony.perard@citrix.com>
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

/*
 * This file implement a client for QMP (QEMU Monitor Protocol). For the
 * Specification, see in the QEMU repository.
 */

#include "libxl_osdeps.h" /* must come before any other headers */

#include <sys/un.h>

#include <yajl/yajl_gen.h>

#include "_libxl_list.h"
#include "libxl_internal.h"

/* #define DEBUG_RECEIVED */

#ifdef DEBUG_RECEIVED
#  define DEBUG_REPORT_RECEIVED(dom, buf, len) \
    LOGD(DEBUG, dom, "received: '%.*s'", len, buf)
#else
#  define DEBUG_REPORT_RECEIVED(dom, buf, len) ((void)0)
#endif

/*
 * QMP types & constant
 */

#define QMP_RECEIVE_BUFFER_SIZE 4096
#define PCI_PT_QDEV_ID "pci-pt-%02x_%02x.%01x"

typedef int (*qmp_callback_t)(libxl__qmp_handler *qmp,
                              const libxl__json_object *tree,
                              void *opaque);

typedef struct qmp_request_context {
    int rc;
} qmp_request_context;

typedef struct callback_id_pair {
    int id;
    qmp_callback_t callback;
    void *opaque;
    qmp_request_context *context;
    LIBXL_STAILQ_ENTRY(struct callback_id_pair) next;
} callback_id_pair;

struct libxl__qmp_handler {
    struct sockaddr_un addr;
    int qmp_fd;
    bool connected;
    time_t timeout;
    /* wait_for_id will be used by the synchronous send function */
    int wait_for_id;

    char buffer[QMP_RECEIVE_BUFFER_SIZE + 1];
    libxl__yajl_ctx *yajl_ctx;

    libxl_ctx *ctx;
    uint32_t domid;

    int last_id_used;
    LIBXL_STAILQ_HEAD(callback_list, callback_id_pair) callback_list;
    struct {
        int major;
        int minor;
        int micro;
    } version;
};

static int qmp_send(libxl__qmp_handler *qmp,
                    const char *cmd, libxl__json_object *args,
                    qmp_callback_t callback, void *opaque,
                    qmp_request_context *context);

static const int QMP_SOCKET_CONNECT_TIMEOUT = 5;

/*
 * QMP callbacks functions
 */

static int store_serial_port_info(libxl__qmp_handler *qmp,
                                  const char *chardev,
                                  int port)
{
    GC_INIT(qmp->ctx);
    char *path = NULL;
    int ret = 0;

    if (!(chardev && strncmp("pty:", chardev, 4) == 0)) {
        return 0;
    }

    path = libxl__xs_get_dompath(gc, qmp->domid);
    path = GCSPRINTF("%s/serial/%d/tty", path, port);

    ret = libxl__xs_printf(gc, XBT_NULL, path, "%s", chardev + 4);

    GC_FREE;
    return ret;
}

static int register_serials_chardev_callback(libxl__qmp_handler *qmp,
                                             const libxl__json_object *o,
                                             void *unused)
{
    const libxl__json_object *obj = NULL;
    const libxl__json_object *label = NULL;
    const char *s = NULL;
    int i = 0;
    const char *chardev = NULL;
    int ret = 0;

    for (i = 0; (obj = libxl__json_array_get(o, i)); i++) {
        if (!libxl__json_object_is_map(obj))
            continue;
        label = libxl__json_map_get("label", obj, JSON_STRING);
        s = libxl__json_object_get_string(label);

        if (s && strncmp("serial", s, strlen("serial")) == 0) {
            const libxl__json_object *filename = NULL;
            char *endptr = NULL;
            int port_number;

            filename = libxl__json_map_get("filename", obj, JSON_STRING);
            chardev = libxl__json_object_get_string(filename);

            s += strlen("serial");
            port_number = strtol(s, &endptr, 10);
            if (*s == 0 || *endptr != 0) {
                LIBXL__LOGD(qmp->ctx, LIBXL__LOG_ERROR, qmp->domid,
                            "Invalid serial port number: %s", s);
                return -1;
            }
            ret = store_serial_port_info(qmp, chardev, port_number);
            if (ret) {
                LIBXL__LOGD_ERRNO(qmp->ctx, LIBXL__LOG_ERROR, qmp->domid,
                                  "Failed to store serial port information"
                                  " in xenstore");
                return ret;
            }
        }
    };

    return ret;
}

static int qmp_write_domain_console_item(libxl__gc *gc, int domid,
                                         const char *item, const char *value)
{
    char *path;

    path = libxl__xs_get_dompath(gc, domid);
    path = GCSPRINTF("%s/console/%s", path, item);

    return libxl__xs_printf(gc, XBT_NULL, path, "%s", value);
}

static int qmp_register_vnc_callback(libxl__qmp_handler *qmp,
                                     const libxl__json_object *o,
                                     void *unused)
{
    GC_INIT(qmp->ctx);
    const libxl__json_object *obj;
    const char *addr, *port;
    int rc = -1;

    if (!libxl__json_object_is_map(o)) {
        goto out;
    }

    obj = libxl__json_map_get("enabled", o, JSON_BOOL);
    if (!obj || !libxl__json_object_get_bool(obj)) {
        rc = 0;
        goto out;
    }

    obj = libxl__json_map_get("host", o, JSON_STRING);
    addr = libxl__json_object_get_string(obj);
    obj = libxl__json_map_get("service", o, JSON_STRING);
    port = libxl__json_object_get_string(obj);

    if (!addr || !port) {
        LOGD(ERROR, qmp->domid, "Failed to retreive VNC connect information.");
        goto out;
    }

    rc = qmp_write_domain_console_item(gc, qmp->domid, "vnc-listen", addr);
    if (!rc)
        rc = qmp_write_domain_console_item(gc, qmp->domid, "vnc-port", port);

out:
    GC_FREE;
    return rc;
}

static int qmp_capabilities_callback(libxl__qmp_handler *qmp,
                                     const libxl__json_object *o, void *unused)
{
    qmp->connected = true;

    return 0;
}

/*
 * QMP commands
 */

static int enable_qmp_capabilities(libxl__qmp_handler *qmp)
{
    return qmp_send(qmp, "qmp_capabilities", NULL,
                    qmp_capabilities_callback, NULL, NULL);
}

/*
 * Helpers
 */

static libxl__qmp_message_type qmp_response_type(libxl__qmp_handler *qmp,
                                                 const libxl__json_object *o)
{
    libxl__qmp_message_type type;
    libxl__json_map_node *node = NULL;
    int i = 0;

    for (i = 0; (node = libxl__json_map_node_get(o, i)); i++) {
        if (libxl__qmp_message_type_from_string(node->map_key, &type) == 0)
            return type;
    }

    return LIBXL__QMP_MESSAGE_TYPE_INVALID;
}

static callback_id_pair *qmp_get_callback_from_id(libxl__qmp_handler *qmp,
                                                  const libxl__json_object *o)
{
    const libxl__json_object *id_object = libxl__json_map_get("id", o,
                                                              JSON_INTEGER);
    int id = -1;
    callback_id_pair *pp = NULL;

    if (id_object) {
        id = libxl__json_object_get_integer(id_object);

        LIBXL_STAILQ_FOREACH(pp, &qmp->callback_list, next) {
            if (pp->id == id) {
                return pp;
            }
        }
    }
    return NULL;
}

static void qmp_handle_error_response(libxl__gc *gc, libxl__qmp_handler *qmp,
                                      const libxl__json_object *resp)
{
    callback_id_pair *pp = qmp_get_callback_from_id(qmp, resp);

    resp = libxl__json_map_get("error", resp, JSON_MAP);
    resp = libxl__json_map_get("desc", resp, JSON_STRING);

    if (pp) {
        if (pp->callback) {
            int rc = pp->callback(qmp, NULL, pp->opaque);
            if (pp->context) {
                pp->context->rc = rc;
            }
        }
        if (pp->id == qmp->wait_for_id) {
            /* tell that the id have been processed */
            qmp->wait_for_id = 0;
        }
        LIBXL_STAILQ_REMOVE(&qmp->callback_list, pp, callback_id_pair, next);
        free(pp);
    }

    LOGD(ERROR, qmp->domid, "received an error message from QMP server: %s",
         libxl__json_object_get_string(resp));
}

static int qmp_handle_response(libxl__gc *gc, libxl__qmp_handler *qmp,
                               const libxl__json_object *resp)
{
    libxl__qmp_message_type type = LIBXL__QMP_MESSAGE_TYPE_INVALID;

    type = qmp_response_type(qmp, resp);
    LOGD(DEBUG, qmp->domid, "message type: %s", libxl__qmp_message_type_to_string(type));

    switch (type) {
    case LIBXL__QMP_MESSAGE_TYPE_QMP: {
        const libxl__json_object *o;
        o = libxl__json_map_get("QMP", resp, JSON_MAP);
        o = libxl__json_map_get("version", o, JSON_MAP);
        o = libxl__json_map_get("qemu", o, JSON_MAP);
        qmp->version.major = libxl__json_object_get_integer(
            libxl__json_map_get("major", o, JSON_INTEGER));
        qmp->version.minor = libxl__json_object_get_integer(
            libxl__json_map_get("minor", o, JSON_INTEGER));
        qmp->version.micro = libxl__json_object_get_integer(
            libxl__json_map_get("micro", o, JSON_INTEGER));
        LOGD(DEBUG, qmp->domid, "QEMU version: %d.%d.%d",
             qmp->version.major, qmp->version.minor, qmp->version.micro);
        /* On the greeting message from the server, enable QMP capabilities */
        return enable_qmp_capabilities(qmp);
    }
    case LIBXL__QMP_MESSAGE_TYPE_RETURN: {
        callback_id_pair *pp = qmp_get_callback_from_id(qmp, resp);

        if (pp) {
            if (pp->callback) {
                int rc = pp->callback(qmp,
                             libxl__json_map_get("return", resp, JSON_ANY),
                             pp->opaque);
                if (pp->context) {
                    pp->context->rc = rc;
                }
            }
            if (pp->id == qmp->wait_for_id) {
                /* tell that the id have been processed */
                qmp->wait_for_id = 0;
            }
            LIBXL_STAILQ_REMOVE(&qmp->callback_list, pp, callback_id_pair,
                                next);
            free(pp);
        }
        return 0;
    }
    case LIBXL__QMP_MESSAGE_TYPE_ERROR:
        qmp_handle_error_response(gc, qmp, resp);
        return -1;
    case LIBXL__QMP_MESSAGE_TYPE_EVENT:
        return 0;
    case LIBXL__QMP_MESSAGE_TYPE_INVALID:
        return -1;
    }
    return 0;
}

static bool qmp_qemu_check_version(libxl__qmp_handler *qmp, int major,
                                   int minor, int micro)
{
    return qmp->version.major > major ||
        (qmp->version.major == major &&
            (qmp->version.minor > minor ||
             (qmp->version.minor == minor && qmp->version.micro >= micro)));
}

/*
 * Handler functions
 */

static libxl__qmp_handler *qmp_init_handler(libxl__gc *gc, uint32_t domid)
{
    libxl__qmp_handler *qmp = NULL;

    qmp = calloc(1, sizeof (libxl__qmp_handler));
    if (qmp == NULL) {
        LOGED(ERROR, domid, "Failed to allocate qmp_handler");
        return NULL;
    }
    qmp->ctx = CTX;
    qmp->domid = domid;
    qmp->timeout = 5;

    LIBXL_STAILQ_INIT(&qmp->callback_list);

    return qmp;
}

static int qmp_open(libxl__qmp_handler *qmp, const char *qmp_socket_path,
                    int timeout)
{
    int ret = -1;
    int i = 0;

    qmp->qmp_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (qmp->qmp_fd < 0) {
        goto out;
    }
    ret = libxl_fd_set_nonblock(qmp->ctx, qmp->qmp_fd, 1);
    if (ret) {
        ret = -1;
        goto out;
    }
    ret = libxl_fd_set_cloexec(qmp->ctx, qmp->qmp_fd, 1);
    if (ret) {
        ret = -1;
        goto out;
    }

    if (sizeof (qmp->addr.sun_path) <= strlen(qmp_socket_path)) {
        ret = -1;
        goto out;
    }
    memset(&qmp->addr, 0, sizeof (qmp->addr));
    qmp->addr.sun_family = AF_UNIX;
    strncpy(qmp->addr.sun_path, qmp_socket_path,
            sizeof (qmp->addr.sun_path)-1);

    do {
        ret = connect(qmp->qmp_fd, (struct sockaddr *) &qmp->addr,
                      sizeof (qmp->addr));
        if (ret == 0)
            break;
        if (errno == ENOENT || errno == ECONNREFUSED) {
            /* ENOENT       : Socket may not have shown up yet
             * ECONNREFUSED : Leftover socket hasn't been removed yet */
            continue;
        }
        ret = -1;
        goto out;
    } while ((++i / 5 <= timeout) && (usleep(200 * 1000) <= 0));

out:
    if (ret == -1 && qmp->qmp_fd > -1) close(qmp->qmp_fd);

    return ret;
}

static void qmp_close(libxl__qmp_handler *qmp)
{
    callback_id_pair *pp = NULL;
    callback_id_pair *tmp = NULL;

    close(qmp->qmp_fd);
    LIBXL_STAILQ_FOREACH(pp, &qmp->callback_list, next) {
        free(tmp);
        tmp = pp;
    }
    free(tmp);
}

static int qmp_next(libxl__gc *gc, libxl__qmp_handler *qmp)
{
    ssize_t rd;
    char *s = NULL;
    char *s_end = NULL;

    char *incomplete = NULL;
    size_t incomplete_size = 0;
    int rc = 0;

    do {
        fd_set rfds;
        int ret = 0;
        struct timeval timeout = {
            .tv_sec = qmp->timeout,
            .tv_usec = 0,
        };

        FD_ZERO(&rfds);
        FD_SET(qmp->qmp_fd, &rfds);

        ret = select(qmp->qmp_fd + 1, &rfds, NULL, NULL, &timeout);
        if (ret == 0) {
            LOGD(ERROR, qmp->domid, "timeout");
            return -1;
        } else if (ret < 0) {
            if (errno == EINTR)
                continue;
            LOGED(ERROR, qmp->domid, "Select error");
            return -1;
        }

        rd = read(qmp->qmp_fd, qmp->buffer, QMP_RECEIVE_BUFFER_SIZE);
        if (rd == 0) {
            LOGD(ERROR, qmp->domid, "Unexpected end of socket");
            return -1;
        } else if (rd < 0) {
            LOGED(ERROR, qmp->domid, "Socket read error");
            return rd;
        }
        qmp->buffer[rd] = '\0';

        DEBUG_REPORT_RECEIVED(qmp->domid, qmp->buffer, rd);

        do {
            char *end = NULL;
            if (incomplete) {
                size_t current_pos = s - incomplete;
                incomplete = libxl__realloc(gc, incomplete,
                                            incomplete_size + rd + 1);
                strncat(incomplete + incomplete_size, qmp->buffer, rd);
                s = incomplete + current_pos;
                incomplete_size += rd;
                s_end = incomplete + incomplete_size;
            } else {
                incomplete = libxl__strndup(gc, qmp->buffer, rd);
                incomplete_size = rd;
                s = incomplete;
                s_end = s + rd;
                rd = 0;
            }

            end = strstr(s, "\r\n");
            if (end) {
                libxl__json_object *o = NULL;

                *end = '\0';

                o = libxl__json_parse(gc, s);

                if (o) {
                    rc = qmp_handle_response(gc, qmp, o);
                } else {
                    LOGD(ERROR, qmp->domid, "Parse error of : %s", s);
                    return -1;
                }

                s = end + 2;
            } else {
                break;
            }
        } while (s < s_end);
    } while (s < s_end);

    return rc;
}

static char *qmp_send_prepare(libxl__gc *gc, libxl__qmp_handler *qmp,
                              const char *cmd, libxl__json_object *args,
                              qmp_callback_t callback, void *opaque,
                              qmp_request_context *context)
{
    const unsigned char *buf = NULL;
    char *ret = NULL;
    libxl_yajl_length len = 0;
    yajl_gen_status s;
    yajl_gen hand;
    callback_id_pair *elm = NULL;

    hand = libxl_yajl_gen_alloc(NULL);

    if (!hand) {
        return NULL;
    }

    yajl_gen_map_open(hand);
    libxl__yajl_gen_asciiz(hand, "execute");
    libxl__yajl_gen_asciiz(hand, cmd);
    libxl__yajl_gen_asciiz(hand, "id");
    yajl_gen_integer(hand, ++qmp->last_id_used);
    if (args) {
        libxl__yajl_gen_asciiz(hand, "arguments");
        libxl__json_object_to_yajl_gen(gc, hand, args);
    }
    yajl_gen_map_close(hand);

    s = yajl_gen_get_buf(hand, &buf, &len);

    if (s) {
        LOGD(ERROR, qmp->domid, "Failed to generate a qmp command");
        goto out;
    }

    elm = malloc(sizeof (callback_id_pair));
    if (elm == NULL) {
        LOGED(ERROR, qmp->domid, "Failed to allocate a QMP callback");
        goto out;
    }
    elm->id = qmp->last_id_used;
    elm->callback = callback;
    elm->opaque = opaque;
    elm->context = context;
    LIBXL_STAILQ_INSERT_TAIL(&qmp->callback_list, elm, next);

    ret = libxl__strndup(gc, (const char*)buf, len);

    LOGD(DEBUG, qmp->domid, "next qmp command: '%s'", buf);

out:
    yajl_gen_free(hand);
    return ret;
}

static int qmp_send(libxl__qmp_handler *qmp,
                    const char *cmd, libxl__json_object *args,
                    qmp_callback_t callback, void *opaque,
                    qmp_request_context *context)
{
    char *buf = NULL;
    int rc = -1;
    GC_INIT(qmp->ctx);

    buf = qmp_send_prepare(gc, qmp, cmd, args, callback, opaque, context);

    if (buf == NULL) {
        goto out;
    }

    if (libxl_write_exactly(qmp->ctx, qmp->qmp_fd, buf, strlen(buf),
                            "QMP command", "QMP socket"))
        goto out;
    if (libxl_write_exactly(qmp->ctx, qmp->qmp_fd, "\r\n", 2,
                            "CRLF", "QMP socket"))
        goto out;

    rc = qmp->last_id_used;
out:
    GC_FREE;
    return rc;
}

static int qmp_synchronous_send(libxl__qmp_handler *qmp, const char *cmd,
                                libxl__json_object *args,
                                qmp_callback_t callback, void *opaque,
                                int ask_timeout)
{
    int id = 0;
    int ret = 0;
    GC_INIT(qmp->ctx);
    qmp_request_context context = { .rc = 0 };

    id = qmp_send(qmp, cmd, args, callback, opaque, &context);
    if (id <= 0) {
        return -1;
    }
    qmp->wait_for_id = id;

    while (qmp->wait_for_id == id) {
        if ((ret = qmp_next(gc, qmp)) < 0) {
            break;
        }
    }

    if (qmp->wait_for_id != id && ret == 0) {
        ret = context.rc;
    }

    GC_FREE;

    return ret;
}

static void qmp_free_handler(libxl__qmp_handler *qmp)
{
    free(qmp);
}

/*
 * QMP Parameters Helpers
 */
static void qmp_parameters_common_add(libxl__gc *gc,
                                      libxl__json_object **param,
                                      const char *name,
                                      libxl__json_object *obj)
{
    libxl__json_map_node *arg = NULL;

    if (!*param) {
        *param = libxl__json_object_alloc(gc, JSON_MAP);
    }

    GCNEW(arg);

    arg->map_key = libxl__strdup(gc, name);
    arg->obj = obj;

    flexarray_append((*param)->u.map, arg);
}

static void qmp_parameters_add_string(libxl__gc *gc,
                                      libxl__json_object **param,
                                      const char *name, const char *argument)
{
    libxl__json_object *obj;

    obj = libxl__json_object_alloc(gc, JSON_STRING);
    obj->u.string = libxl__strdup(gc, argument);

    qmp_parameters_common_add(gc, param, name, obj);
}

static void qmp_parameters_add_bool(libxl__gc *gc,
                                    libxl__json_object **param,
                                    const char *name, bool b)
{
    libxl__json_object *obj;

    obj = libxl__json_object_alloc(gc, JSON_BOOL);
    obj->u.b = b;
    qmp_parameters_common_add(gc, param, name, obj);
}

static void qmp_parameters_add_integer(libxl__gc *gc,
                                       libxl__json_object **param,
                                       const char *name, const int i)
{
    libxl__json_object *obj;

    obj = libxl__json_object_alloc(gc, JSON_INTEGER);
    obj->u.i = i;

    qmp_parameters_common_add(gc, param, name, obj);
}

#define QMP_PARAMETERS_SPRINTF(args, name, format, ...) \
    qmp_parameters_add_string(gc, args, name, GCSPRINTF(format, __VA_ARGS__))

/*
 * API
 */

libxl__qmp_handler *libxl__qmp_initialize(libxl__gc *gc, uint32_t domid)
{
    int ret = 0;
    libxl__qmp_handler *qmp = NULL;
    char *qmp_socket;

    qmp = qmp_init_handler(gc, domid);
    if (!qmp) return NULL;

    qmp_socket = GCSPRINTF("%s/qmp-libxl-%d", libxl__run_dir_path(), domid);
    if ((ret = qmp_open(qmp, qmp_socket, QMP_SOCKET_CONNECT_TIMEOUT)) < 0) {
        LOGED(ERROR, domid, "Connection error");
        qmp_free_handler(qmp);
        return NULL;
    }

    LOGD(DEBUG, domid, "connected to %s", qmp_socket);

    /* Wait for the response to qmp_capabilities */
    while (!qmp->connected) {
        if ((ret = qmp_next(gc, qmp)) < 0) {
            break;
        }
    }

    if (!qmp->connected) {
        LOGD(ERROR, domid, "Failed to connect to QMP");
        libxl__qmp_close(qmp);
        return NULL;
    }
    return qmp;
}

void libxl__qmp_close(libxl__qmp_handler *qmp)
{
    if (!qmp)
        return;
    qmp_close(qmp);
    qmp_free_handler(qmp);
}

void libxl__qmp_cleanup(libxl__gc *gc, uint32_t domid)
{
    char *qmp_socket;

    qmp_socket = GCSPRINTF("%s/qmp-libxl-%d", libxl__run_dir_path(), domid);
    if (unlink(qmp_socket) == -1) {
        if (errno != ENOENT) {
            LOGED(ERROR, domid, "Failed to remove QMP socket file %s", qmp_socket);
        }
    }

    qmp_socket = GCSPRINTF("%s/qmp-libxenstat-%d", libxl__run_dir_path(), domid);
    if (unlink(qmp_socket) == -1) {
        if (errno != ENOENT) {
            LOGED(ERROR, domid, "Failed to remove QMP socket file %s", qmp_socket);
        }
    }
}

int libxl__qmp_query_serial(libxl__qmp_handler *qmp)
{
    return qmp_synchronous_send(qmp, "query-chardev", NULL,
                                register_serials_chardev_callback,
                                NULL, qmp->timeout);
}

static int qmp_query_vnc(libxl__qmp_handler *qmp)
{
    return qmp_synchronous_send(qmp, "query-vnc", NULL,
                                qmp_register_vnc_callback,
                                NULL, qmp->timeout);
}

static int pci_add_callback(libxl__qmp_handler *qmp,
                            const libxl__json_object *response, void *opaque)
{
    libxl_device_pci *pcidev = opaque;
    const libxl__json_object *bus = NULL;
    GC_INIT(qmp->ctx);
    int i, j, rc = -1;
    char *asked_id = GCSPRINTF(PCI_PT_QDEV_ID,
                               pcidev->bus, pcidev->dev, pcidev->func);

    for (i = 0; (bus = libxl__json_array_get(response, i)); i++) {
        const libxl__json_object *devices = NULL;
        const libxl__json_object *device = NULL;
        const libxl__json_object *o = NULL;
        const char *id = NULL;

        devices = libxl__json_map_get("devices", bus, JSON_ARRAY);

        for (j = 0; (device = libxl__json_array_get(devices, j)); j++) {
             o = libxl__json_map_get("qdev_id", device, JSON_STRING);
             id = libxl__json_object_get_string(o);

             if (id && strcmp(asked_id, id) == 0) {
                 int dev_slot, dev_func;

                 o = libxl__json_map_get("slot", device, JSON_INTEGER);
                 if (!o)
                     goto out;
                 dev_slot = libxl__json_object_get_integer(o);
                 o = libxl__json_map_get("function", device, JSON_INTEGER);
                 if (!o)
                     goto out;
                 dev_func = libxl__json_object_get_integer(o);

                 pcidev->vdevfn = PCI_DEVFN(dev_slot, dev_func);

                 rc = 0;
                 goto out;
             }
        }
    }


out:
    GC_FREE;
    return rc;
}

static int qmp_run_command(libxl__gc *gc, int domid,
                           const char *cmd, libxl__json_object *args,
                           qmp_callback_t callback, void *opaque)
{
    libxl__qmp_handler *qmp = NULL;
    int rc = 0;

    qmp = libxl__qmp_initialize(gc, domid);
    if (!qmp)
        return ERROR_FAIL;

    rc = qmp_synchronous_send(qmp, cmd, args, callback, opaque, qmp->timeout);

    libxl__qmp_close(qmp);
    return rc;
}

int libxl__qmp_run_command_flexarray(libxl__gc *gc, int domid,
                                     const char *cmd, flexarray_t *array)
{
    libxl__json_object *args = NULL;
    int i;
    void *name, *value;

    for (i = 0; i < array->count; i += 2) {
        flexarray_get(array, i, &name);
        flexarray_get(array, i + 1, &value);
        qmp_parameters_add_string(gc, &args, (char *)name, (char *)value);
    }

    return qmp_run_command(gc, domid, cmd, args, NULL, NULL);
}

int libxl__qmp_pci_add(libxl__gc *gc, int domid, libxl_device_pci *pcidev)
{
    libxl__qmp_handler *qmp = NULL;
    libxl__json_object *args = NULL;
    char *hostaddr = NULL;
    int rc = 0;

    qmp = libxl__qmp_initialize(gc, domid);
    if (!qmp)
        return -1;

    hostaddr = GCSPRINTF("%04x:%02x:%02x.%01x", pcidev->domain,
                         pcidev->bus, pcidev->dev, pcidev->func);
    if (!hostaddr)
        return -1;

    qmp_parameters_add_string(gc, &args, "driver", "xen-pci-passthrough");
    QMP_PARAMETERS_SPRINTF(&args, "id", PCI_PT_QDEV_ID,
                           pcidev->bus, pcidev->dev, pcidev->func);
    qmp_parameters_add_string(gc, &args, "hostaddr", hostaddr);
    if (pcidev->vdevfn) {
        QMP_PARAMETERS_SPRINTF(&args, "addr", "%x.%x",
                               PCI_SLOT(pcidev->vdevfn), PCI_FUNC(pcidev->vdevfn));
    }
    /*
     * Version of QEMU prior to the XSA-131 fix did not support this
     * property and were effectively always in permissive mode. The
     * fix for XSA-131 switched the default to be restricted by
     * default and added the permissive property.
     *
     * Therefore in order to support both old and new QEMU we only set
     * the permissive flag if it is true. Users of older QEMU have no
     * reason to set the flag so this is ok.
     */
    if (pcidev->permissive)
        qmp_parameters_add_bool(gc, &args, "permissive", true);

    rc = qmp_synchronous_send(qmp, "device_add", args,
                              NULL, NULL, qmp->timeout);
    if (rc == 0) {
        rc = qmp_synchronous_send(qmp, "query-pci", NULL,
                                  pci_add_callback, pcidev, qmp->timeout);
    }

    libxl__qmp_close(qmp);
    return rc;
}

static int qmp_device_del(libxl__gc *gc, int domid, char *id)
{
    libxl__json_object *args = NULL;

    qmp_parameters_add_string(gc, &args, "id", id);
    return qmp_run_command(gc, domid, "device_del", args, NULL, NULL);
}

int libxl__qmp_pci_del(libxl__gc *gc, int domid, libxl_device_pci *pcidev)
{
    char *id = NULL;

    id = GCSPRINTF(PCI_PT_QDEV_ID, pcidev->bus, pcidev->dev, pcidev->func);

    return qmp_device_del(gc, domid, id);
}

int libxl__qmp_system_wakeup(libxl__gc *gc, int domid)
{
    return qmp_run_command(gc, domid, "system_wakeup", NULL, NULL, NULL);
}

int libxl__qmp_save(libxl__gc *gc, int domid, const char *filename, bool live)
{
    libxl__json_object *args = NULL;
    libxl__qmp_handler *qmp = NULL;
    int rc;

    qmp = libxl__qmp_initialize(gc, domid);
    if (!qmp)
        return ERROR_FAIL;

    qmp_parameters_add_string(gc, &args, "filename", (char *)filename);

    /* live parameter was added to QEMU 2.11. It signal QEMU that the save
     * operation is for a live migration rather that for taking a snapshot. */
    if (qmp_qemu_check_version(qmp, 2, 11, 0))
        qmp_parameters_add_bool(gc, &args, "live", live);

    rc = qmp_synchronous_send(qmp, "xen-save-devices-state", args,
                              NULL, NULL, qmp->timeout);
    libxl__qmp_close(qmp);
    return rc;
}

int libxl__qmp_restore(libxl__gc *gc, int domid, const char *state_file)
{
    libxl__json_object *args = NULL;

    qmp_parameters_add_string(gc, &args, "filename", state_file);

    return qmp_run_command(gc, domid, "xen-load-devices-state", args,
                           NULL, NULL);
}

static int qmp_change(libxl__gc *gc, libxl__qmp_handler *qmp,
                      char *device, char *target, char *arg)
{
    libxl__json_object *args = NULL;
    int rc = 0;

    qmp_parameters_add_string(gc, &args, "device", device);
    qmp_parameters_add_string(gc, &args, "target", target);
    if (arg) {
        qmp_parameters_add_string(gc, &args, "arg", arg);
    }

    rc = qmp_synchronous_send(qmp, "change", args,
                              NULL, NULL, qmp->timeout);

    return rc;
}

int libxl__qmp_stop(libxl__gc *gc, int domid)
{
    return qmp_run_command(gc, domid, "stop", NULL, NULL, NULL);
}

int libxl__qmp_resume(libxl__gc *gc, int domid)
{
    return qmp_run_command(gc, domid, "cont", NULL, NULL, NULL);
}

int libxl__qmp_set_global_dirty_log(libxl__gc *gc, int domid, bool enable)
{
    libxl__json_object *args = NULL;

    qmp_parameters_add_bool(gc, &args, "enable", enable);

    return qmp_run_command(gc, domid, "xen-set-global-dirty-log", args,
                           NULL, NULL);
}

int libxl__qmp_insert_cdrom(libxl__gc *gc, int domid,
                            const libxl_device_disk *disk)
{
    libxl__json_object *args = NULL;
    int dev_number = libxl__device_disk_dev_number(disk->vdev, NULL, NULL);

    QMP_PARAMETERS_SPRINTF(&args, "device", "ide-%i", dev_number);

    if (disk->format == LIBXL_DISK_FORMAT_EMPTY) {
        return qmp_run_command(gc, domid, "eject", args, NULL, NULL);
    } else {
        qmp_parameters_add_string(gc, &args, "target", disk->pdev_path);
        return qmp_run_command(gc, domid, "change", args, NULL, NULL);
    }
}

int libxl__qmp_cpu_add(libxl__gc *gc, int domid, int idx)
{
    libxl__json_object *args = NULL;

    qmp_parameters_add_integer(gc, &args, "id", idx);

    return qmp_run_command(gc, domid, "cpu-add", args, NULL, NULL);
}

static int query_cpus_callback(libxl__qmp_handler *qmp,
                               const libxl__json_object *response,
                               void *opaque)
{
    libxl_bitmap *map = opaque;
    unsigned int i;
    const libxl__json_object *cpu = NULL;
    int rc;
    GC_INIT(qmp->ctx);

    libxl_bitmap_set_none(map);
    for (i = 0; (cpu = libxl__json_array_get(response, i)); i++) {
        unsigned int idx;
        const libxl__json_object *o;

        o = libxl__json_map_get("CPU", cpu, JSON_INTEGER);
        if (!o) {
            LOGD(ERROR, qmp->domid, "Failed to retrieve CPU index.");
            rc = ERROR_FAIL;
            goto out;
        }

        idx = libxl__json_object_get_integer(o);
        libxl_bitmap_set(map, idx);
    }

    rc = 0;
out:
    GC_FREE;
    return rc;
}

int libxl__qmp_query_cpus(libxl__gc *gc, int domid, libxl_bitmap *map)
{
    return qmp_run_command(gc, domid, "query-cpus", NULL,
                           query_cpus_callback, map);
}

int libxl__qmp_nbd_server_start(libxl__gc *gc, int domid,
                                const char *host, const char *port)
{
    libxl__json_object *args = NULL;
    libxl__json_object *addr = NULL;
    libxl__json_object *data = NULL;

    /* 'addr': {
     *   'type': 'inet',
     *   'data': {
     *     'host': '$nbd_host',
     *     'port': '$nbd_port'
     *   }
     * }
     */
    qmp_parameters_add_string(gc, &data, "host", host);
    qmp_parameters_add_string(gc, &data, "port", port);

    qmp_parameters_add_string(gc, &addr, "type", "inet");
    qmp_parameters_common_add(gc, &addr, "data", data);

    qmp_parameters_common_add(gc, &args, "addr", addr);

    return qmp_run_command(gc, domid, "nbd-server-start", args, NULL, NULL);
}

int libxl__qmp_nbd_server_add(libxl__gc *gc, int domid, const char *disk)
{
    libxl__json_object *args = NULL;

    qmp_parameters_add_string(gc, &args, "device", disk);
    qmp_parameters_add_bool(gc, &args, "writable", true);

    return qmp_run_command(gc, domid, "nbd-server-add", args, NULL, NULL);
}

int libxl__qmp_start_replication(libxl__gc *gc, int domid, bool primary)
{
    libxl__json_object *args = NULL;

    qmp_parameters_add_bool(gc, &args, "enable", true);
    qmp_parameters_add_bool(gc, &args, "primary", primary);

    return qmp_run_command(gc, domid, "xen-set-replication", args, NULL, NULL);
}

int libxl__qmp_query_xen_replication_status(libxl__gc *gc, int domid)
{
    return qmp_run_command(gc, domid, "query-xen-replication-status", NULL,
                           NULL, NULL);
}

int libxl__qmp_colo_do_checkpoint(libxl__gc *gc, int domid)
{
    return qmp_run_command(gc, domid, "xen-colo-do-checkpoint",
                           NULL, NULL, NULL);
}

int libxl__qmp_stop_replication(libxl__gc *gc, int domid, bool primary)
{
    libxl__json_object *args = NULL;

    qmp_parameters_add_bool(gc, &args, "enable", false);
    qmp_parameters_add_bool(gc, &args, "primary", primary);

    return qmp_run_command(gc, domid, "xen-set-replication", args, NULL, NULL);
}

int libxl__qmp_nbd_server_stop(libxl__gc *gc, int domid)
{
    return qmp_run_command(gc, domid, "nbd-server-stop", NULL, NULL, NULL);
}

int libxl__qmp_x_blockdev_change(libxl__gc *gc, int domid, const char *parent,
                                 const char *child, const char *node)
{
    libxl__json_object *args = NULL;

    qmp_parameters_add_string(gc, &args, "parent", parent);
    if (child)
        qmp_parameters_add_string(gc, &args, "child", child);
    if (node)
        qmp_parameters_add_string(gc, &args, "node", node);

    return qmp_run_command(gc, domid, "x-blockdev-change", args, NULL, NULL);
}

static int hmp_callback(libxl__qmp_handler *qmp,
                        const libxl__json_object *response,
                        void *opaque)
{
    char **output = opaque;
    GC_INIT(qmp->ctx);
    int rc;

    rc = 0;
    if (!output)
        goto out;

    *output = NULL;

    if (libxl__json_object_is_string(response)) {
        *output = libxl__strdup(NOGC, libxl__json_object_get_string(response));
        goto out;
    }

    LOG(ERROR, "Response has unexpected format");
    rc = ERROR_FAIL;

out:
    GC_FREE;
    return rc;
}

int libxl__qmp_hmp(libxl__gc *gc, int domid, const char *command_line,
                   char **output)
{
    libxl__json_object *args = NULL;

    qmp_parameters_add_string(gc, &args, "command-line", command_line);

    return qmp_run_command(gc, domid, "human-monitor-command", args,
                           hmp_callback, output);
}

int libxl_qemu_monitor_command(libxl_ctx *ctx, uint32_t domid,
                               const char *command_line, char **output)
{
    GC_INIT(ctx);
    int rc;

    rc = libxl__qmp_hmp(gc, domid, command_line, output);

    GC_FREE;
    return rc;
}

int libxl__qmp_initializations(libxl__gc *gc, uint32_t domid,
                               const libxl_domain_config *guest_config)
{
    const libxl_vnc_info *vnc = libxl__dm_vnc(guest_config);
    libxl__qmp_handler *qmp = NULL;
    int ret = 0;

    qmp = libxl__qmp_initialize(gc, domid);
    if (!qmp)
        return -1;
    ret = libxl__qmp_query_serial(qmp);
    if (!ret && vnc && vnc->passwd) {
        ret = qmp_change(gc, qmp, "vnc", "password", vnc->passwd);
        qmp_write_domain_console_item(gc, domid, "vnc-pass", vnc->passwd);
    }
    if (!ret) {
        ret = qmp_query_vnc(qmp);
    }
    libxl__qmp_close(qmp);
    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
