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
#  define DEBUG_REPORT_RECEIVED(buf, len) \
    LIBXL__LOG(qmp->ctx, LIBXL__LOG_DEBUG, "received: '%.*s'", len, buf)
#else
#  define DEBUG_REPORT_RECEIVED(buf, len) ((void)0)
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

    char buffer[QMP_RECEIVE_BUFFER_SIZE];
    libxl__yajl_ctx *yajl_ctx;

    libxl_ctx *ctx;
    uint32_t domid;

    int last_id_used;
    LIBXL_STAILQ_HEAD(callback_list, callback_id_pair) callback_list;
};

static int qmp_send(libxl__qmp_handler *qmp,
                    const char *cmd, libxl_key_value_list *args,
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
    path = libxl__sprintf(gc, "%s/serial/%d/tty", path, port);

    ret = libxl__xs_write(gc, XBT_NULL, path, "%s", chardev + 4);

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
                LIBXL__LOG(qmp->ctx, LIBXL__LOG_ERROR,
                           "Invalid serial port number: %s", s);
                return -1;
            }
            ret = store_serial_port_info(qmp, chardev, port_number);
            if (ret) {
                LIBXL__LOG_ERRNO(qmp->ctx, LIBXL__LOG_ERROR,
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
    path = libxl__sprintf(gc, "%s/console/%s", path, item);

    return libxl__xs_write(gc, XBT_NULL, path, "%s", value);
}

static int qmp_register_vnc_callback(libxl__qmp_handler *qmp,
                                     const libxl__json_object *o,
                                     void *unused)
{
    GC_INIT(qmp->ctx);
    const libxl__json_object *obj;
    const char *listen, *port;
    int rc = -1;

    if (!libxl__json_object_is_map(o)) {
        goto out;
    }

    if (libxl__json_map_get("enabled", o, JSON_FALSE)) {
        rc = 0;
        goto out;
    }

    obj = libxl__json_map_get("host", o, JSON_STRING);
    listen = libxl__json_object_get_string(obj);
    obj = libxl__json_map_get("service", o, JSON_STRING);
    port = libxl__json_object_get_string(obj);

    if (!listen || !port) {
        LIBXL__LOG(qmp->ctx, LIBXL__LOG_ERROR,
                   "Failed to retreive VNC connect information.");
        goto out;
    }

    rc = qmp_write_domain_console_item(gc, qmp->domid, "vnc-listen", listen);
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

static void qmp_handle_error_response(libxl__qmp_handler *qmp,
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

    LIBXL__LOG(qmp->ctx, LIBXL__LOG_ERROR,
               "received an error message from QMP server: %s",
               libxl__json_object_get_string(resp));
}

static int qmp_handle_response(libxl__qmp_handler *qmp,
                               const libxl__json_object *resp)
{
    libxl__qmp_message_type type = LIBXL__QMP_MESSAGE_TYPE_INVALID;

    type = qmp_response_type(qmp, resp);
    LIBXL__LOG(qmp->ctx, LIBXL__LOG_DEBUG,
               "message type: %s", libxl__qmp_message_type_to_string(type));

    switch (type) {
    case LIBXL__QMP_MESSAGE_TYPE_QMP:
        /* On the greeting message from the server, enable QMP capabilities */
        return enable_qmp_capabilities(qmp);
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
            LIBXL_STAILQ_REMOVE(
                &qmp->callback_list, pp, callback_id_pair, next);
            free(pp);
        }
        return 0;
    }
    case LIBXL__QMP_MESSAGE_TYPE_ERROR:
        qmp_handle_error_response(qmp, resp);
        return -1;
    case LIBXL__QMP_MESSAGE_TYPE_EVENT:
        return 0;
    case LIBXL__QMP_MESSAGE_TYPE_INVALID:
        return -1;
    }
    return 0;
}

/*
 * Handler functions
 */

static libxl__qmp_handler *qmp_init_handler(libxl__gc *gc, uint32_t domid)
{
    libxl__qmp_handler *qmp = NULL;

    qmp = calloc(1, sizeof (libxl__qmp_handler));
    if (qmp == NULL) {
        LIBXL__LOG_ERRNO(libxl__gc_owner(gc), LIBXL__LOG_ERROR,
                         "Failed to allocate qmp_handler");
        return NULL;
    }
    qmp->ctx = libxl__gc_owner(gc);
    qmp->domid = domid;
    qmp->timeout = 5;

    LIBXL_STAILQ_INIT(&qmp->callback_list);

    return qmp;
}

static int qmp_open(libxl__qmp_handler *qmp, const char *qmp_socket_path,
                    int timeout)
{
    int ret;
    int flags = 0;
    int i = 0;

    qmp->qmp_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (qmp->qmp_fd < 0) {
        return -1;
    }
    if ((flags = fcntl(qmp->qmp_fd, F_GETFL)) == -1) {
        flags = 0;
    }
    if (fcntl(qmp->qmp_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }
    ret = libxl_fd_set_cloexec(qmp->ctx, qmp->qmp_fd, 1);
    if (ret) return -1;

    memset(&qmp->addr, 0, sizeof (&qmp->addr));
    qmp->addr.sun_family = AF_UNIX;
    strncpy(qmp->addr.sun_path, qmp_socket_path,
            sizeof (qmp->addr.sun_path));

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
        return -1;
    } while ((++i / 5 <= timeout) && (usleep(200 * 1000) <= 0));

    return ret;
}

static void qmp_close(libxl__qmp_handler *qmp)
{
    callback_id_pair *pp = NULL;
    callback_id_pair *tmp = NULL;

    close(qmp->qmp_fd);
    LIBXL_STAILQ_FOREACH(pp, &qmp->callback_list, next) {
        if (tmp)
            free(tmp);
        tmp = pp;
    }
    if (tmp)
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
            LIBXL__LOG(qmp->ctx, LIBXL__LOG_ERROR, "timeout");
            return -1;
        } else if (ret < 0) {
            if (errno == EINTR)
                continue;
            LIBXL__LOG_ERRNO(qmp->ctx, LIBXL__LOG_ERROR, "Select error");
            return -1;
        }

        rd = read(qmp->qmp_fd, qmp->buffer, QMP_RECEIVE_BUFFER_SIZE);
        if (rd == 0) {
            LIBXL__LOG(qmp->ctx, LIBXL__LOG_ERROR, "Unexpected end of socket");
            return -1;
        } else if (rd < 0) {
            LIBXL__LOG_ERRNO(qmp->ctx, LIBXL__LOG_ERROR, "Socket read error");
            return rd;
        }

        DEBUG_REPORT_RECEIVED(qmp->buffer, rd);

        do {
            char *end = NULL;
            if (incomplete) {
                size_t current_pos = s - incomplete;
                incomplete = libxl__realloc(gc, incomplete,
                                            incomplete_size + rd);
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
                    rc = qmp_handle_response(qmp, o);
                    libxl__json_object_free(gc, o);
                } else {
                    LIBXL__LOG(qmp->ctx, LIBXL__LOG_ERROR,
                               "Parse error of : %s\n", s);
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
                              const char *cmd, libxl_key_value_list *args,
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
        libxl_key_value_list_gen_json(hand, args);
    }
    yajl_gen_map_close(hand);

    s = yajl_gen_get_buf(hand, &buf, &len);

    if (s) {
        LIBXL__LOG(qmp->ctx, LIBXL__LOG_ERROR,
                   "Failed to generate a qmp command");
        goto out;
    }

    elm = malloc(sizeof (callback_id_pair));
    if (elm == NULL) {
        LIBXL__LOG_ERRNO(qmp->ctx, LIBXL__LOG_ERROR,
                         "Failed to allocate a QMP callback");
        goto out;
    }
    elm->id = qmp->last_id_used;
    elm->callback = callback;
    elm->opaque = opaque;
    elm->context = context;
    LIBXL_STAILQ_INSERT_TAIL(&qmp->callback_list, elm, next);

    ret = libxl__strndup(gc, (const char*)buf, len);

    LIBXL__LOG(qmp->ctx, LIBXL__LOG_DEBUG, "next qmp command: '%s'", buf);

out:
    yajl_gen_free(hand);
    return ret;
}

static int qmp_send(libxl__qmp_handler *qmp,
                    const char *cmd, libxl_key_value_list *args,
                    qmp_callback_t callback, void *opaque,
                    qmp_request_context *context)
{
    char *buf = NULL;
    int rc = -1;
    libxl__gc gc; LIBXL_INIT_GC(gc,qmp->ctx);

    buf = qmp_send_prepare(&gc, qmp, cmd, args, callback, opaque, context);

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
    libxl__free_all(&gc);
    return rc;
}

static int qmp_synchronous_send(libxl__qmp_handler *qmp, const char *cmd,
                                libxl_key_value_list *args,
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
 * API
 */

libxl__qmp_handler *libxl__qmp_initialize(libxl__gc *gc, uint32_t domid)
{
    int ret = 0;
    libxl__qmp_handler *qmp = NULL;
    char *qmp_socket;

    qmp = qmp_init_handler(gc, domid);

    qmp_socket = libxl__sprintf(gc, "%s/qmp-libxl-%d",
                                libxl__run_dir_path(), domid);
    if ((ret = qmp_open(qmp, qmp_socket, QMP_SOCKET_CONNECT_TIMEOUT)) < 0) {
        LIBXL__LOG_ERRNO(qmp->ctx, LIBXL__LOG_ERROR, "Connection error");
        qmp_free_handler(qmp);
        return NULL;
    }

    LIBXL__LOG(qmp->ctx, LIBXL__LOG_DEBUG, "connected to %s", qmp_socket);

    /* Wait for the response to qmp_capabilities */
    while (!qmp->connected) {
        if ((ret = qmp_next(gc, qmp)) < 0) {
            break;
        }
    }

    if (!qmp->connected) {
        LIBXL__LOG(qmp->ctx, LIBXL__LOG_ERROR, "Failed to connect to QMP");
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
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *qmp_socket;

    qmp_socket = libxl__sprintf(gc, "%s/qmp-libxl-%d",
                                libxl__run_dir_path(), domid);
    if (unlink(qmp_socket) == -1) {
        if (errno != ENOENT) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR,
                             "Failed to remove QMP socket file %s",
                             qmp_socket);
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
    char *asked_id = libxl__sprintf(gc, PCI_PT_QDEV_ID,
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

int libxl__qmp_pci_add(libxl__gc *gc, int domid, libxl_device_pci *pcidev)
{
    libxl__qmp_handler *qmp = NULL;
    flexarray_t *parameters = NULL;
    libxl_key_value_list args = NULL;
    char *hostaddr = NULL;
    int rc = 0;

    qmp = libxl__qmp_initialize(gc, domid);
    if (!qmp)
        return -1;

    hostaddr = libxl__sprintf(gc, "%04x:%02x:%02x.%01x", pcidev->domain,
                              pcidev->bus, pcidev->dev, pcidev->func);
    if (!hostaddr)
        return -1;

    parameters = flexarray_make(6, 1);
    flexarray_append_pair(parameters, "driver", "xen-pci-passthrough");
    flexarray_append_pair(parameters, "id",
                          libxl__sprintf(gc, PCI_PT_QDEV_ID,
                                         pcidev->bus, pcidev->dev,
                                         pcidev->func));
    flexarray_append_pair(parameters, "hostaddr", hostaddr);
    if (pcidev->vdevfn) {
        flexarray_append_pair(parameters, "addr",
                              libxl__sprintf(gc, "%x.%x",
                                             PCI_SLOT(pcidev->vdevfn),
                                             PCI_FUNC(pcidev->vdevfn)));
    }
    args = libxl__xs_kvs_of_flexarray(gc, parameters, parameters->count);
    if (!args)
        return -1;

    rc = qmp_synchronous_send(qmp, "device_add", &args,
                              NULL, NULL, qmp->timeout);
    if (rc == 0) {
        rc = qmp_synchronous_send(qmp, "query-pci", NULL,
                                  pci_add_callback, pcidev, qmp->timeout);
    }

    flexarray_free(parameters);
    libxl__qmp_close(qmp);
    return rc;
}

static int qmp_device_del(libxl__gc *gc, int domid, char *id)
{
    libxl__qmp_handler *qmp = NULL;
    flexarray_t *parameters = NULL;
    libxl_key_value_list args = NULL;
    int rc = 0;

    qmp = libxl__qmp_initialize(gc, domid);
    if (!qmp)
        return ERROR_FAIL;

    parameters = flexarray_make(2, 1);
    flexarray_append_pair(parameters, "id", id);
    args = libxl__xs_kvs_of_flexarray(gc, parameters, parameters->count);
    if (!args)
        return ERROR_NOMEM;

    rc = qmp_synchronous_send(qmp, "device_del", &args,
                              NULL, NULL, qmp->timeout);

    flexarray_free(parameters);
    libxl__qmp_close(qmp);
    return rc;
}

int libxl__qmp_pci_del(libxl__gc *gc, int domid, libxl_device_pci *pcidev)
{
    char *id = NULL;

    id = libxl__sprintf(gc, PCI_PT_QDEV_ID,
                        pcidev->bus, pcidev->dev, pcidev->func);

    return qmp_device_del(gc, domid, id);
}

int libxl__qmp_save(libxl__gc *gc, int domid, const char *filename)
{
    libxl__qmp_handler *qmp = NULL;
    flexarray_t *parameters = NULL;
    libxl_key_value_list args = NULL;
    int rc = 0;

    qmp = libxl__qmp_initialize(gc, domid);
    if (!qmp)
        return ERROR_FAIL;

    parameters = flexarray_make(2, 1);
    if (!parameters) {
        rc = ERROR_NOMEM;
        goto out;
    }
    flexarray_append_pair(parameters, "filename", (char *)filename);
    args = libxl__xs_kvs_of_flexarray(gc, parameters, parameters->count);
    if (!args) {
        rc = ERROR_NOMEM;
        goto out2;
    }

    rc = qmp_synchronous_send(qmp, "xen-save-devices-state", &args,
                              NULL, NULL, qmp->timeout);

out2:
    flexarray_free(parameters);
out:
    libxl__qmp_close(qmp);
    return rc;
}

static int qmp_change(libxl__gc *gc, libxl__qmp_handler *qmp,
                      char *device, char *target, char *arg)
{
    flexarray_t *parameters = NULL;
    libxl_key_value_list args = NULL;
    int rc = 0;

    parameters = flexarray_make(6, 1);
    flexarray_append_pair(parameters, "device", device);
    flexarray_append_pair(parameters, "target", target);
    if (arg)
        flexarray_append_pair(parameters, "arg", arg);
    args = libxl__xs_kvs_of_flexarray(gc, parameters, parameters->count);
    if (!args)
        return ERROR_NOMEM;

    rc = qmp_synchronous_send(qmp, "change", &args,
                              NULL, NULL, qmp->timeout);

    flexarray_free(parameters);
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
