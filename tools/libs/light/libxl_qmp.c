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
 *
 * WARNING - Do not trust QEMU when writing codes for new commands or when
 *           improving the client code.
 */

/*
 * Logic used to send command to QEMU
 *
 * qmp_open():
 *  Will open a socket and connect to QEMU.
 *
 * qmp_next():
 *  Will read data sent by QEMU and then call qmp_handle_response() once a
 *  complete QMP message is received.
 *  The function return on timeout/error or once every data received as been
 *  processed.
 *
 * qmp_handle_response()
 *  This process json messages received from QEMU and update different list and
 *  may call callback function.
 *  `libxl__qmp_handler.wait_for_id` is reset once a message with this ID is
 *    processed.
 *  `libxl__qmp_handler.callback_list`: list with ID of command sent and
 *    optional assotiated callback function. The return value of a callback is
 *    set in context.
 *
 * qmp_send():
 *  Simply prepare a QMP command and send it to QEMU.
 *  It also add a `struct callback_id_pair` on the
 *  `libxl__qmp_handler.callback_list` via qmp_send_prepare().
 *
 * qmp_synchronous_send():
 *  This function calls qmp_send(), then wait for QEMU to reply to the command.
 *  The wait is done by calling qmp_next() over and over again until either
 *  there is a response for the command or there is an error.
 *
 *  An ID can be set for each QMP command, this is set into
 *  `libxl__qmp_handler.wait_for_id`. qmp_next will check every response's ID
 *  again this field and change the value of the field once the ID is found.
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

#ifdef DEBUG_QMP_CLIENT
#  define LOG_QMP(f, ...) LOGD(DEBUG, ev->domid, f, ##__VA_ARGS__)
#else
#  define LOG_QMP(f, ...)
#endif

/*
 * QMP types & constant
 */

#define QMP_RECEIVE_BUFFER_SIZE 4096
#define QMP_MAX_SIZE_RX_BUF MB(1)

/*
 * qmp_callback_t is call whenever a message from QMP contain the "id"
 * associated with the callback.
 * "tree" contain the JSON tree that is in "return" of a QMP message. If QMP
 * sent an error message, "tree" will be NULL.
 */
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
    int qmp_fd;
    bool connected;
    time_t timeout;
    /* wait_for_id will be used by the synchronous send function */
    int wait_for_id;

    char buffer[QMP_RECEIVE_BUFFER_SIZE + 1];

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

static libxl__qmp_message_type qmp_response_type(const libxl__json_object *o)
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

    type = qmp_response_type(resp);
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

/*
 * return values:
 *   < 0  if qemu's version <  asked version
 *   = 0  if qemu's version == asked version
 *   > 0  if qemu's version >  asked version
 */
static int qmp_ev_qemu_compare_version(libxl__ev_qmp *ev, int major,
                                       int minor, int micro)
{
#define CHECK_VERSION(level) do { \
    if (ev->qemu_version.level > (level)) return +1; \
    if (ev->qemu_version.level < (level)) return -1; \
} while (0)

    CHECK_VERSION(major);
    CHECK_VERSION(minor);
    CHECK_VERSION(micro);

#undef CHECK_VERSION

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
    GC_INIT(qmp->ctx);
    int ret = -1;
    int i = 0;
    struct sockaddr_un addr;

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

    ret = libxl__prepare_sockaddr_un(gc, &addr, qmp_socket_path, "QMP socket");
    if (ret)
        goto out;

    do {
        ret = connect(qmp->qmp_fd, (struct sockaddr *) &addr, sizeof(addr));
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

    GC_FREE;
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

        DEBUG_REPORT_RECEIVED(qmp->domid, qmp->buffer, (int)rd);

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

        do {
            char *end = NULL;

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

static char *qmp_prepare_cmd(libxl__gc *gc, const char *cmd,
                             const libxl__json_object *args,
                             int id)
{
    yajl_gen hand = NULL;
    /* memory for 'buf' is owned by 'hand' */
    const unsigned char *buf;
    libxl_yajl_length len;
    yajl_gen_status s;
    char *ret = NULL;

    hand = libxl_yajl_gen_alloc(NULL);

    if (!hand) {
        return NULL;
    }

#if HAVE_YAJL_V2
    /* Disable beautify for data sent to QEMU */
    yajl_gen_config(hand, yajl_gen_beautify, 0);
#endif

    yajl_gen_map_open(hand);
    libxl__yajl_gen_asciiz(hand, "execute");
    libxl__yajl_gen_asciiz(hand, cmd);
    libxl__yajl_gen_asciiz(hand, "id");
    yajl_gen_integer(hand, id);
    if (args) {
        libxl__yajl_gen_asciiz(hand, "arguments");
        libxl__json_object_to_yajl_gen(gc, hand, args);
    }
    yajl_gen_map_close(hand);

    s = yajl_gen_get_buf(hand, &buf, &len);

    if (s != yajl_gen_status_ok)
        goto out;

    ret = libxl__sprintf(gc, "%*.*s\r\n", (int)len, (int)len, buf);

out:
    yajl_gen_free(hand);
    return ret;
}

static char *qmp_send_prepare(libxl__gc *gc, libxl__qmp_handler *qmp,
                              const char *cmd, libxl__json_object *args,
                              qmp_callback_t callback, void *opaque,
                              qmp_request_context *context)
{
    char *buf;
    callback_id_pair *elm;

    buf = qmp_prepare_cmd(gc, cmd, args, ++qmp->last_id_used);

    if (!buf) {
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

    LOGD(DEBUG, qmp->domid, "next qmp command: '%s'", buf);

out:
    return buf;
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
        return ERROR_FAIL;
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

void libxl__qmp_param_add_string(libxl__gc *gc,
                                 libxl__json_object **param,
                                 const char *name, const char *argument)
{
    libxl__json_object *obj;

    obj = libxl__json_object_alloc(gc, JSON_STRING);
    obj->u.string = libxl__strdup(gc, argument);

    qmp_parameters_common_add(gc, param, name, obj);
}

void libxl__qmp_param_add_bool(libxl__gc *gc,
                               libxl__json_object **param,
                               const char *name, bool b)
{
    libxl__json_object *obj;

    obj = libxl__json_object_alloc(gc, JSON_BOOL);
    obj->u.b = b;
    qmp_parameters_common_add(gc, param, name, obj);
}

void libxl__qmp_param_add_integer(libxl__gc *gc,
                                  libxl__json_object **param,
                                  const char *name, const int i)
{
    libxl__json_object *obj;

    obj = libxl__json_object_alloc(gc, JSON_INTEGER);
    obj->u.i = i;

    qmp_parameters_common_add(gc, param, name, obj);
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

int libxl__qmp_restore(libxl__gc *gc, int domid, const char *state_file)
{
    libxl__json_object *args = NULL;

    libxl__qmp_param_add_string(gc, &args, "filename", state_file);

    return qmp_run_command(gc, domid, "xen-load-devices-state", args,
                           NULL, NULL);
}

int libxl__qmp_resume(libxl__gc *gc, int domid)
{
    return qmp_run_command(gc, domid, "cont", NULL, NULL, NULL);
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
    libxl__qmp_param_add_string(gc, &data, "host", host);
    libxl__qmp_param_add_string(gc, &data, "port", port);

    libxl__qmp_param_add_string(gc, &addr, "type", "inet");
    qmp_parameters_common_add(gc, &addr, "data", data);

    qmp_parameters_common_add(gc, &args, "addr", addr);

    return qmp_run_command(gc, domid, "nbd-server-start", args, NULL, NULL);
}

int libxl__qmp_nbd_server_add(libxl__gc *gc, int domid, const char *disk)
{
    libxl__json_object *args = NULL;

    libxl__qmp_param_add_string(gc, &args, "device", disk);
    libxl__qmp_param_add_bool(gc, &args, "writable", true);

    return qmp_run_command(gc, domid, "nbd-server-add", args, NULL, NULL);
}

int libxl__qmp_start_replication(libxl__gc *gc, int domid, bool primary)
{
    libxl__json_object *args = NULL;

    libxl__qmp_param_add_bool(gc, &args, "enable", true);
    libxl__qmp_param_add_bool(gc, &args, "primary", primary);

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

    libxl__qmp_param_add_bool(gc, &args, "enable", false);
    libxl__qmp_param_add_bool(gc, &args, "primary", primary);

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

    libxl__qmp_param_add_string(gc, &args, "parent", parent);
    if (child)
        libxl__qmp_param_add_string(gc, &args, "child", child);
    if (node)
        libxl__qmp_param_add_string(gc, &args, "node", node);

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

    libxl__qmp_param_add_string(gc, &args, "command-line", command_line);

    return qmp_run_command(gc, domid, "human-monitor-command", args,
                           hmp_callback, output);
}


typedef struct {
    libxl__ev_qmp qmp;
    char **output; /* user pointer */
} qemu_monitor_command_state;

static void qemu_monitor_command_done(libxl__egc *, libxl__ev_qmp *,
                                      const libxl__json_object *response,
                                      int rc);

int libxl_qemu_monitor_command(libxl_ctx *ctx, uint32_t domid,
                               const char *command_line, char **output,
                               const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    qemu_monitor_command_state *qmcs;
    libxl__json_object *args = NULL;
    int rc;

    if (!output) {
        rc = ERROR_INVAL;
        goto out;
    }

    GCNEW(qmcs);
    libxl__ev_qmp_init(&qmcs->qmp);
    qmcs->qmp.ao = ao;
    qmcs->qmp.domid = domid;
    qmcs->qmp.payload_fd = -1;
    qmcs->qmp.callback = qemu_monitor_command_done;
    qmcs->output = output;
    libxl__qmp_param_add_string(gc, &args, "command-line", command_line);
    rc = libxl__ev_qmp_send(egc, &qmcs->qmp, "human-monitor-command", args);
out:
    if (rc) return AO_CREATE_FAIL(rc);
    return AO_INPROGRESS;
}

static void qemu_monitor_command_done(libxl__egc *egc, libxl__ev_qmp *qmp,
                                      const libxl__json_object *response,
                                      int rc)
{
    STATE_AO_GC(qmp->ao);
    qemu_monitor_command_state *qmcs = CONTAINER_OF(qmp, *qmcs, qmp);

    if (rc) goto out;

    if (!libxl__json_object_is_string(response)) {
        rc = ERROR_QEMU_API;
        LOGD(ERROR, qmp->domid, "Response has unexpected format");
        goto out;
    }

    *(qmcs->output) =
        libxl__strdup(NOGC, libxl__json_object_get_string(response));
    rc = 0;

out:
    libxl__ev_qmp_dispose(gc, qmp);
    libxl__ao_complete(egc, ao, rc);
}

/*
 * Functions using libxl__ev_qmp
 */

static void dm_stopped(libxl__egc *egc, libxl__ev_qmp *ev,
                       const libxl__json_object *response, int rc);
static void dm_state_fd_ready(libxl__egc *egc, libxl__ev_qmp *ev,
                              const libxl__json_object *response, int rc);
static void dm_state_save_to_fdset(libxl__egc *egc, libxl__ev_qmp *ev, int fdset);
static void dm_state_saved(libxl__egc *egc, libxl__ev_qmp *ev,
                           const libxl__json_object *response, int rc);

/* calls dsps->callback_device_model_done when done */
void libxl__qmp_suspend_save(libxl__egc *egc,
                             libxl__domain_suspend_state *dsps)
{
    EGC_GC;
    int rc;
    libxl__ev_qmp *ev = &dsps->qmp;

    ev->ao = dsps->ao;
    ev->domid = dsps->domid;
    ev->callback = dm_stopped;
    ev->payload_fd = -1;

    rc = libxl__ev_qmp_send(egc, ev, "stop", NULL);
    if (rc)
        goto error;

    return;

error:
    dsps->callback_device_model_done(egc, dsps, rc);
}

static void dm_stopped(libxl__egc *egc, libxl__ev_qmp *ev,
                       const libxl__json_object *response, int rc)
{
    EGC_GC;
    libxl__domain_suspend_state *dsps = CONTAINER_OF(ev, *dsps, qmp);
    const char *const filename = dsps->dm_savefile;
    uint32_t dm_domid = libxl_get_stubdom_id(CTX, dsps->domid);

    if (rc)
        goto error;

    if (dm_domid) {
        /* see Linux stubdom interface in docs/stubdom.txt */
        dm_state_save_to_fdset(egc, ev, 1);
        return;
    }

    ev->payload_fd = open(filename, O_WRONLY | O_CREAT, 0600);
    if (ev->payload_fd < 0) {
        LOGED(ERROR, ev->domid,
              "Failed to open file %s for QEMU", filename);
        rc = ERROR_FAIL;
        goto error;
    }

    ev->callback = dm_state_fd_ready;
    rc = libxl__ev_qmp_send(egc, ev, "add-fd", NULL);
    if (rc)
        goto error;

    return;

error:
    if (ev->payload_fd >= 0) {
        close(ev->payload_fd);
        libxl__remove_file(gc, filename);
        ev->payload_fd = -1;
    }
    dsps->callback_device_model_done(egc, dsps, rc);
}

static void dm_state_fd_ready(libxl__egc *egc, libxl__ev_qmp *ev,
                              const libxl__json_object *response, int rc)
{
    EGC_GC;
    int fdset;
    const libxl__json_object *o;
    libxl__domain_suspend_state *dsps = CONTAINER_OF(ev, *dsps, qmp);

    close(ev->payload_fd);
    ev->payload_fd = -1;

    if (rc)
        goto error;

    o = libxl__json_map_get("fdset-id", response, JSON_INTEGER);
    if (!o) {
        rc = ERROR_QEMU_API;
        goto error;
    }
    fdset = libxl__json_object_get_integer(o);
    dm_state_save_to_fdset(egc, ev, fdset);
    return;

error:
    assert(rc);
    libxl__remove_file(gc, dsps->dm_savefile);
    dsps->callback_device_model_done(egc, dsps, rc);
}

static void dm_state_save_to_fdset(libxl__egc *egc, libxl__ev_qmp *ev, int fdset)
{
    EGC_GC;
    int rc;
    libxl__json_object *args = NULL;
    libxl__domain_suspend_state *dsps = CONTAINER_OF(ev, *dsps, qmp);

    ev->callback = dm_state_saved;

    /* The `live` parameter was added to QEMU 2.11. It signals QEMU that
     * the save operation is for a live migration rather than for taking a
     * snapshot. */
    if (qmp_ev_qemu_compare_version(ev, 2, 11, 0) >= 0)
        libxl__qmp_param_add_bool(gc, &args, "live", dsps->live);
    QMP_PARAMETERS_SPRINTF(&args, "filename", "/dev/fdset/%d", fdset);
    rc = libxl__ev_qmp_send(egc, ev, "xen-save-devices-state", args);
    if (rc)
        goto error;

    return;

error:
    assert(rc);
    if (!libxl_get_stubdom_id(CTX, dsps->domid))
        libxl__remove_file(gc, dsps->dm_savefile);
    dsps->callback_device_model_done(egc, dsps, rc);
}

static void dm_state_saved(libxl__egc *egc, libxl__ev_qmp *ev,
                           const libxl__json_object *response, int rc)
{
    EGC_GC;
    libxl__domain_suspend_state *dsps = CONTAINER_OF(ev, *dsps, qmp);

    if (rc)
        libxl__remove_file(gc, dsps->dm_savefile);

    dsps->callback_device_model_done(egc, dsps, rc);
}


/* ------------ Implementation of libxl__ev_qmp ---------------- */

/*
 * Possible internal state compared to qmp_state:
 *
 * qmp_state     External   cfd    efd     id     rx_buf* tx_buf* msg* lock
 * disconnected   Idle       NULL   Idle    reset  free    free    free Idle
 * waiting_lock   Active     open   Idle    reset  used    free    set  Active
 * connecting     Active     open   IN      reset  used    free    set  Acquired
 * cap.neg        Active     open   IN|OUT  sent   used    cap_neg set  Acquired
 * cap.neg        Active     open   IN      sent   used    free    set  Acquired
 * connected      Connected  open   IN      any    used    free    free Acquired
 * waiting_reply  Active     open   IN|OUT  sent   used    free    set  Acquired
 * waiting_reply  Active     open   IN|OUT  sent   used    user's  free Acquired
 * waiting_reply  Active     open   IN      sent   used    free    free Acquired
 * broken[1]      none[2]    any    Active  any    any     any     any  any
 *
 * [1] When an internal function return an error, it can leave ev_qmp in a
 * `broken` state but only if the caller is another internal function.
 * That `broken` needs to be cleaned up, e.i. transitionned to the
 * `disconnected` state, before the control of ev_qmp is released outsides
 * of ev_qmp implementation.
 *
 * [2] This internal state should not be visible externally, see [1].
 *
 * Possible buffers states:
 * - receiving buffer:
 *                     free   used
 *     rx_buf           NULL   NULL or allocated
 *     rx_buf_size      0      allocation size of `rx_buf`
 *     rx_buf_used      0      <= rx_buf_size, actual data in the buffer
 * - transmitting buffer:
 *                     free   used
 *     tx_buf           NULL   contains data
 *     tx_buf_len       0      size of data
 *     tx_buf_off       0      <= tx_buf_len, data already sent
 * - queued user command:
 *                     free  set
 *     msg              NULL  contains data
 *     msg_id           0     id assoctiated with the command in `msg`
 *
 * - Allowed internal state transition:
 * disconnected                     -> waiting_lock
 * waiting_lock                     -> connecting
 * connection                       -> capability_negotiation
 * capability_negotiation/connected -> waiting_reply
 * waiting_reply                    -> connected
 * any                              -> broken
 * broken                           -> disconnected
 * any                              -> disconnected
 *
 * The QEMU Machine Protocol (QMP) specification can be found in the QEMU
 * repository:
 * https://git.qemu.org/?p=qemu.git;a=blob_plain;f=docs/interop/qmp-spec.txt
 */

/* prototypes */

static void qmp_ev_fd_callback(libxl__egc *egc, libxl__ev_fd *ev_fd,
                               int fd, short events, short revents);
static int qmp_ev_callback_writable(libxl__gc *gc,
                                    libxl__ev_qmp *ev, int fd);
static int qmp_ev_callback_readable(libxl__egc *egc,
                                    libxl__ev_qmp *ev, int fd);
static int qmp_ev_get_next_msg(libxl__egc *egc, libxl__ev_qmp *ev,
                               libxl__json_object **o_r);
static int qmp_ev_handle_message(libxl__egc *egc,
                                 libxl__ev_qmp *ev,
                                 const libxl__json_object *resp);

/* helpers */

static void qmp_ev_ensure_reading_writing(libxl__gc *gc, libxl__ev_qmp *ev)
    /* Update the state of `efd` to match the permited state
     * on entry: !disconnected */
{
    short events = POLLIN;

    if (ev->state == qmp_state_waiting_lock)
        /* We can't modify the efd yet, as it isn't registered. */
        return;

    if (ev->tx_buf)
        events |= POLLOUT;
    else if ((ev->state == qmp_state_waiting_reply) && ev->msg)
        events |= POLLOUT;

    libxl__ev_fd_modify(gc, &ev->efd, events);
}

static void qmp_ev_set_state(libxl__gc *gc, libxl__ev_qmp *ev,
                             libxl__qmp_state new_state)
    /* on entry: !broken and !disconnected */
{
    switch (new_state) {
    case qmp_state_disconnected:
        break;
    case qmp_state_waiting_lock:
        assert(ev->state == qmp_state_disconnected);
        break;
    case qmp_state_connecting:
        assert(ev->state == qmp_state_waiting_lock);
        break;
    case qmp_state_capability_negotiation:
        assert(ev->state == qmp_state_connecting);
        break;
    case qmp_state_waiting_reply:
        assert(ev->state == qmp_state_capability_negotiation ||
               ev->state == qmp_state_connected);
        break;
    case qmp_state_connected:
        assert(ev->state == qmp_state_waiting_reply);
        break;
    }

    ev->state = new_state;

    qmp_ev_ensure_reading_writing(gc, ev);
}

static void qmp_ev_tx_buf_clear(libxl__ev_qmp *ev)
{
    ev->tx_buf = NULL;
    ev->tx_buf_len = 0;
    ev->tx_buf_off = 0;
}

static int qmp_error_class_to_libxl_error_code(libxl__gc *gc,
                                               const char *eclass)
{
    const libxl_enum_string_table *t = libxl_error_string_table;
    const char skip[] = "QMP_";
    const size_t skipl = sizeof(skip) - 1;

    /* compare "QMP_GENERIC_ERROR" from libxl_error to "GenericError"
     * generated by the QMP server */

    for (; t->s; t++) {
            const char *s = eclass;
            const char *se = t->s;
        if (strncasecmp(t->s, skip, skipl))
            continue;
        se += skipl;
        while (*s && *se) {
            /* skip underscores */
            if (*se == '_') {
                se++;
                continue;
            }
            if (tolower(*s) != tolower(*se))
                break;
            s++, se++;
        }
        if (!*s && !*se)
            return t->v;
    }

    LOG(ERROR, "Unknown QMP error class '%s'", eclass);
    return ERROR_UNKNOWN_QMP_ERROR;
}

/* Setup connection */

static void qmp_ev_lock_aquired(libxl__egc *, libxl__ev_slowlock *,
                                int rc);
static void lock_error_callback(libxl__egc *, libxl__ev_immediate *);

static int qmp_ev_connect(libxl__egc *egc, libxl__ev_qmp *ev)
    /* disconnected -> waiting_lock/connecting but with `msg` free
     * on error: broken */
{
    EGC_GC;
    int fd;
    int rc;

    /* Convenience aliases */
    libxl__ev_slowlock *lock = &ev->lock;

    assert(ev->state == qmp_state_disconnected);

    libxl__carefd_begin();
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    ev->cfd = libxl__carefd_opened(CTX, fd);
    if (!ev->cfd) {
        LOGED(ERROR, ev->domid, "socket() failed");
        rc = ERROR_FAIL;
        goto out;
    }
    rc = libxl_fd_set_nonblock(CTX, libxl__carefd_fd(ev->cfd), 1);
    if (rc)
        goto out;

    qmp_ev_set_state(gc, ev, qmp_state_waiting_lock);

    lock->ao = ev->ao;
    lock->domid = ev->domid;
    lock->callback = qmp_ev_lock_aquired;
    libxl__ev_slowlock_lock(egc, &ev->lock);

    return 0;

out:
    return rc;
}

static void qmp_ev_lock_aquired(libxl__egc *egc, libxl__ev_slowlock *lock,
                                int rc)
    /* waiting_lock (with `lock' Acquired) -> connecting
     * on error: broken */
{
    libxl__ev_qmp *ev = CONTAINER_OF(lock, *ev, lock);
    EGC_GC;
    const char *qmp_socket_path;
    struct sockaddr_un un;
    int r;

    if (rc) goto out;

    qmp_socket_path = libxl__qemu_qmp_path(gc, ev->domid);

    LOGD(DEBUG, ev->domid, "Connecting to %s", qmp_socket_path);

    rc = libxl__prepare_sockaddr_un(gc, &un, qmp_socket_path,
                                    "QMP socket");
    if (rc)
        goto out;

    r = connect(libxl__carefd_fd(ev->cfd),
                (struct sockaddr *) &un, sizeof(un));
    if (r && errno != EINPROGRESS) {
        LOGED(ERROR, ev->domid, "Failed to connect to QMP socket %s",
              qmp_socket_path);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__ev_fd_register(gc, &ev->efd, qmp_ev_fd_callback,
                               libxl__carefd_fd(ev->cfd), POLLIN);
    if (rc)
        goto out;

    qmp_ev_set_state(gc, ev, qmp_state_connecting);

    return;

out:
    /* An error occurred and we need to let the caller know.  At this
     * point, we can only do so via the callback. Unfortunately, the
     * callback of libxl__ev_slowlock_lock() might be called synchronously,
     * but libxl__ev_qmp_send() promise that it will not call the callback
     * synchronously. So we have to arrange to call the callback
     * asynchronously. */
    ev->rc = rc;
    ev->ei.callback = lock_error_callback;
    libxl__ev_immediate_register(egc, &ev->ei);
}

static void lock_error_callback(libxl__egc *egc, libxl__ev_immediate *ei)
    /* broken -> disconnected */
{
    EGC_GC;
    libxl__ev_qmp *ev = CONTAINER_OF(ei, *ev, ei);

    int rc = ev->rc;

    /* On error, deallocate all private resources */
    libxl__ev_qmp_dispose(gc, ev);

    /* And tell libxl__ev_qmp user about the error */
    ev->callback(egc, ev, NULL, rc); /* must be last */
}

/* QMP FD callbacks */

static void qmp_ev_fd_callback(libxl__egc *egc, libxl__ev_fd *ev_fd,
                               int fd, short events, short revents)
    /* On entry, ev_fd is (of course) Active.  The ev_qmp may be in any
     * state where this is permitted.  qmp_ev_fd_callback will do the work
     * necessary to make progress, depending on the current state, and make
     * the appropriate state transitions and callbacks.  */
{
    libxl__ev_qmp *ev = CONTAINER_OF(ev_fd, *ev, efd);
    STATE_AO_GC(ev->ao);
    int rc;

    if (revents & (POLLHUP|POLLERR)) {
        int r;
        int error_val = 0;
        socklen_t opt_len = sizeof(error_val);

        r = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error_val, &opt_len);
        if (r)
            LOGED(ERROR, ev->domid, "getsockopt failed");
        if (!r && error_val) {
            errno = error_val;
            LOGED(ERROR, ev->domid, "error on QMP socket");
        } else {
            LOGD(ERROR, ev->domid,
                 "received POLLHUP|POLLERR from QMP socket");
        }
        rc = ERROR_PROTOCOL_ERROR_QMP;
        goto error;
    }

    if (revents & ~(POLLIN|POLLOUT)) {
        LOGD(ERROR, ev->domid,
             "unexpected poll event 0x%x on QMP socket (expected POLLIN "
             "and/or POLLOUT)",
            revents);
        rc = ERROR_FAIL;
        goto error;
    }

    if (revents & POLLOUT) {
        rc = qmp_ev_callback_writable(gc, ev, fd);
        if (rc)
            goto error;
    }

    if (revents & POLLIN) {
        rc = qmp_ev_callback_readable(egc, ev, fd);
        if (rc < 0)
            goto error;
        if (rc == 1) {
            /* user callback has been called */
            return;
        }
    }

    return;

error:
    assert(rc);

    LOGD(ERROR, ev->domid,
         "Error happened with the QMP connection to QEMU");

    /* On error, deallocate all private ressources */
    libxl__ev_qmp_dispose(gc, ev);

    /* And tell libxl__ev_qmp user about the error */
    ev->callback(egc, ev, NULL, rc); /* must be last */
}

static int qmp_ev_callback_writable(libxl__gc *gc,
                                    libxl__ev_qmp *ev, int fd)
    /* on entry: !disconnected
     * on return, one of these state transition:
     *   waiting_reply (with msg set) -> waiting_reply (with msg free)
     *   tx_buf set -> same state or tx_buf free
     * on error: broken */
{
    int rc;
    ssize_t r;

    if (ev->state == qmp_state_waiting_reply) {
        if (ev->msg) {
            assert(!ev->tx_buf);
            ev->tx_buf = ev->msg;
            ev->tx_buf_len = strlen(ev->msg);
            ev->tx_buf_off = 0;
            ev->id = ev->msg_id;
            ev->msg = NULL;
            ev->msg_id = 0;
        }
    }

    assert(ev->tx_buf);

    LOG_QMP("sending: '%.*s'", (int)ev->tx_buf_len, ev->tx_buf);

    /*
     * We will send a file descriptor associated with a command on the
     * first byte of this command.
     */
    if (ev->state == qmp_state_waiting_reply &&
        ev->payload_fd >= 0 &&
        ev->tx_buf_off == 0) {

        rc = libxl__sendmsg_fds(gc, fd, ev->tx_buf[ev->tx_buf_off],
                                1, &ev->payload_fd, "QMP socket");
        /* Check for EWOULDBLOCK, and return to try again later */
        if (rc == ERROR_NOT_READY)
            return 0;
        if (rc)
            return rc;
        ev->tx_buf_off++;
    }

    while (ev->tx_buf_off < ev->tx_buf_len) {
        ssize_t max_write = ev->tx_buf_len - ev->tx_buf_off;
        r = write(fd, ev->tx_buf + ev->tx_buf_off, max_write);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EWOULDBLOCK)
                break;
            LOGED(ERROR, ev->domid, "failed to write to QMP socket");
            return ERROR_FAIL;
        }
        assert(r > 0 && r <= max_write);
        ev->tx_buf_off += r;
    }

    if (ev->tx_buf_off == ev->tx_buf_len)
        qmp_ev_tx_buf_clear(ev);

    qmp_ev_ensure_reading_writing(gc, ev);

    return 0;
}

static int qmp_ev_callback_readable(libxl__egc *egc,
                                    libxl__ev_qmp *ev, int fd)
    /*
     * Return values:
     *   < 0    libxl error code
     *   0      success
     *   1      success, but a user callback has been called,
     *          `ev` should not be used anymore.
     *
     * This function will update the rx buffer and possibly update
     * ev->state:
     *  connecting             -> capability_negotiation
     *  capability_negotiation -> waiting_reply
     *  waiting_reply          -> connected
     * on error: broken
     */
{
    STATE_AO_GC(ev->ao);
    int rc;
    ssize_t r;

    while (1) {
        while (1) {
            libxl__json_object *o = NULL;

            /* parse rx buffer to find one json object */
            rc = qmp_ev_get_next_msg(egc, ev, &o);
            if (rc == ERROR_NOTFOUND)
                break;
            else if (rc)
                return rc;

            /* Must be last and return when the user callback is called */
            rc = qmp_ev_handle_message(egc, ev, o);
            if (rc)
                /* returns both rc values -ERROR_* and 1 */
                return rc;
        }

        /* Check if the buffer still have space, or increase size */
        if (ev->rx_buf_size - ev->rx_buf_used < QMP_RECEIVE_BUFFER_SIZE) {
            size_t newsize = ev->rx_buf_size * 2 + QMP_RECEIVE_BUFFER_SIZE;

            if (newsize > QMP_MAX_SIZE_RX_BUF) {
                LOGD(ERROR, ev->domid,
                     "QMP receive buffer is too big (%zu > %lld)",
                     newsize, QMP_MAX_SIZE_RX_BUF);
                return ERROR_BUFFERFULL;
            }
            ev->rx_buf_size = newsize;
            ev->rx_buf = libxl__realloc(gc, ev->rx_buf, ev->rx_buf_size);
        }

        r = read(fd, ev->rx_buf + ev->rx_buf_used,
                 ev->rx_buf_size - ev->rx_buf_used);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EWOULDBLOCK)
                break;
            LOGED(ERROR, ev->domid, "error reading QMP socket");
            return ERROR_FAIL;
        }

        if (r == 0) {
            LOGD(ERROR, ev->domid, "Unexpected EOF on QMP socket");
            return ERROR_PROTOCOL_ERROR_QMP;
        }

        LOG_QMP("received %ldB: '%.*s'", r,
                (int)r, ev->rx_buf + ev->rx_buf_used);

        ev->rx_buf_used += r;
        assert(ev->rx_buf_used <= ev->rx_buf_size);
    }

    return 0;
}

/* Handle messages received from QMP server */

static int qmp_ev_get_next_msg(libxl__egc *egc, libxl__ev_qmp *ev,
                               libxl__json_object **o_r)
    /* Find a JSON object and store it in o_r.
     * return ERROR_NOTFOUND if no object is found.
     *
     * !disconnected -> same state (with rx buffer updated)
     */
{
    STATE_AO_GC(ev->ao);
    size_t len;
    char *end = NULL;
    const char eom[] = "\r\n";
    const size_t eoml = sizeof(eom) - 1;
    libxl__json_object *o = NULL;

    if (!ev->rx_buf_used)
        return ERROR_NOTFOUND;

    /* Search for the end of a QMP message: "\r\n" */
    end = memmem(ev->rx_buf, ev->rx_buf_used, eom, eoml);
    if (!end)
        return ERROR_NOTFOUND;
    len = (end - ev->rx_buf) + eoml;

    LOG_QMP("parsing %luB: '%.*s'", len, (int)len, ev->rx_buf);

    /* Replace \r by \0 so that libxl__json_parse can use strlen */
    ev->rx_buf[len - eoml] = '\0';
    o = libxl__json_parse(gc, ev->rx_buf);

    if (!o) {
        LOGD(ERROR, ev->domid, "Parse error");
        return ERROR_PROTOCOL_ERROR_QMP;
    }

    ev->rx_buf_used -= len;
    memmove(ev->rx_buf, ev->rx_buf + len, ev->rx_buf_used);

    LOG_QMP("JSON object received: %s", JSON(o));

    *o_r = o;

    return 0;
}

static int qmp_ev_parse_error_messages(libxl__egc *egc,
                                       libxl__ev_qmp *ev,
                                       const libxl__json_object *resp);

static int qmp_ev_handle_message(libxl__egc *egc,
                                 libxl__ev_qmp *ev,
                                 const libxl__json_object *resp)
    /*
     * This function will handle every messages sent by the QMP server.
     * Return values:
     *   < 0    libxl error code
     *   0      success
     *   1      success, but a user callback has been called,
     *          `ev` should not be used anymore.
     *
     * Possible state changes:
     * connecting -> capability_negotiation
     * capability_negotiation -> waiting_reply
     * waiting_reply -> waiting_reply/connected
     *
     * on error: broken
     */
{
    STATE_AO_GC(ev->ao);
    int id;
    char *buf;
    int rc = 0;
    const libxl__json_object *o;
    const libxl__json_object *response;
    libxl__qmp_message_type type = qmp_response_type(resp);

    switch (type) {
    case LIBXL__QMP_MESSAGE_TYPE_QMP:
        /* greeting message */

        if (ev->state != qmp_state_connecting) {
            LOGD(ERROR, ev->domid,
                 "Unexpected greeting message received");
            return ERROR_PROTOCOL_ERROR_QMP;
        }

        /*
         * Store advertised QEMU version
         * { "QMP": { "version": {
         *     "qemu": { "major": int, "minor": int, "micro": int } } } }
         */
        o = libxl__json_map_get("QMP", resp, JSON_MAP);
        o = libxl__json_map_get("version", o, JSON_MAP);
        o = libxl__json_map_get("qemu", o, JSON_MAP);
#define GRAB_VERSION(level) do { \
        ev->qemu_version.level = libxl__json_object_get_integer( \
            libxl__json_map_get(#level, o, JSON_INTEGER)); \
        } while (0)
        GRAB_VERSION(major);
        GRAB_VERSION(minor);
        GRAB_VERSION(micro);
#undef GRAB_VERSION
        LOGD(DEBUG, ev->domid, "QEMU version: %d.%d.%d",
             ev->qemu_version.major,
             ev->qemu_version.minor,
             ev->qemu_version.micro);

        /* Prepare next message to send */
        assert(!ev->tx_buf);
        ev->id = ev->next_id++;
        buf = qmp_prepare_cmd(gc, "qmp_capabilities", NULL, ev->id);
        if (!buf) {
            LOGD(ERROR, ev->domid,
                 "Failed to generate qmp_capabilities command");
            return ERROR_FAIL;
        }
        ev->tx_buf = buf;
        ev->tx_buf_len = strlen(buf);
        ev->tx_buf_off = 0;
        qmp_ev_set_state(gc, ev, qmp_state_capability_negotiation);

        return 0;

    case LIBXL__QMP_MESSAGE_TYPE_RETURN:
    case LIBXL__QMP_MESSAGE_TYPE_ERROR:
        /*
         * Reply to a command (success/error) or server error
         *
         * In this cases, we are parsing two possibles responses:
         * - success:
         * { "return": json-value, "id": int }
         * - error:
         * { "error": { "class": string, "desc": string }, "id": int }
         */

        o = libxl__json_map_get("id", resp, JSON_INTEGER);
        if (!o) {
            /*
             * If "id" isn't present, an error occur on the server before
             * it has read the "id" provided by libxl.
             *
             * We deliberately squash all errors into
             * ERROR_PROTOCOL_ERROR_QMP as qmp_ev_parse_error_messages may
             * also return ERROR_QMP_* but those are reserved for errors
             * return by the caller's command.
             */
            qmp_ev_parse_error_messages(egc, ev, resp);
            return ERROR_PROTOCOL_ERROR_QMP;
        }

        id = libxl__json_object_get_integer(o);

        if (id != ev->id) {
            LOGD(ERROR, ev->domid,
                 "Message from QEMU with unexpected id %d: %s",
                 id, JSON(resp));
            return ERROR_PROTOCOL_ERROR_QMP;
        }

        switch (ev->state) {
        case qmp_state_capability_negotiation:
            if (type != LIBXL__QMP_MESSAGE_TYPE_RETURN) {
                LOGD(ERROR, ev->domid,
                     "Error during capability negotiation: %s",
                     JSON(resp));
                return ERROR_PROTOCOL_ERROR_QMP;
            }
            qmp_ev_set_state(gc, ev, qmp_state_waiting_reply);
            return 0;
        case qmp_state_waiting_reply:
            if (type == LIBXL__QMP_MESSAGE_TYPE_RETURN) {
                response = libxl__json_map_get("return", resp, JSON_ANY);
                rc = 0;
            } else {
                /* error message */
                response = NULL;
                rc = qmp_ev_parse_error_messages(egc, ev, resp);
            }
            qmp_ev_set_state(gc, ev, qmp_state_connected);
            ev->callback(egc, ev, response, rc); /* must be last */
            return 1;
        default:
            LOGD(ERROR, ev->domid, "Unexpected message: %s", JSON(resp));
            return ERROR_PROTOCOL_ERROR_QMP;
        }
        return 0;

    case LIBXL__QMP_MESSAGE_TYPE_EVENT:
        /* Events are ignored */
        return 0;

    case LIBXL__QMP_MESSAGE_TYPE_INVALID:
        LOGD(ERROR, ev->domid, "Unexpected message received: %s",
             JSON(resp));
        return ERROR_PROTOCOL_ERROR_QMP;

    default:
        abort();
    }

    return 0;
}

static int qmp_ev_parse_error_messages(libxl__egc *egc,
                                       libxl__ev_qmp *ev,
                                       const libxl__json_object *resp)
    /* no state change */
{
    STATE_AO_GC(ev->ao);
    int rc;
    const char *s;
    const libxl__json_object *o;
    const libxl__json_object *err;

    /*
     * { "error": { "class": string, "desc": string } }
     */

    err = libxl__json_map_get("error", resp, JSON_MAP);

    o = libxl__json_map_get("class", err, JSON_STRING);
    if (!o) {
        LOGD(ERROR, ev->domid,
             "Protocol error: missing 'class' member in error message");
        return ERROR_PROTOCOL_ERROR_QMP;
    }
    s = libxl__json_object_get_string(o);
    if (s)
        rc = qmp_error_class_to_libxl_error_code(gc, s);
    else
        rc = ERROR_PROTOCOL_ERROR_QMP;

    o = libxl__json_map_get("desc", err, JSON_STRING);
    if (!o) {
        LOGD(ERROR, ev->domid,
             "Protocol error: missing 'desc' member in error message");
        return ERROR_PROTOCOL_ERROR_QMP;
    }
    s = libxl__json_object_get_string(o);
    if (s)
        LOGD(ERROR, ev->domid, "%s", s);
    else
        LOGD(ERROR, ev->domid, "Received unexpected error: %s",
             JSON(resp));
    return rc;
}

/*
 * libxl__ev_qmp_*
 */

void libxl__ev_qmp_init(libxl__ev_qmp *ev)
    /* disconnected -> disconnected */
{
    /* Start with an message ID that is obviously generated by libxl
     * "xlq\0" */
    ev->next_id = 0x786c7100;

    ev->cfd = NULL;
    libxl__ev_fd_init(&ev->efd);
    ev->state = qmp_state_disconnected;
    ev->id = 0;

    ev->rx_buf = NULL;
    ev->rx_buf_size = ev->rx_buf_used = 0;
    qmp_ev_tx_buf_clear(ev);

    ev->msg = NULL;
    ev->msg_id = 0;

    ev->qemu_version.major = -1;
    ev->qemu_version.minor = -1;
    ev->qemu_version.micro = -1;

    libxl__ev_qmplock_init(&ev->lock);
    ev->rc = 0;
}

int libxl__ev_qmp_send(libxl__egc *egc, libxl__ev_qmp *ev,
                       const char *cmd, libxl__json_object *args)
    /* disconnected -> waiting_lock/connecting
     * connected -> waiting_reply (with msg set)
     * on error: disconnected */
{
    STATE_AO_GC(ev->ao);
    int rc;

    LOGD(DEBUG, ev->domid, " ev %p, cmd '%s'", ev, cmd);

    assert(ev->state == qmp_state_disconnected ||
           ev->state == qmp_state_connected);
    assert(cmd);

    /* Connect to QEMU if not already connected */
    if (ev->state == qmp_state_disconnected) {
        rc = qmp_ev_connect(egc, ev);
        if (rc)
            goto error;
    }

    /* Prepare user command */
    ev->msg_id = ev->next_id++;
    ev->msg = qmp_prepare_cmd(gc, cmd, args, ev->msg_id);
    if (!ev->msg) {
        LOGD(ERROR, ev->domid, "Failed to generate caller's command %s",
             cmd);
        rc = ERROR_FAIL;
        goto error;
    }
    if (ev->state == qmp_state_connected) {
        qmp_ev_set_state(gc, ev, qmp_state_waiting_reply);
    }

    return 0;

error:
    libxl__ev_qmp_dispose(gc, ev);
    return rc;
}

void libxl__ev_qmp_dispose(libxl__gc *gc, libxl__ev_qmp *ev)
    /* * -> disconnected */
{
    LOGD(DEBUG, ev->domid, " ev %p", ev);

    libxl__ev_fd_deregister(gc, &ev->efd);
    libxl__carefd_close(ev->cfd);
    libxl__ev_slowlock_dispose(gc, &ev->lock);

    libxl__ev_qmp_init(ev);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
