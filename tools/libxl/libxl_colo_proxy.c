/*
 * Copyright (C) 2016 FUJITSU LIMITED
 * Author: Yang Hongyang <hongyang.yang@easystack.cn>
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

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"

#include <netlink/netlink.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Consistent with the new COLO netlink channel in kernel side */
#define NETLINK_COLO 28
#define COLO_DEFAULT_WAIT_TIME 500000

enum colo_netlink_op {
    COLO_QUERY_CHECKPOINT = (NLMSG_MIN_TYPE + 1),
    COLO_CHECKPOINT,
    COLO_FAILOVER,
    COLO_PROXY_INIT,
    COLO_PROXY_RESET, /* UNUSED, will be used for continuous FT */
};

/* ========= colo-proxy: helper functions ========== */

static int colo_proxy_send(libxl__colo_proxy_state *cps, uint8_t *buff,
                           uint64_t size, int type)
{
    struct sockaddr_nl sa;
    struct nlmsghdr msg;
    struct iovec iov;
    struct msghdr mh;
    int ret;

    STATE_AO_GC(cps->ao);

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;
    sa.nl_groups = 0;

    msg.nlmsg_len = NLMSG_SPACE(0);
    msg.nlmsg_flags = NLM_F_REQUEST;
    if (type == COLO_PROXY_INIT)
        msg.nlmsg_flags |= NLM_F_ACK;
    msg.nlmsg_seq = 0;
    msg.nlmsg_pid = cps->index;
    msg.nlmsg_type = type;

    iov.iov_base = &msg;
    iov.iov_len = msg.nlmsg_len;

    mh.msg_name = &sa;
    mh.msg_namelen = sizeof(sa);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = NULL;
    mh.msg_controllen = 0;
    mh.msg_flags = 0;

    ret = sendmsg(cps->sock_fd, &mh, 0);
    if (ret <= 0) {
        LOGD(ERROR, ao->domid, "can't send msg to kernel by netlink: %s",
            strerror(errno));
    }

    return ret;
}

static int colo_userspace_proxy_send(libxl__colo_proxy_state *cps,
                                     uint8_t *buff,
                                     uint32_t size)
{
    int ret = 0;
    uint32_t len = 0;

    len = htonl(size);
    ret = send(cps->sock_fd, (uint8_t *)&len, sizeof(len), 0);
    if (ret != sizeof(len)) {
        goto err;
    }

    ret = send(cps->sock_fd, (uint8_t *)buff, size, 0);
    if (ret != size) {
        goto err;
    }

err:
    return ret;
}

static int colo_userspace_proxy_recv(libxl__colo_proxy_state *cps,
                                     char *buff,
                                     unsigned int timeout_us)
{
    struct timeval tv;
    int ret;
    uint32_t len = 0;
    uint32_t size = 0;

    STATE_AO_GC(cps->ao);

    if (timeout_us) {
        tv.tv_sec = timeout_us / 1000000;
        tv.tv_usec = timeout_us % 1000000;
        ret = setsockopt(cps->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv,
                         sizeof(tv));
        if (ret < 0) {
            LOGD(ERROR, ao->domid,
                 "colo_userspace_proxy_recv setsockopt error: %s",
                 strerror(errno));
        }
    }

    ret = recv(cps->sock_fd, (uint8_t *)&len, sizeof(len), 0);
    if (ret < 0) {
        goto err;
    }

    size = ntohl(len);
    ret = recv(cps->sock_fd, buff, size, 0);

err:
    return ret;
}

/* error: return -1, otherwise return 0 */
static int64_t colo_proxy_recv(libxl__colo_proxy_state *cps, uint8_t **buff,
                               unsigned int timeout_us)
{
    struct sockaddr_nl sa;
    struct iovec iov;
    struct msghdr mh = {
        .msg_name = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    struct timeval tv;
    uint32_t size = 16384;
    int64_t len = 0;
    int ret;

    STATE_AO_GC(cps->ao);
    uint8_t *tmp = libxl__malloc(NOGC, size);

    if (timeout_us) {
        tv.tv_sec = timeout_us / 1000000;
        tv.tv_usec = timeout_us % 1000000;
        setsockopt(cps->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    iov.iov_base = tmp;
    iov.iov_len = size;
next:
    ret = recvmsg(cps->sock_fd, &mh, 0);
    if (ret <= 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            LOGED(ERROR, ao->domid, "can't recv msg from kernel by netlink");
        goto err;
    }

    len += ret;
    if (mh.msg_flags & MSG_TRUNC) {
        size += 16384;
        tmp = libxl__realloc(NOGC, tmp, size);
        iov.iov_base = tmp + len;
        iov.iov_len = size - len;
        goto next;
    }

    *buff = tmp;
    ret = len;
    goto out;

err:
    free(tmp);
    *buff = NULL;

out:
    if (timeout_us) {
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        setsockopt(cps->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    return ret;
}

/* ========= colo-proxy: setup and teardown ========== */

int colo_proxy_setup(libxl__colo_proxy_state *cps)
{
    int skfd = 0;
    struct sockaddr_nl sa;
    struct nlmsghdr *h;
    int i = 1;
    int ret = ERROR_FAIL;
    uint8_t *buff = NULL;
    int64_t size;

    STATE_AO_GC(cps->ao);

    /* If enable userspace proxy mode, we don't need setup kernel proxy */
    if (cps->is_userspace_proxy) {
        struct sockaddr_in addr;
        int port;
        char recvbuff[1024];
        const char sendbuf[] = "COLO_USERSPACE_PROXY_INIT";

        memset(&addr, 0, sizeof(addr));
        port = atoi(cps->checkpoint_port);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(cps->checkpoint_host);

        skfd = socket(AF_INET, SOCK_STREAM, 0);
        if (skfd < 0) {
            LOGD(ERROR, ao->domid, "can not create a TCP socket: %s",
                 strerror(errno));
            goto out;
        }

        cps->sock_fd = skfd;

        if (connect(skfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            LOGD(ERROR, ao->domid, "connect error");
            goto out;
        }

        ret = colo_userspace_proxy_send(cps, (uint8_t *)sendbuf, strlen(sendbuf));
        if (ret < 0)
            goto out;

        ret = colo_userspace_proxy_recv(cps, recvbuff, COLO_DEFAULT_WAIT_TIME);
        if (ret < 0) {
            LOGD(ERROR, ao->domid, "Can't recv msg from qemu colo-compare: %s",
                 strerror(errno));
            goto out;
        }

        return 0;
    }

    skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_COLO);
    if (skfd < 0) {
        LOGD(ERROR, ao->domid, "can not create a netlink socket: %s", strerror(errno));
        goto out;
    }
    cps->sock_fd = skfd;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = 0;
retry:
    sa.nl_pid = i++;

    if (i > 10) {
        LOGD(ERROR, ao->domid, "netlink bind error");
        goto out;
    }

    ret = bind(skfd, (struct sockaddr *)&sa, sizeof(sa));
    if (ret < 0 && errno == EADDRINUSE) {
        LOGD(ERROR, ao->domid, "colo index %d has already in used", sa.nl_pid);
        goto retry;
    } else if (ret < 0) {
        LOGD(ERROR, ao->domid, "netlink bind error");
        goto out;
    }

    cps->index = sa.nl_pid;
    ret = colo_proxy_send(cps, NULL, 0, COLO_PROXY_INIT);
    if (ret < 0)
        goto out;

    /* receive ack */
    size = colo_proxy_recv(cps, &buff, 500000);
    if (size < 0) {
        LOGD(ERROR, ao->domid, "Can't recv msg from kernel by netlink: %s",
             strerror(errno));
        goto out;
    }

    if (size) {
        h = (struct nlmsghdr *)buff;
        if (h->nlmsg_type == NLMSG_ERROR) {
            /* ack's type is NLMSG_ERROR */
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);

            if (size - sizeof(*h) < sizeof(*err)) {
                LOGD(ERROR, ao->domid, "NLMSG_LENGTH is too short");
                goto out;
            }

            if (err->error) {
                LOGD(ERROR, ao->domid, "NLMSG_ERROR contains error %d", err->error);
                goto out;
            }
        }
    }

    ret = 0;

out:
    free(buff);
    if (ret) {
        close(cps->sock_fd);
        cps->sock_fd = -1;
    }
    return ret;
}

void colo_proxy_teardown(libxl__colo_proxy_state *cps)
{
    /*
     * If enable userspace proxy mode,
     * we don't need teardown kernel proxy
     */
    if (cps->is_userspace_proxy)
        return;

    if (cps->sock_fd >= 0) {
        close(cps->sock_fd);
        cps->sock_fd = -1;
    }
}

/* ========= colo-proxy: preresume, postresume and checkpoint ========== */

void colo_proxy_preresume(libxl__colo_proxy_state *cps)
{
    /*
     * If enable userspace proxy mode,
     * we don't need preresume kernel proxy
     */
    if (cps->is_userspace_proxy) {
        const char sendbuf[] = "COLO_CHECKPOINT";
        colo_userspace_proxy_send(cps,
                                  (uint8_t *)sendbuf,
                                  strlen(sendbuf));
        return;
    }

    colo_proxy_send(cps, NULL, 0, COLO_CHECKPOINT);
    /* TODO: need to handle if the call fails... */
}

void colo_proxy_postresume(libxl__colo_proxy_state *cps)
{
    /* nothing to do... */
}

typedef struct colo_msg {
    bool is_checkpoint;
} colo_msg;

/*
 * Return value:
 * -1: error
 *  0: no checkpoint event is received before timeout
 *  1: do checkpoint
 */
int colo_proxy_checkpoint(libxl__colo_proxy_state *cps,
                          unsigned int timeout_us)
{
    uint8_t *buff = NULL;
    int64_t size;
    struct nlmsghdr *h;
    struct colo_msg *m;
    int ret = -1;
    char recvbuff[1024];

    STATE_AO_GC(cps->ao);

    /*
     * Enable userspace proxy to periodical checkpoint mode,
     * sleeping temporarily for colo userspace proxy mode.
     * then we will use socket recv instead of this usleep.
     * In other words, we use socket communicate with Qemu
     * Proxy part(colo-compare), for example, notify checkpoint
     * event.
     */
    if (cps->is_userspace_proxy) {
        ret = colo_userspace_proxy_recv(cps, recvbuff, timeout_us);
        if (ret <= 0) {
            ret = 0;
            goto out;
        }

        if (!strcmp(recvbuff, "DO_CHECKPOINT")) {
            ret = 1;
        } else {
            LOGD(ERROR, ao->domid, "receive qemu colo-compare checkpoint error");
            ret = 0;
        }
        goto out;
    }

    size = colo_proxy_recv(cps, &buff, timeout_us);

    /* timeout, return no checkpoint message. */
    if (size <= 0) {
        ret = 0;
        goto out;
    }

    h = (struct nlmsghdr *) buff;

    if (h->nlmsg_type == NLMSG_ERROR) {
        LOGD(ERROR, ao->domid, "receive NLMSG_ERROR");
        goto out;
    }

    if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*m))) {
        LOGD(ERROR, ao->domid, "NLMSG_LENGTH is too short");
        goto out;
    }

    m = NLMSG_DATA(h);

    ret = m->is_checkpoint ? 1 : 0;

out:
    free(buff);
    return ret;
}
