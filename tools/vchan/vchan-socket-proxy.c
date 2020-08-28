/**
 * @file
 * @section AUTHORS
 *
 * Copyright (C) 2010  Rafal Wojtczuk  <rafal@invisiblethingslab.com>
 *
 *  Authors:
 *       Rafal Wojtczuk  <rafal@invisiblethingslab.com>
 *       Daniel De Graaf <dgdegra@tycho.nsa.gov>
 *       Marek Marczykowski-Górecki  <marmarek@invisiblethingslab.com>
 *
 * @section LICENSE
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * @section DESCRIPTION
 *
 * This is a vchan to unix socket proxy. Vchan server is set, and on client
 * connection, local socket connection is established. Communication is bidirectional.
 * One client is served at a time, clients needs to coordinate this themselves.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <getopt.h>

#include <xenstore.h>
#include <xenctrl.h>
#include <libxenvchan.h>

static void usage(char** argv)
{
    fprintf(stderr, "usage:\n"
        "\t%s [options] domainid nodepath [socket-path|file-no|-]\n"
        "\n"
        "options:\n"
        "\t-m, --mode=client|server - vchan connection mode (client by default)\n"
        "\t-s, --state-path=path - xenstore path where write \"running\" to \n"
        "\t                        at startup\n"
        "\t-v, --verbose - verbose logging\n"
        "\n"
        "client: client of a vchan connection, fourth parameter can be:\n"
        "\tsocket-path: listen on a UNIX socket at this path and connect to vchan\n"
        "\t             whenever new connection is accepted;\n"
        "\t             handle multiple _subsequent_ connections, until terminated\n"
        "\n"
        "\tfile-no:     except open FD of a socket in listen mode;\n"
        "\t             otherwise similar to socket-path\n"
        "\n"
        "\t-:           open vchan connection immediately and pass the data\n"
        "\t             from stdin/stdout; terminate when vchan connection\n"
        "\t             is closed\n"
        "\n"
        "server: server of a vchan connection, fourth parameter can be:\n"
        "\tsocket-path: connect to this UNIX socket when new vchan connection\n"
        "\t             is accepted;\n"
        "\t             handle multiple _subsequent_ connections, until terminated\n"
        "\n"
        "\tfile-no:     pass data to/from this FD; terminate when vchan connection\n"
        "\t             is closed\n"
        "\n"
        "\t-:           pass data to/from stdin/stdout; terminate when vchan\n"
        "\t             connection is closed\n",
        argv[0]);
    exit(1);
}

#define BUFSIZE 8192
char inbuf[BUFSIZE];
char outbuf[BUFSIZE];
int insiz = 0;
int outsiz = 0;
int verbose = 0;

struct vchan_proxy_state {
    struct libxenvchan *ctrl;
    int output_fd;
    int input_fd;
};

static void vchan_wr(struct libxenvchan *ctrl) {
    int ret;

    if (!insiz)
        return;
    ret = libxenvchan_write(ctrl, inbuf, insiz);
    if (ret < 0) {
        fprintf(stderr, "vchan write failed\n");
        exit(1);
    }
    if (verbose)
        fprintf(stderr, "wrote %d bytes to vchan\n", ret);
    if (ret > 0) {
        insiz -= ret;
        memmove(inbuf, inbuf + ret, insiz);
    }
}

static void socket_wr(int output_fd) {
    int ret;

    if (!outsiz)
        return;
    ret = write(output_fd, outbuf, outsiz);
    if (ret < 0 && errno != EAGAIN)
        exit(1);
    if (ret > 0) {
        outsiz -= ret;
        memmove(outbuf, outbuf + ret, outsiz);
    }
}

static int set_nonblocking(int fd, int nonblocking) {
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1)
        return -1;

    if (nonblocking)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) == -1)
        return -1;

    return 0;
}

static int connect_socket(const char *path_or_fd) {
    int fd;
    char *endptr;
    struct sockaddr_un addr;

    fd = strtoll(path_or_fd, &endptr, 0);
    if (*endptr == '\0') {
        set_nonblocking(fd, 1);
        return fd;
    }

    if (strlen(path_or_fd) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "UNIX socket path \"%s\" too long (%zd >= %zd)\n",
                path_or_fd, strlen(path_or_fd), sizeof(addr.sun_path));
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path_or_fd);
    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("connect");
        close(fd);
        return -1;
    }

    set_nonblocking(fd, 1);

    return fd;
}

static int listen_socket(const char *path_or_fd) {
    int fd;
    char *endptr;
    struct sockaddr_un addr;

    fd = strtoll(path_or_fd, &endptr, 0);
    if (*endptr == '\0') {
        return fd;
    }

    if (strlen(path_or_fd) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "UNIX socket path \"%s\" too long (%zd >= %zd)\n",
                path_or_fd, strlen(path_or_fd), sizeof(addr.sun_path));
        return -1;
    }

    /* if not a number, assume a socket path */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path_or_fd);
    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 5) != 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

static struct libxenvchan *connect_vchan(int domid, const char *path) {
    struct libxenvchan *ctrl = NULL;
    struct xs_handle *xs = NULL;
    xc_interface *xc = NULL;
    xc_dominfo_t dominfo;
    char **watch_ret;
    unsigned int watch_num;
    int ret;

    xs = xs_open(XS_OPEN_READONLY);
    if (!xs) {
        perror("xs_open");
        goto out;
    }
    xc = xc_interface_open(NULL, NULL, XC_OPENFLAG_NON_REENTRANT);
    if (!xc) {
        perror("xc_interface_open");
        goto out;
    }
    /* wait for vchan server to create *path* */
    if (!xs_watch(xs, path, "path")) {
        fprintf(stderr, "xs_watch(%s) failed.\n", path);
        goto out;
    }
    if (!xs_watch(xs, "@releaseDomain", "release")) {
        fprintf(stderr, "xs_watch(@releaseDomain failed.\n");
        goto out;
    }

    while ((watch_ret = xs_read_watch(xs, &watch_num))) {
        /* don't care about exact which fired the watch */
        free(watch_ret);
        ctrl = libxenvchan_client_init(NULL, domid, path);
        if (ctrl)
            break;

        ret = xc_domain_getinfo(xc, domid, 1, &dominfo);
        /* break the loop if domain is definitely not there anymore, but
         * continue if it is or the call failed (like EPERM) */
        if (ret == -1 && errno == ESRCH)
            break;
        if (ret == 1 && (dominfo.domid != (uint32_t)domid || dominfo.dying))
            break;
    }

out:
    if (xc)
        xc_interface_close(xc);
    if (xs)
        xs_close(xs);
    return ctrl;
}


static void discard_buffers(struct libxenvchan *ctrl) {
    /* discard local buffers */
    insiz = 0;
    outsiz = 0;

    /* discard remaining incoming data */
    while (libxenvchan_data_ready(ctrl)) {
        if (libxenvchan_read(ctrl, inbuf, BUFSIZE) == -1) {
            perror("vchan read");
            exit(1);
        }
    }
}

int data_loop(struct vchan_proxy_state *state)
{
    int ret;
    int libxenvchan_fd;
    int max_fd;

    libxenvchan_fd = libxenvchan_fd_for_select(state->ctrl);
    for (;;) {
        fd_set rfds;
        fd_set wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);

        max_fd = -1;
        if (state->input_fd != -1 && insiz != BUFSIZE) {
            FD_SET(state->input_fd, &rfds);
            if (state->input_fd > max_fd)
                max_fd = state->input_fd;
        }
        if (state->output_fd != -1 && outsiz) {
            FD_SET(state->output_fd, &wfds);
            if (state->output_fd > max_fd)
                max_fd = state->output_fd;
        }
        FD_SET(libxenvchan_fd, &rfds);
        if (libxenvchan_fd > max_fd)
            max_fd = libxenvchan_fd;
        ret = select(max_fd + 1, &rfds, &wfds, NULL, NULL);
        if (ret < 0) {
            perror("select");
            exit(1);
        }
        if (FD_ISSET(libxenvchan_fd, &rfds)) {
            libxenvchan_wait(state->ctrl);
            if (!libxenvchan_is_open(state->ctrl)) {
                if (verbose)
                    fprintf(stderr, "vchan client disconnected\n");
                while (outsiz)
                    socket_wr(state->output_fd);
                close(state->output_fd);
                state->output_fd = -1;
                close(state->input_fd);
                state->input_fd = -1;
                discard_buffers(state->ctrl);
                break;
            }
            vchan_wr(state->ctrl);
        }

        if (FD_ISSET(state->input_fd, &rfds)) {
            ret = read(state->input_fd, inbuf + insiz, BUFSIZE - insiz);
            if (ret < 0 && errno != EAGAIN)
                exit(1);
            if (verbose)
                fprintf(stderr, "from-unix: %.*s\n", ret, inbuf + insiz);
            if (ret == 0) {
                /* EOF on socket, write everything in the buffer and close the
                 * state->input_fd socket */
                while (insiz) {
                    vchan_wr(state->ctrl);
                    libxenvchan_wait(state->ctrl);
                }
                close(state->input_fd);
                if (state->input_fd == state->output_fd)
                    state->output_fd = -1;
                state->input_fd = -1;
                /* TODO: maybe signal the vchan client somehow? */
                break;
            }
            if (ret)
                insiz += ret;
            vchan_wr(state->ctrl);
        }
        if (FD_ISSET(state->output_fd, &wfds))
            socket_wr(state->output_fd);
        while (libxenvchan_data_ready(state->ctrl) && outsiz < BUFSIZE) {
            ret = libxenvchan_read(state->ctrl, outbuf + outsiz,
                                   BUFSIZE - outsiz);
            if (ret < 0)
                exit(1);
            if (verbose)
                fprintf(stderr, "from-vchan: %.*s\n", ret, outbuf + outsiz);
            outsiz += ret;
            socket_wr(state->output_fd);
        }
    }
    return 0;
}

/**
    Simple libxenvchan application, both client and server.
    Both sides may write and read, both from the libxenvchan and from
    stdin/stdout (just like netcat).
*/

static struct option options[] = {
    { "mode",       required_argument, NULL, 'm' },
    { "verbose",          no_argument, NULL, 'v' },
    { "state-path", required_argument, NULL, 's' },
    { }
};

int main(int argc, char **argv)
{
    int is_server = 0;
    int socket_fd = -1;
    struct vchan_proxy_state state = { .ctrl = NULL,
                                       .input_fd = -1,
                                       .output_fd = -1 };
    const char *socket_path;
    int domid;
    const char *vchan_path;
    const char *state_path = NULL;
    int opt;
    int ret;

    while ((opt = getopt_long(argc, argv, "m:vs:", options, NULL)) != -1) {
        switch (opt) {
            case 'm':
                if (strcmp(optarg, "server") == 0)
                    is_server = 1;
                else if (strcmp(optarg, "client") == 0)
                    is_server = 0;
                else {
                    fprintf(stderr, "invalid argument for --mode: %s\n", optarg);
                    usage(argv);
                    return 1;
                }
                break;
            case 'v':
                verbose = 1;
                break;
            case 's':
                state_path = optarg;
                break;
            case '?':
                usage(argv);
        }
    }

    if (argc-optind != 3)
        usage(argv);

    domid = atoi(argv[optind]);
    vchan_path = argv[optind+1];
    socket_path = argv[optind+2];

    if (is_server) {
        state.ctrl = libxenvchan_server_init(NULL, domid, vchan_path, 0, 0);
        if (!state.ctrl) {
            perror("libxenvchan_server_init");
            exit(1);
        }
    } else {
        if (strcmp(socket_path, "-") == 0) {
            state.input_fd = 0;
            state.output_fd = 1;
        } else {
            socket_fd = listen_socket(socket_path);
            if (socket_fd == -1) {
                fprintf(stderr, "listen socket failed\n");
                return 1;
            }
        }
    }

    if (state_path) {
        struct xs_handle *xs;

        xs = xs_open(0);
        if (!xs) {
            perror("xs_open");
            return 1;
        }
        if (!xs_write(xs, XBT_NULL, state_path, "running", strlen("running"))) {
            perror("xs_write");
            return 1;
        }
        xs_close(xs);
    }

    ret = 0;

    for (;;) {
        if (is_server) {
            /* wait for vchan connection */
            while (libxenvchan_is_open(state.ctrl) != 1)
                libxenvchan_wait(state.ctrl);
            /* vchan client connected, setup local FD if needed */
            if (strcmp(socket_path, "-") == 0) {
                state.input_fd = 0;
                state.output_fd = 1;
            } else {
                state.input_fd = state.output_fd = connect_socket(socket_path);
            }
            if (state.input_fd == -1) {
                fprintf(stderr, "connect_socket failed\n");
                ret = 1;
                break;
            }
            if (data_loop(&state) != 0)
                break;
            /* keep it running only when get UNIX socket path */
            if (socket_path[0] != '/')
                break;
        } else {
            /* wait for local socket connection */
            if (strcmp(socket_path, "-") != 0)
                state.input_fd = state.output_fd = accept(socket_fd,
                                                          NULL, NULL);
            if (state.input_fd == -1) {
                perror("accept");
                ret = 1;
                break;
            }
            set_nonblocking(state.input_fd, 1);
            set_nonblocking(state.output_fd, 1);
            state.ctrl = connect_vchan(domid, vchan_path);
            if (!state.ctrl) {
                perror("vchan client init");
                ret = 1;
                break;
            }
            if (data_loop(&state) != 0)
                break;
            /* don't reconnect if output was stdout */
            if (strcmp(socket_path, "-") == 0)
                break;

            libxenvchan_close(state.ctrl);
            state.ctrl = NULL;
        }
    }

    if (state.output_fd >= 0)
        close(state.output_fd);
    if (state.input_fd >= 0)
        close(state.input_fd);
    if (state.ctrl)
        libxenvchan_close(state.ctrl);
    if (socket_fd >= 0)
        close(socket_fd);

    return ret;
}
