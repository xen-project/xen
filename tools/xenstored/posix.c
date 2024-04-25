/* 
    Simple prototype Xen Store Daemon providing simple tree-like database.
    Copyright (C) 2005 Rusty Russell IBM Corporation

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; If not, see <http://www.gnu.org/licenses/>.
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#if defined(HAVE_SYSTEMD)
#include <xen-sd-notify.h>
#endif
#include <xen-tools/xenstore-common.h>

#include "utils.h"
#include "core.h"
#include "osdep.h"
#include "talloc.h"

static int reopen_log_pipe0_pollfd_idx = -1;
static int reopen_log_pipe[2];

static int sock_pollfd_idx = -1;
static int sock = -1;

static void write_pidfile(const char *pidfile)
{
	char buf[100];
	int len;
	int fd;

	fd = open(pidfile, O_RDWR | O_CREAT, 0600);
	if (fd == -1)
		barf_perror("Opening pid file %s", pidfile);

	/* We exit silently if daemon already running. */
	if (lockf(fd, F_TLOCK, 0) == -1)
		exit(0);

	len = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
	if (write(fd, buf, len) != len)
		barf_perror("Writing pid file %s", pidfile);

	close(fd);
}

/* Stevens. */
static void daemonize(void)
{
	pid_t pid;

	/* Separate from our parent via fork, so init inherits us. */
	if ((pid = fork()) < 0)
		barf_perror("Failed to fork daemon");
	if (pid != 0)
		exit(0);

	/* Session leader so ^C doesn't whack us. */
	setsid();

	/* Let session leader exit so child cannot regain CTTY */
	if ((pid = fork()) < 0)
		barf_perror("Failed to fork daemon");
	if (pid != 0)
		exit(0);

	/* Move off any mount points we might be in. */
	if (chdir("/") == -1)
		barf_perror("Failed to chdir");

	/* Discard our parent's old-fashioned umask prejudices. */
	umask(0);
}

/*
 * Signal handler for SIGHUP, which requests that the trace log is reopened
 * (in the main loop).  A single byte is written to reopen_log_pipe, to awaken
 * the poll() in the main loop.
 */
static void trigger_reopen_log(int signal __attribute__((unused)))
{
	char c = 'A';
	int dummy;

	dummy = write(reopen_log_pipe[1], &c, 1);
}

void finish_daemonize(void)
{
	int devnull = open("/dev/null", O_RDWR);
	if (devnull == -1)
		barf_perror("Could not open /dev/null\n");
	dup2(devnull, STDIN_FILENO);
	dup2(devnull, STDOUT_FILENO);
	dup2(devnull, STDERR_FILENO);
	close(devnull);
}

static void init_pipe(void)
{
	int flags;
	unsigned int i;

	if (pipe(reopen_log_pipe)) {
		barf_perror("pipe");
	}

	for (i = 0; i < 2; i++) {
		flags = fcntl(reopen_log_pipe[i], F_GETFD);
		if (flags < 0)
			barf_perror("pipe get flags");
		flags |= FD_CLOEXEC;
		if (fcntl(reopen_log_pipe[i],  F_SETFD, flags) < 0)
			barf_perror("pipe set flags");
	}
}

void unmap_xenbus(void *interface)
{
	munmap(interface, getpagesize());
}

evtchn_port_t get_xenbus_evtchn(void)
{
	int fd;
	int rc;
	evtchn_port_t port;
	char str[20];

	fd = open(XENSTORED_PORT_DEV, O_RDONLY);
	if (fd == -1)
		return -1;

	rc = read(fd, str, sizeof(str) - 1);
	if (rc == -1)
	{
		int err = errno;
		close(fd);
		errno = err;
		return -1;
	}

	str[rc] = '\0';
	port = strtoul(str, NULL, 0);

	close(fd);
	return port;
}

void *xenbus_map(void)
{
	int fd;
	void *addr;

	fd = open(XENSTORED_KVA_DEV, O_RDWR);
	if (fd == -1)
		return NULL;

	addr = mmap(NULL, getpagesize(), PROT_READ|PROT_WRITE,
		MAP_SHARED, fd, 0);

	if (addr == MAP_FAILED)
		addr = NULL;

	close(fd);

	return addr;
}

static int writefd(struct connection *conn, const void *data, unsigned int len)
{
	int rc;

	while ((rc = write(conn->fd, data, len)) < 0) {
		if (errno == EAGAIN) {
			rc = 0;
			break;
		}
		if (errno != EINTR)
			break;
	}

	return rc;
}

static int readfd(struct connection *conn, void *data, unsigned int len)
{
	int rc;

	while ((rc = read(conn->fd, data, len)) < 0) {
		if (errno == EAGAIN) {
			rc = 0;
			break;
		}
		if (errno != EINTR)
			break;
	}

	/* Reading zero length means we're done with this connection. */
	if ((rc == 0) && (len != 0)) {
		errno = EBADF;
		rc = -1;
	}

	return rc;
}

static bool socket_can_process(struct connection *conn, int mask)
{
	if (conn->pollfd_idx == -1)
		return false;

	if (poll_fds[conn->pollfd_idx].revents & ~(POLLIN | POLLOUT)) {
		talloc_free(conn);
		return false;
	}

	return (poll_fds[conn->pollfd_idx].revents & mask);
}

static bool socket_can_write(struct connection *conn)
{
	return socket_can_process(conn, POLLOUT);
}

static bool socket_can_read(struct connection *conn)
{
	return socket_can_process(conn, POLLIN);
}

static const struct interface_funcs socket_funcs = {
	.write = writefd,
	.read = readfd,
	.can_write = socket_can_write,
	.can_read = socket_can_read,
};

static void accept_connection(int sock)
{
	int fd;
	struct connection *conn;

	fd = accept(sock, NULL, NULL);
	if (fd < 0)
		return;

	conn = new_connection(&socket_funcs);
	if (conn) {
		conn->fd = fd;
		conn->id = dom0_domid;
	} else
		close(fd);
}

static void destroy_fds(void)
{
	if (sock >= 0)
		close(sock);
}

static void init_sockets(void)
{
	struct sockaddr_un addr;
	const char *soc_str = xenstore_daemon_path();

	if (!soc_str)
		barf_perror("Failed to obtain xs domain socket");

	/* Create sockets for them to listen to. */
	atexit(destroy_fds);
	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		barf_perror("Could not create socket");

	/* FIXME: Be more sophisticated, don't mug running daemon. */
	unlink(soc_str);

	addr.sun_family = AF_UNIX;

	if (strlen(soc_str) >= sizeof(addr.sun_path))
		barf_perror("socket string '%s' too long", soc_str);
	strcpy(addr.sun_path, soc_str);
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		barf_perror("Could not bind socket to %s", soc_str);

	if (chmod(soc_str, 0600) != 0)
		barf_perror("Could not chmod sockets");

	if (listen(sock, 1) != 0)
		barf_perror("Could not listen on sockets");
}


struct connection *add_socket_connection(int fd)
{
	struct connection *conn;

	conn = new_connection(&socket_funcs);
	if (!conn)
		barf("error restoring connection");
	conn->fd = fd;

	return conn;
}

void early_init(bool live_update, bool dofork, const char *pidfile)
{
	reopen_log();

	/* Make sure xenstored directories exist. */
	/* Errors ignored here, will be reported when we open files */
	mkdir(xenstore_daemon_rundir(), 0755);
	mkdir(XENSTORE_LIB_DIR, 0755);

	if (dofork) {
		openlog("xenstored", 0, LOG_DAEMON);
		if (!live_update)
			daemonize();
	}

	if (pidfile)
		write_pidfile(pidfile);

	/* Don't kill us with SIGPIPE. */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, trigger_reopen_log);

	if (!live_update)
		init_sockets();

	init_pipe();
}

void set_special_fds(void)
{
	if (reopen_log_pipe[0] != -1)
		reopen_log_pipe0_pollfd_idx =
			set_fd(reopen_log_pipe[0], POLLIN|POLLPRI);

	if (sock != -1)
		sock_pollfd_idx = set_fd(sock, POLLIN|POLLPRI);
}

void handle_special_fds(void)
{
	if (reopen_log_pipe0_pollfd_idx != -1) {
		if (poll_fds[reopen_log_pipe0_pollfd_idx].revents & ~POLLIN) {
			close(reopen_log_pipe[0]);
			close(reopen_log_pipe[1]);
			init_pipe();
		} else if (poll_fds[reopen_log_pipe0_pollfd_idx].revents &
			   POLLIN) {
			char c;

			if (read(reopen_log_pipe[0], &c, 1) != 1)
				barf_perror("read failed");
			reopen_log();
		}
		reopen_log_pipe0_pollfd_idx = -1;
	}

	if (sock_pollfd_idx != -1) {
		if (poll_fds[sock_pollfd_idx].revents & ~POLLIN) {
			barf_perror("sock poll failed");
		} else if (poll_fds[sock_pollfd_idx].revents & POLLIN) {
			accept_connection(sock);
			sock_pollfd_idx = -1;
		}
	}
}

void late_init(bool live_update)
{
#if defined(HAVE_SYSTEMD)
	if (!live_update) {
		sd_notify(1, "READY=1");
		fprintf(stderr, "xenstored is ready\n");
	}
#endif
}

int get_socket_fd(void)
{
	return sock;
}

void set_socket_fd(int fd)
{
	sock = fd;
}

const char *xenstore_rundir(void)
{
	return xenstore_daemon_rundir();
}
