/*\
 *  Copyright (C) International Business Machines  Corp., 2005
 *  Author(s): Anthony Liguori <aliguori@us.ibm.com>
 *
 *  Xen Console Daemon
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
\*/

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>

#include "xenctrl.h"
#include "xen/io/domain_controller.h"
#include "xcs_proto.h"

#include "utils.h"

struct xs_handle *xs;
int xc;

int xcs_ctrl_fd = -1;
int xcs_data_fd = -1;

bool _read_write_sync(int fd, void *data, size_t size, bool do_read)
{
	size_t offset = 0;
	ssize_t len;

	while (offset < size) {
		if (do_read) {
			len = read(fd, data + offset, size - offset);
		} else {
			len = write(fd, data + offset, size - offset);
		}

		if (len < 1) {
			if (len == -1 && (errno == EAGAIN || errno == EINTR)) {
				continue;
			} else {
				return false;
			}
		} else {
			offset += len;
		}
	}

	return true;
}

static int open_domain_socket(const char *path)
{
	struct sockaddr_un addr;
	int sock;
	size_t addr_len;

	if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		goto out;
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);
	addr_len = sizeof(addr.sun_family) + strlen(XCS_SUN_PATH) + 1;

	if (connect(sock, (struct sockaddr *)&addr, addr_len) == -1) {
		goto out_close_sock;
	}

	return sock;

 out_close_sock:
	close(sock);
 out:
	return -1;
}

static void child_exit(int sig)
{
	while (waitpid(-1, NULL, WNOHANG) > 0);
}

void daemonize(const char *pidfile)
{
	pid_t pid;
	int fd;
	int len;
	int i;
	char buf[100];

	if (getppid() == 1) {
		return;
	}

	if ((pid = fork()) > 0) {
		exit(0);
	} else if (pid == -1) {
		err(errno, "fork() failed");
	}

	setsid();

	/* redirect fd 0,1,2 to /dev/null */
	if ((fd = open("/dev/null",O_RDWR)) == -1) {
		exit(1);
	}

	for (i = 0; i <= 2; i++) {
		close(i);
		dup2(fd, i);
	}

	close(fd);

	umask(027);
	chdir("/");

	fd = open(pidfile, O_RDWR | O_CREAT);
	if (fd == -1) {
		exit(1);
	}

	if (lockf(fd, F_TLOCK, 0) == -1) {
		exit(1);
	}

	len = sprintf(buf, "%d\n", getpid());
	write(fd, buf, len);

	signal(SIGCHLD, child_exit);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
}

/* synchronized send/recv strictly for setting up xcs */
/* always use asychronize callbacks any other time */
static bool xcs_send_recv(int fd, xcs_msg_t *msg)
{
	bool ret = false;

	if (!write_sync(fd, msg, sizeof(*msg))) {
		dolog(LOG_ERR, "Write failed at %s:%s():L%d?  Possible bug.",
		       __FILE__, __FUNCTION__, __LINE__);
		goto out;
	}

	if (!read_sync(fd, msg, sizeof(*msg))) {
		dolog(LOG_ERR, "Read failed at %s:%s():L%d?  Possible bug.",
		       __FILE__, __FUNCTION__, __LINE__);
		goto out;
	}

	ret = true;

 out:
	return ret;
}

bool xen_setup(void)
{
	int sock;
	xcs_msg_t msg;
	
	xs = xs_daemon_open();
	if (xs == NULL) {
		dolog(LOG_ERR,
		      "Failed to contact xenstore (%m).  Is it running?");
		goto out;
	}

	xc = xc_interface_open();
	if (xc == -1) {
		dolog(LOG_ERR, "Failed to contact hypervisor (%m)");
		goto out;
	}

	sock = open_domain_socket(XCS_SUN_PATH);
	if (sock == -1) {
		dolog(LOG_ERR, "Failed to contact xcs (%m).  Is it running?");
		goto out_close_store;
	}

	xcs_ctrl_fd = sock;

	sock = open_domain_socket(XCS_SUN_PATH);
	if (sock == -1) {
		dolog(LOG_ERR, "Failed to contact xcs (%m).  Is it running?");
		goto out_close_ctrl;
	}
	
	xcs_data_fd = sock;

	memset(&msg, 0, sizeof(msg));
	msg.type = XCS_CONNECT_CTRL;
	if (!xcs_send_recv(xcs_ctrl_fd, &msg) || msg.result != XCS_RSLT_OK) {
		dolog(LOG_ERR, "xcs control connect failed.  Possible bug.");
		goto out_close_data;
	}

	msg.type = XCS_CONNECT_DATA;
	if (!xcs_send_recv(xcs_data_fd, &msg) || msg.result != XCS_RSLT_OK) {
		dolog(LOG_ERR, "xcs data connect failed.  Possible bug.");
		goto out_close_data;
	}

	msg.type = XCS_VIRQ_BIND;
	msg.u.virq.virq = VIRQ_DOM_EXC;
	if (!xcs_send_recv(xcs_ctrl_fd, &msg) || msg.result != XCS_RSLT_OK) {
		dolog(LOG_ERR, "xcs virq bind failed.  Possible bug.");
		goto out_close_data;
	}
	
	return true;

 out_close_data:
	close(xcs_ctrl_fd);
	xcs_data_fd = -1;
 out_close_ctrl:
	close(xcs_ctrl_fd);
	xcs_ctrl_fd = -1;
 out_close_store:
	xs_daemon_close(xs);
 out:
	return false;
}

