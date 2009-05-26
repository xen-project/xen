/* Copyright (c) 2008, XenSource Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of XenSource Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <xs.h>
#include "disktypes.h"
#include "tapdisk-dispatch.h"

#define TAPDISK_DAEMON_DOMID_WATCH   "domid-watch"
#define TAPDISK_DAEMON_PIDFILE       "/var/run/blktapctrl.pid"

typedef struct tapdisk_daemon {
	char                         *node;
	int                           blktap_fd;
	uint16_t                      cookie;

	struct xs_handle             *xsh;
	struct list_head              channels;
	struct xenbus_watch           watch;
} tapdisk_daemon_t;

static tapdisk_daemon_t tapdisk_daemon;

#define tapdisk_daemon_for_each_channel(c, tmp) \
	list_for_each_entry_safe(c, tmp, &tapdisk_daemon.channels, list)

#define MAX(a, b) ((a) >= (b) ? (a) : (b))

static void
tapdisk_daemon_print_drivers(void)
{
	int i, size;

	DPRINTF("blktap-daemon: v1.0.2\n");

	size = sizeof(dtypes) / sizeof(disk_info_t *);
	for (i = 0; i < size; i++)
		DPRINTF("Found driver: [%s]\n", dtypes[i]->name);
}

static int
tapdisk_daemon_write_pidfile(long pid)
{
	char buf[100];
	int len, fd, flags, err;

	fd = open(TAPDISK_DAEMON_PIDFILE, O_RDWR | O_CREAT, 0600);
	if (fd == -1) {
		EPRINTF("Opening pid file failed (%d)\n", errno);
		return -errno;
	}

	/* We exit silently if daemon already running */
	err = lockf(fd, F_TLOCK, 0);
	if (err == -1)
		exit(0);

	/* Set FD_CLOEXEC, so that tapdisk doesn't get this file descriptor */
	flags = fcntl(fd, F_GETFD);
	if (flags == -1) {
		EPRINTF("F_GETFD failed (%d)\n", errno);
		return -errno;
	}

	flags |= FD_CLOEXEC;
	err = fcntl(fd, F_SETFD, flags);
	if (err == -1) {
		EPRINTF("F_SETFD failed (%d)\n", errno);
		return -errno;
	}

	len = sprintf(buf, "%ld\n", pid);
	err = write(fd, buf, len);
	if (err != len) {
		EPRINTF("Writing pid file failed (%d)\n", errno);
		return -errno;
	}

	return 0;
}

static int
tapdisk_daemon_init(void)
{
	char *devname;
	int i, err, blktap_major;

	memset(&tapdisk_daemon, 0, sizeof(tapdisk_daemon_t));

	err = asprintf(&devname, "%s/%s0", BLKTAP_DEV_DIR, BLKTAP_DEV_NAME);
	if (err == -1) {
		devname = NULL;
		err = -ENOMEM;
		goto fail;
	}

	err = xc_find_device_number("blktap0");
	if (err < 0)
		goto fail;

	blktap_major = major(err);
	err = make_blktap_device(devname, blktap_major, 0, S_IFCHR | 0600);
	if (err)
		goto fail;

	tapdisk_daemon.blktap_fd = open(devname, O_RDWR);
	if (tapdisk_daemon.blktap_fd == -1) {
		err = -errno;
		EPRINTF("blktap0 open failed\n");
		goto fail;
	}

	for (i = 0; i < 2; i++) {
		tapdisk_daemon.xsh = xs_daemon_open();
		if (!tapdisk_daemon.xsh) {
			EPRINTF("xs_daemon_open failed -- is xenstore running?\n");
			sleep(2);
		} else
			break;
	}

	if (!tapdisk_daemon.xsh) {
		err = -ENOSYS;
		goto fail;
	}

	INIT_LIST_HEAD(&tapdisk_daemon.channels);

	free(devname);
	return 0;

fail:
	if (tapdisk_daemon.blktap_fd > 0)
		close(tapdisk_daemon.blktap_fd);
	free(devname);
	memset(&tapdisk_daemon, 0, sizeof(tapdisk_daemon_t));
	EPRINTF("%s: %d\n", __func__, err);

	return err;
}

static int
tapdisk_daemon_set_node(void)
{
	int err;
	char *domid;

	domid = get_dom_domid(tapdisk_daemon.xsh);
	if (!domid)
		return -EAGAIN;

	err = asprintf(&tapdisk_daemon.node,
		       "/local/domain/%s/backend/tap", domid);
	if (err == -1) {
		tapdisk_daemon.node = NULL;
		err = -ENOMEM;
		goto out;
	}

	err = 0;

out:
	free(domid);
	return err;
}

static int
tapdisk_daemon_get_domid(void)
{
	int err;
	unsigned int num;
	char **res, *node, *token, *domid;

	res = xs_read_watch(tapdisk_daemon.xsh, &num);
	if (!res)
		return -EAGAIN;

	err   = 0;
	node  = res[XS_WATCH_PATH];
	token = res[XS_WATCH_TOKEN];

	if (strcmp(token, TAPDISK_DAEMON_DOMID_WATCH)) {
		err = -EINVAL;
		goto out;
	}

	err = tapdisk_daemon_set_node();

out:
	free(res);
	return err;
}

static int
tapdisk_daemon_wait_for_domid(void)
{
	int err;
	char *domid;
	fd_set readfds;

	err = tapdisk_daemon_set_node();
	if (!err)
		return 0;

	if (!xs_watch(tapdisk_daemon.xsh, "/local/domain",
		      TAPDISK_DAEMON_DOMID_WATCH)) {
		EPRINTF("unable to set domain id watch\n");
		return -EINVAL;
	}

	do {
		FD_ZERO(&readfds);
		FD_SET(xs_fileno(tapdisk_daemon.xsh), &readfds);

		select(xs_fileno(tapdisk_daemon.xsh) + 1,
		       &readfds, NULL, NULL, NULL);

		if (FD_ISSET(xs_fileno(tapdisk_daemon.xsh), &readfds))
			err = tapdisk_daemon_get_domid();
		else
			err = -EAGAIN;
	} while (err == -EAGAIN);

	xs_unwatch(tapdisk_daemon.xsh,
		   "/local/domain", TAPDISK_DAEMON_DOMID_WATCH);
	return err;
}

static inline int
tapdisk_daemon_new_vbd_event(const char *node)
{
	return (!strcmp(node, "start-tapdisk"));
}

static int
tapdisk_daemon_write_uuid(char *path, uint32_t uuid)
{
	int err;
	char *cpath, uuid_str[12];

	snprintf(uuid_str, sizeof(uuid_str), "%u", uuid);

	err = asprintf(&cpath, "%s/tapdisk-uuid", path);
	if (err == -1)
		return -ENOMEM;

	err = xs_write(tapdisk_daemon.xsh, XBT_NULL,
		       cpath, uuid_str, strlen(uuid_str));
	free(cpath);

	return (err ? 0 : -errno);
}

static void
tapdisk_daemon_probe(struct xs_handle *xsh,
		     struct xenbus_watch *watch, const char *path)
{
	char *cpath;
	int len, err;
	uint32_t cookie;
	const char *node;
	tapdisk_channel_t *channel;

	len = strsep_len(path, '/', 7);
	if (len < 0)
		return;

	node = path + len + 1;

	if (!tapdisk_daemon_new_vbd_event(node))
		return;

	if (!xs_exists(xsh, path))
		return;

	cpath = strdup(path);
	if (!cpath) {
		EPRINTF("failed to allocate control path for %s\n", path);
		return;
	}
	cpath[len] = '\0';

	cookie = tapdisk_daemon.cookie++;
	err    = tapdisk_daemon_write_uuid(cpath, cookie);
	if (err)
		goto out;

	DPRINTF("%s: got watch on %s, uuid = %u\n", __func__, path, cookie);

	err = tapdisk_channel_open(&channel, cpath,
				   tapdisk_daemon.xsh,
				   tapdisk_daemon.blktap_fd,
				   cookie);
	if (!err)
		list_add(&channel->list, &tapdisk_daemon.channels);
	else
		EPRINTF("failed to open tapdisk channel for %s: %d\n",
			path, err);

out:
	free(cpath);
}

static int
tapdisk_daemon_start(void)
{
	int err;

	err = tapdisk_daemon_wait_for_domid();
	if (err)
		return err;

	tapdisk_daemon.watch.node     = tapdisk_daemon.node;
	tapdisk_daemon.watch.callback = tapdisk_daemon_probe;

	err = register_xenbus_watch(tapdisk_daemon.xsh, &tapdisk_daemon.watch);
	if (err)
		goto fail;

	ioctl(tapdisk_daemon.blktap_fd,
	      BLKTAP_IOCTL_SETMODE, BLKTAP_MODE_INTERPOSE);
	ioctl(tapdisk_daemon.blktap_fd, BLKTAP_IOCTL_SENDPID, getpid());

	return 0;

fail:
	free(tapdisk_daemon.node);
	tapdisk_daemon.node       = NULL;
	tapdisk_daemon.watch.node = NULL;
	EPRINTF("%s: %d\n", __func__, err);
	return err;
}

static int
tapdisk_daemon_stop(void)
{
	unregister_xenbus_watch(tapdisk_daemon.xsh, &tapdisk_daemon.watch);

	ioctl(tapdisk_daemon.blktap_fd,
	      BLKTAP_IOCTL_SETMODE, BLKTAP_MODE_PASSTHROUGH);
	close(tapdisk_daemon.blktap_fd);

	return 0;
}

static void
tapdisk_daemon_free(void)
{
	free(tapdisk_daemon.node);
	xs_daemon_close(tapdisk_daemon.xsh);
	memset(&tapdisk_daemon, 0, sizeof(tapdisk_daemon_t));
}

static int
tapdisk_daemon_read_message(int fd, tapdisk_message_t *message, int timeout)
{
	fd_set readfds;
	struct timeval tv;
	int ret, len, offset;

	tv.tv_sec  = timeout;
	tv.tv_usec = 0;
	offset     = 0;
	len        = sizeof(tapdisk_message_t);

	memset(message, 0, sizeof(tapdisk_message_t));

	while (offset < len) {
		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);

		/* we don't bother reinitializing tv. at worst, it will wait a
		 * bit more time than expected. */

		ret = select(fd + 1, &readfds, NULL, NULL, &tv);
		if (ret == -1)
			break;
		else if (FD_ISSET(fd, &readfds)) {
			ret = read(fd, message + offset, len - offset);
			if (ret <= 0)
				break;
			offset += ret;
		} else
			break;
	}

	return (offset == len ? 0 : -EIO);
}

static int
tapdisk_daemon_receive_message(int fd)
{
	int err;
	tapdisk_message_t m;
	tapdisk_channel_t *c, *tmp;

	err = tapdisk_daemon_read_message(fd, &m, 2);
	if (err) {
		EPRINTF("failed reading message on %d: %d\n", fd, err);
		return err;
	}

	tapdisk_daemon_for_each_channel(c, tmp)
		if (c->cookie == m.cookie && c->read_fd == fd) {
			DPRINTF("got '%s' message from %d:%d\n",
				tapdisk_message_name(m.type),
				c->channel_id, c->cookie);

			return tapdisk_channel_receive_message(c, &m);
		}

	EPRINTF("unrecognized message on %d: '%s' (uuid = %u)\n",
		fd, tapdisk_message_name(m.type), m.cookie);

	return -EINVAL;
}

static int
tapdisk_daemon_set_fds(fd_set *readfds)
{
	int max, fd;
	tapdisk_channel_t *channel, *tmp;

	max = xs_fileno(tapdisk_daemon.xsh);

	FD_ZERO(readfds);
	FD_SET(max, readfds);

	tapdisk_daemon_for_each_channel(channel, tmp) {
		fd  = channel->read_fd;
		max = MAX(fd, max);
		FD_SET(fd, readfds);
	}

	return max;
}

static int
tapdisk_daemon_check_fds(fd_set *readfds)
{
	int err;
	tapdisk_channel_t *channel, *tmp;

	if (FD_ISSET(xs_fileno(tapdisk_daemon.xsh), readfds))
		xs_fire_next_watch(tapdisk_daemon.xsh);

	tapdisk_daemon_for_each_channel(channel, tmp)
		if (FD_ISSET(channel->read_fd, readfds))
			return tapdisk_daemon_receive_message(channel->read_fd);

	return 0;
}

static int
tapdisk_daemon_run(void)
{
	int err, max;
	fd_set readfds;

	while (1) {
		max = tapdisk_daemon_set_fds(&readfds);

		err = select(max + 1, &readfds, NULL, NULL, NULL);
		if (err < 0)
			continue;

		err = tapdisk_daemon_check_fds(&readfds);
	}

	return err;
}

void
tapdisk_daemon_find_channel(tapdisk_channel_t *channel)
{
	tapdisk_channel_t *c, *tmp;

	channel->read_fd     = 0;
	channel->write_fd    = 0;
	channel->tapdisk_pid = 0;

	/* do we want multiple vbds per tapdisk? */
	if (!xs_exists(tapdisk_daemon.xsh, channel->share_tapdisk_str)) {
		channel->shared = 0;
		return;
	}

	channel->shared = 1;

	/* check if we already have a process started */
	tapdisk_daemon_for_each_channel(c, tmp)
		if (c->drivertype == channel->drivertype) {
			channel->write_fd    = c->write_fd;
			channel->read_fd     = c->read_fd;
			channel->channel_id  = c->channel_id;
			channel->tapdisk_pid = c->tapdisk_pid;
			return;
		}
}

void
tapdisk_daemon_close_channel(tapdisk_channel_t *channel)
{
	tapdisk_channel_t *c, *tmp;

	list_del(&channel->list);

	tapdisk_daemon_for_each_channel(c, tmp)
		if (c->channel_id == channel->channel_id)
			return;

	close(channel->read_fd);
	close(channel->write_fd);
}

int
main(int argc, char *argv[])
{
	int err;
	char buf[128];

	if (daemon(0, 0)) {
	  EPRINTF("daemon() failed (%d)\n", errno);
	  return -errno;
	}

#define CORE_DUMP
#if defined(CORE_DUMP)
#include <sys/resource.h>
	{
		/* set up core-dumps*/
		struct rlimit rlim;
		rlim.rlim_cur = RLIM_INFINITY;
		rlim.rlim_max = RLIM_INFINITY;
		if (setrlimit(RLIMIT_CORE, &rlim) < 0)
			EPRINTF("setrlimit failed: %d\n", errno);
	}
#endif

	snprintf(buf, sizeof(buf), "BLKTAP-DAEMON[%d]", getpid());
	openlog(buf, LOG_CONS | LOG_ODELAY, LOG_DAEMON);

	err = tapdisk_daemon_write_pidfile(getpid());
	if (err)
		goto out;

	tapdisk_daemon_print_drivers();

	err = tapdisk_daemon_init();
	if (err)
		goto out;

	err = tapdisk_daemon_start();
	if (err)
		goto out;

	tapdisk_daemon_run();

	tapdisk_daemon_stop();
	tapdisk_daemon_free();

	err = 0;

out:
	if (err)
		EPRINTF("failed to start %s: %d\n", argv[0], err);
	closelog();
	return err;
}
