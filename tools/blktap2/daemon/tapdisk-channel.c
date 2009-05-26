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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/resource.h>

#include <xs.h>
#include "disktypes.h"
#include "tapdisk-dispatch.h"

#define TAPDISK_CHANNEL_IDLE          1
#define TAPDISK_CHANNEL_WAIT_PID      2
#define TAPDISK_CHANNEL_WAIT_OPEN     3
#define TAPDISK_CHANNEL_WAIT_PAUSE    4
#define TAPDISK_CHANNEL_WAIT_RESUME   5
#define TAPDISK_CHANNEL_WAIT_CLOSE    6
#define TAPDISK_CHANNEL_CLOSED        7

static void tapdisk_channel_error(tapdisk_channel_t *,
				  const char *fmt, ...)
  __attribute__((format(printf, 2, 3)));
static void tapdisk_channel_fatal(tapdisk_channel_t *,
				  const char *fmt, ...)
  __attribute__((format(printf, 2, 3)));
static int tapdisk_channel_parse_params(tapdisk_channel_t *);
static void tapdisk_channel_pause_event(struct xs_handle *,
					struct xenbus_watch *,
					const char *);

static int
tapdisk_channel_check_uuid(tapdisk_channel_t *channel)
{
	uint32_t uuid;
	char *uuid_str;

	uuid_str = xs_read(channel->xsh, XBT_NULL, channel->uuid_str, NULL);
	if (!uuid_str)
		return -errno;

	uuid = strtoul(uuid_str, NULL, 10);
	free(uuid_str);

	if (uuid != channel->cookie)
		return -EINVAL;

	return 0;
}

static inline int
tapdisk_channel_validate_watch(tapdisk_channel_t *channel, const char *path)
{
	int err, len;

	len = strsep_len(path, '/', 7);
	if (len < 0)
		return -EINVAL;

	err = tapdisk_channel_check_uuid(channel);
	if (err)
		return err;

	if (!xs_exists(channel->xsh, path))
		return -ENOENT;

	return 0;
}

static inline int
tapdisk_channel_validate_message(tapdisk_channel_t *channel,
				 tapdisk_message_t *message)
{
	switch (message->type) {
	case TAPDISK_MESSAGE_PID_RSP:
		if (channel->state != TAPDISK_CHANNEL_WAIT_PID)
			return -EINVAL;
		break;

	case TAPDISK_MESSAGE_OPEN_RSP:
		if (channel->state != TAPDISK_CHANNEL_WAIT_OPEN)
			return -EINVAL;
		break;

	case TAPDISK_MESSAGE_PAUSE_RSP:
		if (channel->state != TAPDISK_CHANNEL_WAIT_PAUSE)
			return -EINVAL;
		break;

	case TAPDISK_MESSAGE_RESUME_RSP:
		if (channel->state != TAPDISK_CHANNEL_WAIT_RESUME)
			return -EINVAL;
		break;

	case TAPDISK_MESSAGE_CLOSE_RSP:
		if (channel->state != TAPDISK_CHANNEL_WAIT_CLOSE)
			return -EINVAL;
		break;

	case TAPDISK_MESSAGE_RUNTIME_ERROR:
		/*
		 * runtime errors can be received at any time
		 * and should not affect the state machine
		 */
		return 0;
	}

	channel->state = TAPDISK_CHANNEL_IDLE;
	return 0;
}

static int
tapdisk_channel_send_message(tapdisk_channel_t *channel,
			     tapdisk_message_t *message, int timeout)
{
	fd_set writefds;
	struct timeval tv;
	int ret, len, offset;

	tv.tv_sec  = timeout;
	tv.tv_usec = 0;
	offset     = 0;
	len        = sizeof(tapdisk_message_t);

	DPRINTF("%s: sending '%s' message to %d:%d\n",
		channel->path, tapdisk_message_name(message->type),
		channel->channel_id, channel->cookie);

	if (channel->state != TAPDISK_CHANNEL_IDLE &&
	    message->type  != TAPDISK_MESSAGE_CLOSE)
		EPRINTF("%s: writing message to non-idle channel (%d)\n",
			channel->path, channel->state);

	while (offset < len) {
		FD_ZERO(&writefds);
		FD_SET(channel->write_fd, &writefds);

		/* we don't bother reinitializing tv. at worst, it will wait a
		 * bit more time than expected. */

		ret = select(channel->write_fd + 1,
			     NULL, &writefds, NULL, &tv);
		if (ret == -1)
			break;
		else if (FD_ISSET(channel->write_fd, &writefds)) {
			ret = write(channel->write_fd,
				    message + offset, len - offset);
			if (ret <= 0)
				break;
			offset += ret;
		} else
			break;
	}

	if (offset != len) {
		EPRINTF("%s: error writing '%s' message to %d:%d\n",
			channel->path, tapdisk_message_name(message->type),
			channel->channel_id, channel->cookie);
		return -EIO;
	}

	switch (message->type) {
	case TAPDISK_MESSAGE_PID:
		channel->state = TAPDISK_CHANNEL_WAIT_PID;
		break;

	case TAPDISK_MESSAGE_OPEN:
		channel->state = TAPDISK_CHANNEL_WAIT_OPEN;
		break;

	case TAPDISK_MESSAGE_PAUSE:
		channel->state = TAPDISK_CHANNEL_WAIT_PAUSE;
		break;

	case TAPDISK_MESSAGE_RESUME:
		channel->state = TAPDISK_CHANNEL_WAIT_RESUME;
		break;

	case TAPDISK_MESSAGE_CLOSE:
		channel->state = TAPDISK_CHANNEL_WAIT_CLOSE;
		break;

	default:
		EPRINTF("%s: unrecognized message type %d\n",
			channel->path, message->type);
	}

	return 0;
}

static void
__tapdisk_channel_error(tapdisk_channel_t *channel,
			const char *fmt, va_list ap)
{
	int err;
	char *dir, *buf, *message;

	err = vasprintf(&buf, fmt, ap);
	if (err == -1) {
		EPRINTF("failed to allocate error message\n");
		buf = NULL;
	}

	if (buf)
		message = buf;
	else
		message = "tapdisk error";

	EPRINTF("%s: %s\n", channel->path, message);

	err = asprintf(&dir, "%s/tapdisk-error", channel->path);
	if (err == -1) {
		EPRINTF("%s: failed to write %s\n", __func__, message);
		dir = NULL;
		goto out;
	}

	xs_write(channel->xsh, XBT_NULL, dir, message, strlen(message));

out:
	free(dir);
	free(buf);
}

static void
tapdisk_channel_error(tapdisk_channel_t *channel, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__tapdisk_channel_error(channel, fmt, ap);
	va_end(ap);
}

static void
tapdisk_channel_fatal(tapdisk_channel_t *channel, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__tapdisk_channel_error(channel, fmt, ap);
	va_end(ap);

	tapdisk_channel_close(channel);
}

static int
tapdisk_channel_connect_backdev(tapdisk_channel_t *channel)
{
	int err, major, minor;
	char *s, *path, *devname;

	s       = NULL;
	path    = NULL;
	devname = NULL;

	err = ioctl(channel->blktap_fd,
		    BLKTAP_IOCTL_BACKDEV_SETUP, channel->minor);
	if (err) {
		err = -errno;
		goto fail;
	}

	err = asprintf(&path, "%s/backdev-node", channel->path);
	if (err == -1) {
		path = NULL;
		err  = -ENOMEM;
		goto fail;
	}

	s = xs_read(channel->xsh, XBT_NULL, path, NULL);
	if (!s) {
		err = -errno;
		goto fail;
	}

	err = sscanf(s, "%d:%d", &major, &minor);
	if (err != 2) {
		err = -EINVAL;
		goto fail;
	}

	err = asprintf(&devname,"%s/%s%d",
		       BLKTAP_DEV_DIR, BACKDEV_NAME, minor);
	if (err == -1) {
		devname = NULL;
		err = -ENOMEM;
		goto fail;
	}

	err = make_blktap_device(devname, major, minor, S_IFBLK | 0600);
	if (err)
		goto fail;

	free(path);
	err = asprintf(&path, "%s/backdev-path", channel->path);
	if (err == -1) {
		path = NULL;
		err  = -ENOMEM;
		goto fail;
	}

	err = xs_write(channel->xsh, XBT_NULL, path, devname, strlen(devname));
	if (err == 0) {
		err = -errno;
		goto fail;
	}

	err = 0;
 out:
	free(devname);
	free(path);
	free(s);
	return err;

 fail:
	EPRINTF("backdev setup failed [%d]\n", err);
	goto out;
}

static int
tapdisk_channel_complete_connection(tapdisk_channel_t *channel)
{
	int err;
	char *path;

	if (!xs_printf(channel->xsh, channel->path,
		       "sectors", "%llu", channel->image.size)) {
		EPRINTF("ERROR: Failed writing sectors");
		return -errno;
	}

	if (!xs_printf(channel->xsh, channel->path,
		       "sector-size", "%lu", channel->image.secsize)) {
		EPRINTF("ERROR: Failed writing sector-size");
		return -errno;
	}

	if (!xs_printf(channel->xsh, channel->path,
		       "info", "%u", channel->image.info)) {
		EPRINTF("ERROR: Failed writing info");
		return -errno;
	}

	err = tapdisk_channel_connect_backdev(channel);
	if (err)
		goto clean;

	channel->connected = 1;
	return 0;

 clean:
	if (asprintf(&path, "%s/info", channel->path) == -1)
		return err;

	if (!xs_rm(channel->xsh, XBT_NULL, path))
		goto clean_out;

	free(path);
	if (asprintf(&path, "%s/sector-size", channel->path) == -1)
		return err;

	if (!xs_rm(channel->xsh, XBT_NULL, path))
		goto clean_out;

	free(path);
	if (asprintf(&path, "%s/sectors", channel->path) == -1)
		return err;

	xs_rm(channel->xsh, XBT_NULL, path);

 clean_out:
	free(path);
	return err;
}

static int
tapdisk_channel_send_open_request(tapdisk_channel_t *channel)
{
	int len;
	tapdisk_message_t message;

	memset(&message, 0, sizeof(tapdisk_message_t));

	len = strlen(channel->vdi_path);

	message.type              = TAPDISK_MESSAGE_OPEN;
	message.cookie            = channel->cookie;
	message.drivertype        = channel->drivertype;
	message.u.params.storage  = channel->storage;
	message.u.params.devnum   = channel->minor;
	message.u.params.domid    = channel->domid;
	message.u.params.path_len = len;
	strncpy(message.u.params.path, channel->vdi_path, len);

	if (channel->mode == 'r')
		message.u.params.flags |= TAPDISK_MESSAGE_FLAG_RDONLY;
	if (channel->shared)
		message.u.params.flags |= TAPDISK_MESSAGE_FLAG_SHARED;

	/* TODO: clean this up */
	if (xs_exists(channel->xsh, "/local/domain/0/tapdisk/add-cache"))
		message.u.params.flags |= TAPDISK_MESSAGE_FLAG_ADD_CACHE;
	if (xs_exists(channel->xsh, "/local/domain/0/tapdisk/log-dirty"))
		message.u.params.flags |= TAPDISK_MESSAGE_FLAG_LOG_DIRTY;

	return tapdisk_channel_send_message(channel, &message, 2);
}

static int
tapdisk_channel_receive_open_response(tapdisk_channel_t *channel,
				      tapdisk_message_t *message)
{
	int err;

	channel->image.size    = message->u.image.sectors;
	channel->image.secsize = message->u.image.sector_size;
	channel->image.info    = message->u.image.info;

	err = tapdisk_channel_complete_connection(channel);
	if (err)
		goto fail;

	/* did we receive a pause request before the connection completed? */
	if (channel->pause_needed) {
		DPRINTF("%s: deferred pause request\n", channel->path);
		tapdisk_channel_pause_event(channel->xsh,
					    &channel->pause_watch,
					    channel->pause_str);
		channel->pause_needed = 0;
	}

	return 0;

fail:
	tapdisk_channel_fatal(channel,
			      "failure completing connection: %d", err);
	return err;
}

static int
tapdisk_channel_send_shutdown_request(tapdisk_channel_t *channel)
{
	tapdisk_message_t message;

	memset(&message, 0, sizeof(tapdisk_message_t));

	message.type       = TAPDISK_MESSAGE_CLOSE;
	message.drivertype = channel->drivertype;
	message.cookie     = channel->cookie;

	return tapdisk_channel_send_message(channel, &message, 2);
}

static int
tapdisk_channel_receive_shutdown_response(tapdisk_channel_t *channel,
					  tapdisk_message_t *message)
{
	channel->open  = 0;
	channel->state = TAPDISK_CHANNEL_CLOSED;
	tapdisk_channel_close(channel);
	return 0;
}

static int
tapdisk_channel_receive_runtime_error(tapdisk_channel_t *channel,
				      tapdisk_message_t *message)
{
	tapdisk_channel_error(channel,
			      "runtime error: %s", message->u.string.text);
	return 0;
}

static int
tapdisk_channel_send_pid_request(tapdisk_channel_t *channel)
{
	int err;
	tapdisk_message_t message;

	memset(&message, 0, sizeof(tapdisk_message_t));

	message.type       = TAPDISK_MESSAGE_PID;
	message.drivertype = channel->drivertype;
	message.cookie     = channel->cookie;

	err = tapdisk_channel_send_message(channel, &message, 2);

	if (!err)
		channel->open = 1;

	return err;
}

static int
tapdisk_channel_receive_pid_response(tapdisk_channel_t *channel,
				     tapdisk_message_t *message)
{
	int err;

	channel->tapdisk_pid = message->u.tapdisk_pid;

	DPRINTF("%s: tapdisk pid: %d\n", channel->path, channel->tapdisk_pid);

	err = setpriority(PRIO_PROCESS, channel->tapdisk_pid, PRIO_SPECIAL_IO);
	if (err) {
		tapdisk_channel_fatal(channel,
				      "setting tapdisk priority: %d", err);
		return err;
	}

	err = tapdisk_channel_send_open_request(channel);
	if (err) {
		tapdisk_channel_fatal(channel,
				      "sending open request: %d", err);
		return err;
	}

	return 0;
}

static int
tapdisk_channel_send_pause_request(tapdisk_channel_t *channel)
{
	tapdisk_message_t message;

	memset(&message, 0, sizeof(tapdisk_message_t));

	DPRINTF("pausing %s\n", channel->path);

	message.type       = TAPDISK_MESSAGE_PAUSE;
	message.drivertype = channel->drivertype;
	message.cookie     = channel->cookie;

	return tapdisk_channel_send_message(channel, &message, 2);
}

static int
tapdisk_channel_receive_pause_response(tapdisk_channel_t *channel,
				       tapdisk_message_t *message)
{
	int err;

	if (!xs_write(channel->xsh, XBT_NULL,
		      channel->pause_done_str, "", strlen(""))) {
		err = -errno;
		goto fail;
	}

	return 0;

fail:
	tapdisk_channel_fatal(channel,
			      "failure receiving pause response: %d\n", err);
	return err;
}

static int
tapdisk_channel_send_resume_request(tapdisk_channel_t *channel)
{
	int len;
	tapdisk_message_t message;

	memset(&message, 0, sizeof(tapdisk_message_t));

	len = strlen(channel->vdi_path);

	DPRINTF("resuming %s\n", channel->path);

	message.type              = TAPDISK_MESSAGE_RESUME;
	message.drivertype        = channel->drivertype;
	message.cookie            = channel->cookie;
	message.u.params.path_len = len;
	strncpy(message.u.params.path, channel->vdi_path, len);

	return tapdisk_channel_send_message(channel, &message, 2);
}

static int
tapdisk_channel_receive_resume_response(tapdisk_channel_t *channel,
					tapdisk_message_t *message)
{
	int err;

	if (!xs_rm(channel->xsh, XBT_NULL, channel->pause_done_str)) {
		err = -errno;
		goto fail;
	}

	return 0;

fail:
	tapdisk_channel_fatal(channel,
			      "failure receiving pause response: %d", err);
	return err;
}

static void
tapdisk_channel_shutdown_event(struct xs_handle *xsh,
			       struct xenbus_watch *watch, const char *path)
{
	int err;
	tapdisk_channel_t *channel;

	channel = watch->data;

	DPRINTF("%s: got watch on %s\n", channel->path, path);

	if (!xs_exists(channel->xsh, channel->path)) {
		tapdisk_channel_close(channel);
		return;
	}

	err = tapdisk_channel_validate_watch(channel, path);
	if (err) {
		if (err == -EINVAL)
			tapdisk_channel_fatal(channel, "bad shutdown watch");
		return;
	}

	tapdisk_channel_send_shutdown_request(channel);
}

static void
tapdisk_channel_pause_event(struct xs_handle *xsh,
			    struct xenbus_watch *watch, const char *path)
{
	int err, paused;
	tapdisk_channel_t *channel;

	channel = watch->data;

	DPRINTF("%s: got watch on %s\n", channel->path, path);

	if (!xs_exists(channel->xsh, channel->path)) {
		tapdisk_channel_close(channel);
		return;
	}

	/* NB: The VBD is essentially considered ready since the
	 * backend hotplug event ocurred, which is just after
	 * start-tapdisk, not after watch registration. We start
	 * testing xenstore keys with the very first shot, but defer
	 * until after connection completion. */

	err = tapdisk_channel_validate_watch(channel, path);
	if (err) {
		if (err == -EINVAL)
			tapdisk_channel_fatal(channel, "bad pause watch");

		if (err != -ENOENT)
			return;

		err = 0;
	}

	paused  = xs_exists(xsh, channel->pause_done_str);

	if (xs_exists(xsh, channel->pause_str)) {
		/*
		 * Duplicate requests are a protocol validation, but
		 * impossible to identify if watch registration and an
		 * actual pause request may fire separately in close
		 * succession. Warn, but do not signal an error.
		 */
		int pausing = channel->state == TAPDISK_CHANNEL_WAIT_PAUSE;
		if (pausing || paused) {
			DPRINTF("Ignoring pause event for %s vbd %s\n",
				pausing ? "pausing" : "paused", channel->path);
			goto out;
		}

		/* defer if tapdisk is not ready yet */
		if (!channel->connected) {
			DPRINTF("%s: deferring pause request\n", path);
			channel->pause_needed = 1;
			goto out;
		}

		err = tapdisk_channel_send_pause_request(channel);

	} else if (xs_exists(xsh, channel->pause_done_str)) {
		free(channel->params);
		channel->params   = NULL;
		channel->vdi_path = NULL;

		err = xs_gather(channel->xsh, channel->path,
				"params", NULL, &channel->params, NULL);
		if (err) {
			EPRINTF("failure re-reading params: %d\n", err);
			channel->params = NULL;
			goto out;
		}

		err = tapdisk_channel_parse_params(channel);
		if (err)
			goto out;

		err = tapdisk_channel_send_resume_request(channel);
		if (err)
			goto out;
	}

	err = 0;

out:
	if (err)
		tapdisk_channel_error(channel, "pause event failed: %d", err);
}

static int
tapdisk_channel_open_control_socket(char *devname)
{
	int err, fd;
	fd_set socks;
	struct timeval timeout;

	err = mkdir(BLKTAP_CTRL_DIR, 0755);
	if (err == -1 && errno != EEXIST) {
		EPRINTF("Failure creating %s directory: %d\n",
			BLKTAP_CTRL_DIR, errno);
		return -errno;
	}

	err = mkfifo(devname, S_IRWXU | S_IRWXG | S_IRWXO);
	if (err) {
		if (errno == EEXIST) {
			/*
			 * Remove fifo since it may have data from
			 * it's previous use --- earlier invocation
			 * of tapdisk may not have read all messages.
			 */
			err = unlink(devname);
			if (err) {
				EPRINTF("ERROR: unlink(%s) failed (%d)\n",
					devname, errno);
				return -errno;
			}

			err = mkfifo(devname, S_IRWXU | S_IRWXG | S_IRWXO);
		}

		if (err) {
			EPRINTF("ERROR: pipe failed (%d)\n", errno);
			return -errno;
		}
	}

	fd = open(devname, O_RDWR | O_NONBLOCK);
	if (fd == -1) {
		EPRINTF("Failed to open %s\n", devname);
		return -errno;
	}

	return fd;
}

static int
tapdisk_channel_get_device_number(tapdisk_channel_t *channel)
{
	char *devname;
	domid_translate_t tr;
	int major, minor, err;

	tr.domid = channel->domid;
        tr.busid = channel->busid;

	minor = ioctl(channel->blktap_fd, BLKTAP_IOCTL_NEWINTF, tr);
	if (minor <= 0 || minor > MAX_TAP_DEV) {
		EPRINTF("invalid dev id: %d\n", minor);
		return -EINVAL;
	}

	major = ioctl(channel->blktap_fd, BLKTAP_IOCTL_MAJOR, minor);
	if (major < 0) {
		EPRINTF("invalid major id: %d\n", major);
		return -EINVAL;
	}

	err = asprintf(&devname, "%s/%s%d",
		       BLKTAP_DEV_DIR, BLKTAP_DEV_NAME, minor);
	if (err == -1) {
		EPRINTF("get_new_dev: malloc failed\n");
		return -ENOMEM;
	}

	err = make_blktap_device(devname, major, minor, S_IFCHR | 0600);
	free(devname);

	if (err)
		return err;

	DPRINTF("Received device id %d and major %d, "
		"sent domid %d and be_id %d\n",
		minor, major, tr.domid, tr.busid);

	channel->major = major;
	channel->minor = minor;

	return 0;
}

static int
tapdisk_channel_start_process(tapdisk_channel_t *channel,
			      char *write_dev, char *read_dev)
{
	pid_t child;
	char *argv[] = { "tapdisk", write_dev, read_dev, NULL };

	if ((child = fork()) == -1)
		return -errno;

	if (!child) {
		int i;
		for (i = 0 ; i < sysconf(_SC_OPEN_MAX) ; i++)
			if (i != STDIN_FILENO &&
			    i != STDOUT_FILENO &&
			    i != STDERR_FILENO)
				close(i);

		execvp("tapdisk", argv);
		_exit(1);
	} else {
		pid_t got;
		do {
			got = waitpid(child, NULL, 0);
		} while (got != child);
	}
	return 0;
}

static int
tapdisk_channel_launch_tapdisk(tapdisk_channel_t *channel)
{
	int err;
	char *read_dev, *write_dev;

	read_dev          = NULL;
	write_dev         = NULL;
	channel->read_fd  = -1;
	channel->write_fd = -1;

	err = tapdisk_channel_get_device_number(channel);
	if (err)
		return err;

	err = asprintf(&write_dev,
		       "%s/tapctrlwrite%d", BLKTAP_CTRL_DIR, channel->minor);
	if (err == -1) {
		err = -ENOMEM;
		write_dev = NULL;
		goto fail;
	}

	err = asprintf(&read_dev,
		       "%s/tapctrlread%d", BLKTAP_CTRL_DIR, channel->minor);
	if (err == -1) {
		err = -ENOMEM;
		read_dev = NULL;
		goto fail;
	}

	channel->write_fd = tapdisk_channel_open_control_socket(write_dev);
	if (channel->write_fd < 0) {
		err = channel->write_fd;
		channel->write_fd = -1;
		goto fail;
	}

	channel->read_fd = tapdisk_channel_open_control_socket(read_dev);
	if (channel->read_fd < 0) {
		err = channel->read_fd;
		channel->read_fd = -1;
		goto fail;
	}

	err = tapdisk_channel_start_process(channel, write_dev, read_dev);
	if (err)
		goto fail;

	channel->open       = 1;
	channel->channel_id = channel->write_fd;

	free(read_dev);
	free(write_dev);

	DPRINTF("process launched, channel = %d:%d\n",
		channel->channel_id, channel->cookie);

	return tapdisk_channel_send_pid_request(channel);

fail:
	free(read_dev);
	free(write_dev);
	if (channel->read_fd != -1)
		close(channel->read_fd);
	if (channel->write_fd != -1)
		close(channel->write_fd);
	return err;
}

static int
tapdisk_channel_connect(tapdisk_channel_t *channel)
{
	int err;

	tapdisk_daemon_find_channel(channel);

	if (!channel->tapdisk_pid)
		return tapdisk_channel_launch_tapdisk(channel);

	DPRINTF("%s: process exists: %d, channel = %d:%d\n",
		channel->path, channel->tapdisk_pid,
		channel->channel_id, channel->cookie);

	err = tapdisk_channel_get_device_number(channel);
	if (err)
		return err;

	return tapdisk_channel_send_pid_request(channel);
}

static int
tapdisk_channel_init(tapdisk_channel_t *channel)
{
	int err;

	channel->uuid_str          = NULL;
	channel->pause_str         = NULL;
	channel->pause_done_str    = NULL;
	channel->shutdown_str      = NULL;
	channel->share_tapdisk_str = NULL;

	err = asprintf(&channel->uuid_str,
		       "%s/tapdisk-uuid", channel->path);
	if (err == -1) {
		channel->uuid_str = NULL;
		goto fail;
	}

	err = asprintf(&channel->pause_str, "%s/pause", channel->path);
	if (err == -1) {
		channel->pause_str = NULL;
		goto fail;
	}

	err = asprintf(&channel->pause_done_str,
		       "%s/pause-done", channel->path);
	if (err == -1) {
		channel->pause_done_str = NULL;
		goto fail;
	}

	err = asprintf(&channel->shutdown_str,
		       "%s/shutdown-tapdisk", channel->path);
	if (err == -1) {
		channel->shutdown_str = NULL;
		goto fail;
	}

	channel->share_tapdisk_str = "/local/domain/0/tapdisk/share-tapdisks";

	return 0;

fail:
	free(channel->uuid_str);
	free(channel->pause_str);
	free(channel->pause_done_str);
	free(channel->shutdown_str);
	channel->uuid_str          = NULL;
	channel->pause_str         = NULL;
	channel->pause_done_str    = NULL;
	channel->shutdown_str      = NULL;
	channel->share_tapdisk_str = NULL;
	return -ENOMEM;
}

static int
tapdisk_channel_set_watches(tapdisk_channel_t *channel)
{
	int err;

	/* watch for pause events */
	channel->pause_watch.node            = channel->pause_str;
	channel->pause_watch.callback        = tapdisk_channel_pause_event;
	channel->pause_watch.data            = channel;
	err = register_xenbus_watch(channel->xsh, &channel->pause_watch);
	if (err) {
		channel->pause_watch.node    = NULL;
		goto fail;
	}

	/* watch for shutdown events */
	channel->shutdown_watch.node         = channel->shutdown_str;
	channel->shutdown_watch.callback     = tapdisk_channel_shutdown_event;
	channel->shutdown_watch.data         = channel;
	err = register_xenbus_watch(channel->xsh, &channel->shutdown_watch);
	if (err) {
		channel->shutdown_watch.node = NULL;
		goto fail;
	}

	return 0;

fail:
	if (channel->pause_watch.node) {
		unregister_xenbus_watch(channel->xsh, &channel->pause_watch);
		channel->pause_watch.node    = NULL;
	}
	if (channel->shutdown_watch.node) {
		unregister_xenbus_watch(channel->xsh, &channel->shutdown_watch);
		channel->shutdown_watch.node = NULL;
	}
	return err;
}

static void
tapdisk_channel_get_storage_type(tapdisk_channel_t *channel)
{
	int err, type;
	unsigned int len;
	char *path, *stype;

	channel->storage = TAPDISK_STORAGE_TYPE_DEFAULT;

	err = asprintf(&path, "%s/sm-data/storage-type", channel->path);
	if (err == -1)
		return;

	stype = xs_read(channel->xsh, XBT_NULL, path, &len);
	if (!stype)
		goto out;
	else if (!strcmp(stype, "nfs"))
		channel->storage = TAPDISK_STORAGE_TYPE_NFS;
	else if (!strcmp(stype, "ext"))
		channel->storage = TAPDISK_STORAGE_TYPE_EXT;
	else if (!strcmp(stype, "lvm"))
		channel->storage = TAPDISK_STORAGE_TYPE_LVM;

out:
	free(path);
	free(stype);
}

static int
tapdisk_channel_get_busid(tapdisk_channel_t *channel)
{
	int len, end;
	const char *ptr;
	char *tptr, num[10];

	len = strsep_len(channel->path, '/', 6);
	end = strlen(channel->path);
	if(len < 0 || end < 0) {
		EPRINTF("invalid path: %s\n", channel->path);
		return -EINVAL;
	}
	
	ptr = channel->path + len + 1;
	strncpy(num, ptr, end - len);
	tptr = num + (end - (len + 1));
	*tptr = '\0';

	channel->busid = atoi(num);
	return 0;
}

static int
tapdisk_channel_parse_params(tapdisk_channel_t *channel)
{
	int i, size, err;
	unsigned int len;
	char *ptr, *path, handle[10];
	char *vdi_type;
	char *vtype;

	path = channel->params;
	size = sizeof(dtypes) / sizeof(disk_info_t *);

	if (strlen(path) + 1 >= TAPDISK_MESSAGE_MAX_PATH_LENGTH)
		goto fail;

	ptr = strchr(path, ':');
	if (!ptr)
		goto fail;

	channel->vdi_path = ptr + 1;
	memcpy(handle, path, (ptr - path));
	ptr  = handle + (ptr - path);
	*ptr = '\0';

	err = asprintf(&vdi_type, "%s/sm-data/vdi-type", channel->path);
	if (err == -1)
		goto fail;

	if (xs_exists(channel->xsh, vdi_type)) {
		vtype = xs_read(channel->xsh, XBT_NULL, vdi_type, &len);
		free(vdi_type);
		if (!vtype)
			goto fail;
		if (len >= sizeof(handle) - 1) {
			free(vtype);
			goto fail;
		}
		sprintf(handle, "%s", vtype);
		free(vtype);
	}

	for (i = 0; i < size; i++) {
		if (strncmp(handle, dtypes[i]->handle, (ptr - path)))
			continue;

		if (dtypes[i]->idnum == -1)
			goto fail;

		channel->drivertype = dtypes[i]->idnum;
		return 0;
	}

fail:
	EPRINTF("%s: invalid blktap params: %s\n",
		channel->path, channel->params);
	channel->vdi_path = NULL;
	return -EINVAL;
}

static int
tapdisk_channel_gather_info(tapdisk_channel_t *channel)
{
	int err;

	err = xs_gather(channel->xsh, channel->path,
			"frontend", NULL, &channel->frontpath,
			"frontend-id", "%li", &channel->domid,
			"params", NULL, &channel->params,
			"mode", "%c", &channel->mode, NULL);
	if (err) {
		EPRINTF("could not find device info: %d\n", err);
		return err;
	}

	err = tapdisk_channel_parse_params(channel);
	if (err)
		return err;

	err = tapdisk_channel_get_busid(channel);
	if (err)
		return err;

	tapdisk_channel_get_storage_type(channel);

	return 0;
}

static int
tapdisk_channel_verify_start_request(tapdisk_channel_t *channel)
{
	char *path;
	unsigned int err;

	err = asprintf(&path, "%s/start-tapdisk", channel->path);
	if (err == -1)
		goto mem_fail;

	if (!xs_exists(channel->xsh, path))
		goto fail;

	free(path);
	err = asprintf(&path, "%s/shutdown-request", channel->path);
	if (err == -1)
		goto mem_fail;

	if (xs_exists(channel->xsh, path))
		goto fail;

	if (xs_exists(channel->xsh, channel->shutdown_str))
		goto fail;

	free(path);
	err = asprintf(&path, "%s/shutdown-done", channel->path);
	if (err == -1)
		goto mem_fail;

	if (xs_exists(channel->xsh, path))
		goto fail;

	free(path);

	return 0;

fail:
	free(path);
	EPRINTF("%s:%s: invalid start request\n", __func__, channel->path);
	return -EINVAL;

mem_fail:
	EPRINTF("%s:%s: out of memory\n", __func__, channel->path);
	return -ENOMEM;
}

void
tapdisk_channel_close(tapdisk_channel_t *channel)
{
	if (channel->channel_id)
		DPRINTF("%s: closing channel %d:%d\n",
			channel->path, channel->channel_id, channel->cookie);

	if (channel->open)
		tapdisk_channel_send_shutdown_request(channel);

	if (channel->pause_watch.node) {
		unregister_xenbus_watch(channel->xsh, &channel->pause_watch);
		channel->pause_watch.node = NULL;
	}

	if (channel->shutdown_watch.node) {
		unregister_xenbus_watch(channel->xsh, &channel->shutdown_watch);
		channel->shutdown_watch.node = NULL;
	}

	tapdisk_daemon_close_channel(channel);

	free(channel->params);
	free(channel->frontpath);
	free(channel->shutdown_str);
	free(channel->pause_done_str);
	free(channel->pause_str);
	free(channel->uuid_str);
	free(channel->path);
	free(channel);
}

int
tapdisk_channel_open(tapdisk_channel_t **_channel,
		     char *path, struct xs_handle *xsh,
		     int blktap_fd, uint16_t cookie)
{
	int err;
	char *msg;
	tapdisk_channel_t *channel;

	msg       = NULL;
	*_channel = NULL;

	channel = calloc(1, sizeof(tapdisk_channel_t));
	if (!channel)
		return -ENOMEM;

	channel->xsh       = xsh;
	channel->blktap_fd = blktap_fd;
	channel->cookie    = cookie;
	channel->state     = TAPDISK_CHANNEL_IDLE;

	INIT_LIST_HEAD(&channel->list);

	channel->path = strdup(path);
	if (!channel->path) {
		err = -ENOMEM;
		goto fail;
	}

	err = tapdisk_channel_init(channel);
	if (err) {
		msg = "allocating device";
		goto fail;
	}

	err = tapdisk_channel_check_uuid(channel);
	if (err) {
		msg = "checking uuid";
		goto fail;
	}

	err = tapdisk_channel_gather_info(channel);
	if (err) {
		msg = "gathering parameters";
		goto fail;
	}

	err = tapdisk_channel_verify_start_request(channel);
	if (err) {
		msg = "invalid start request";
		goto fail;
	}

	err = tapdisk_channel_set_watches(channel);
	if (err) {
		msg = "registering xenstore watches";
		goto fail;
	}

	err = tapdisk_channel_connect(channel);
	if (err) {
		msg = "connecting to tapdisk";
		goto fail;
	}

	*_channel = channel;
	return 0;

fail:
	tapdisk_channel_fatal(channel, "%s: %d", (msg ? : "failure"), err);
	return err;
}

int
tapdisk_channel_receive_message(tapdisk_channel_t *c, tapdisk_message_t *m)
{
	int err;

	err = tapdisk_channel_validate_message(c, m);
	if (err)
		goto fail;

	switch (m->type) {
	case TAPDISK_MESSAGE_PID_RSP:
		return tapdisk_channel_receive_pid_response(c, m);

	case TAPDISK_MESSAGE_OPEN_RSP:
		return tapdisk_channel_receive_open_response(c, m);

	case TAPDISK_MESSAGE_PAUSE_RSP:
		return tapdisk_channel_receive_pause_response(c, m);

	case TAPDISK_MESSAGE_RESUME_RSP:
		return tapdisk_channel_receive_resume_response(c, m);

	case TAPDISK_MESSAGE_CLOSE_RSP:
		return tapdisk_channel_receive_shutdown_response(c, m);

	case TAPDISK_MESSAGE_RUNTIME_ERROR:
		return tapdisk_channel_receive_runtime_error(c, m);
	}

fail:
	tapdisk_channel_fatal(c, "received unexpected message %s in state %d",
			      tapdisk_message_name(m->type), c->state);
	return -EINVAL;
}
