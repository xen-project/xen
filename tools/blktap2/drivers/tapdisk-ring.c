/* 
 * Copyright (c) 2008, XenSource Inc.
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
#include <errno.h>

#include "tapdisk-ring.h"

static int
tapdisk_uring_create_ctlfd(td_uring_t *ring)
{
	int fd, err;
	struct sockaddr_un saddr;

	if (strnlen(ring->ctlfd_path, sizeof(saddr.sun_family)) >=
	    sizeof(saddr.sun_family))
		return -ENAMETOOLONG;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
		return -errno;

	memset(&saddr, 0, sizeof(struct sockaddr_un));
	saddr.sun_family = AF_UNIX;
	memcpy(saddr.sun_path, ring->ctlfd_path, strlen(ring->ctlfd_path));

	err = unlink(ring->ctlfd_path);
	if (err == -1 && errno != ENOENT) {
		err = -errno;
		goto fail;
	}

	err = bind(fd, &saddr, sizeof(struct sockaddr_un));
	if (err == -1) {
		err = -errno;
		goto fail;
	}

	err = listen(fd, 1);
	if (err == -1) {
		err = -errno;
		goto fail;
	}

	ring->ctlfd = fd;
	return 0;

fail:
	close(fd);
	return err;
}

static void
tapdisk_uring_destroy_ctlfd(td_uring_t *ring)
{
	if (ring->ctlfd) {
		close(ring->ctlfd);
		ring->ctlfd = 0;
	}

	if (ring->ctlfd_path) {
		unlink(ring->ctlfd_path);
		free(ring->ctlfd_path);
		ring->ctlfd_path = NULL;
	}
}

static int
tapdisk_uring_connect_ctlfd(td_uring_t *ring)
{
	int fd, err;
	struct sockaddr_un saddr;

	if (strnlen(ring->ctlfd_path, sizeof(saddr.sun_path)) >=
	    sizeof(saddr.sun_path))
		return -ENAMETOOLONG;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
		return -errno;

	memset(&saddr, 0, sizeof(struct sockaddr_un));
	saddr.sun_family = AF_UNIX;
	memcpy(saddr.sun_path, ring->ctlfd_path, strlen(ring->ctlfd_path));

	err = connect(fd, &saddr, sizeof(saddr));
	if (err == -1) {
		err = -errno;
		goto fail;
	}

	ring->ctlfd = fd;
	return 0;

fail:
	close(fd);
	return err;
}

static void
tapdisk_uring_disconnect_ctlfd(td_uring_t *ring)
{
	if (ring->ctlfd)
		close(ring->ctlfd);
	free(ring->ctlfd_path);
	ring->ctlfd_path = NULL;
}

static int
tapdisk_uring_create_shmem(td_uring_t *ring)
{
	int fd, err;

	fd = shm_open(ring->shmem_path, O_CREAT | O_RDWR, 0750);
	if (fd == -1)
		return -errno;

	err = ftruncate(fd, ring->shmem_size);
	if (err == -1) {
		err = -errno;
		goto out;
	}

	ring->shmem = mmap(NULL, ring->shmem_size,
			   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ring->shmem == MAP_FAILED) {
		ring->shmem = NULL;
		err = -errno;
		goto out;
	}

	err = 0;

out:
	close(fd);
	return err;
}

static void
tapdisk_uring_destroy_shmem(td_uring_t *ring)
{
	if (ring->shmem) {
		munmap(ring->shmem, ring->shmem_size);
		ring->shmem = NULL;
	}

	if (ring->shmem_path) {
		shm_unlink(ring->shmem_path);
		free(ring->shmem_path);
		ring->shmem_path = NULL;
	}
}

static int
tapdisk_uring_connect_shmem(td_uring_t *ring)
{
	int fd, err;
	td_uring_header_t header, *p;

	fd = shm_open(ring->shmem_path, O_RDWR);
	if (fd == -1)
		return -errno;

	p = mmap(NULL, sizeof(td_uring_header_t),
		 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		err = -errno;
		goto out;
	}

	memcpy(&header, p, sizeof(td_uring_header_t));
	munmap(p, sizeof(td_uring_header_t));

	if (memcmp(header.cookie,
		   TAPDISK_URING_COOKIE, sizeof(header.cookie))) {
		err = -EINVAL;
		goto out;
	}

	if (header.version != TD_URING_CURRENT_VERSION) {
		err = -EINVAL;
		goto out;
	}

	ring->ring_size  = header.ring_size;
	ring->data_size  = header.data_size;
	ring->shmem_size = header.shmem_size;

	ring->shmem = mmap(NULL, ring->shmem_size,
			   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ring->shmem == MAP_FAILED) {
		rint->shmem = NULL;
		err = -errno;
		goto out;
	}

	err = 0;

out:
	close(fd);
	return err;
}

static void
tapdisk_uring_disconnect_shmem(td_uring_t *ring)
{
	if (ring->shmem)
		munmap(ring->shmem, ring->shmem_size);
	free(ring->shmem_path);
	ring->shmem_path = NULL;
}

int
tapdisk_uring_create(td_uring_t *ring, const char *location,
		    uint32_t ring_size, uint32_t data_size)
{
	int fd, err;

	memset(ring, 0, sizeof(td_uring_t));

	ring->ring_size  = ring_size;
	ring->data_size  = data_size;
	ring->shmem_size = ring_size + data_size + sizeof(td_uring_header_t);

	err = asprintf(&ring->shmem_path, "%s.shm", location);
	if (err == -1) {
		ring->shmem_path = NULL;
		err = -errno;
		goto fail;
	}

	err = asprintf(&ring->ctlfd_path, "%s.cfd", location);
	if (err == -1) {
		ring->ctlfd_path = NULL;
		err = -errno;
		goto fail;
	}

	err = tapdisk_uring_create_ctlfd(ring);
	if (err)
		goto fail;

	err = tapdisk_uring_create_shmem(ring);
	if (err)
		goto fail;

	ring->ring_area = (unsigned long)ring->shmem + sizeof(td_uring_header_t);
	ring->data_area = (unsigned long)ring->ring_area + ring->ring_size;

	return 0;

fail:
	tapdisk_uring_destroy(ring);
	return err;
}

int
tapdisk_uring_destroy(td_uring_t *ring)
{
	tapdisk_uring_destroy_shmem(ring);
	tapdisk_uring_destroy_ctlfd(ring);
	return 0;
}

int
tapdisk_uring_connect(td_uring_t *ring, const char *location)
{
	int fd, err;

	memset(ring, 0, sizeof(td_uring_t));

	err = asprintf(&ring->shmem_path, "%s.shm", location);
	if (err == -1) {
		ring->shmem_path = NULL;
		err = -errno;
		goto fail;
	}

	err = asprintf(&ring->ctlfd_path, "%s.cfd", location);
	if (err == -1) {
		ring->ctlfd_path = NULL;
		err = -errno;
		goto fail;
	}

	err = tapdisk_uring_connect_ctlfd(ring);
	if (err)
		goto fail;

	err = tapdisk_uring_connect_shmem(ring);
	if (err)
		goto fail;

	err = 0;

fail:
}

int
tapdisk_uring_disconnect(td_uring_t *ring)
{
	tapdisk_uring_disconnect_shmem(ring);
	tapdisk_uring_disconnect_ctlfd(ring);
	return 0;
}

static int
tapdisk_ring_read_message(int fd, td_uring_message_t *message, int timeout)
{
	fd_set readfds;
	int ret, len, offset;
	struct timeval tv, *t;

	t      = NULL;
	offset = 0;
	len    = sizeof(td_uring_message_t);

	if (timeout) {
		tv.tv_sec  = timeout;
		tv.tv_usec = 0;
		t = &tv;
	}

	while (offset < len) {
		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);

		/* we don't bother reinitializing tv. at worst, it will wait a
		 * bit more time than expected. */

		ret = select(fd + 1, &readfds, NULL, NULL, t);
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

	if (offset != len)
		return -EIO;

	return 0;
}

static int
tapdisk_ring_write_message(int fd, td_uring_message_t *message, int timeout)
{
	fd_set writefds;
	int ret, len, offset;
	struct timeval tv, *t;

	t      = NULL;
	offset = 0;
	len    = sizeof(td_uring_message_t);

	if (timeout) {
		tv.tv_sec  = timeout;
		tv.tv_usec = 0;
		t = &tv;
	}

	while (offset < len) {
		FD_ZERO(&writefds);
		FD_SET(fd, &writefds);

		/* we don't bother reinitializing tv. at worst, it will wait a
		 * bit more time than expected. */

		ret = select(fd + 1, NULL, &writefds, NULL, t);
		if (ret == -1)
			break;
		else if (FD_ISSET(fd, &writefds)) {
			ret = write(fd, message + offset, len - offset);
			if (ret <= 0)
				break;
			offset += ret;
		} else
			break;
	}

	if (offset != len)
		return -EIO;

	return 0;
}

int
tapdisk_uring_poll(td_uring_t *ring)
{
	int err;
	td_uring_message_t message;

	err = tapdisk_uring_read_message(ring->ctlfd, &message, 1);
	if (err)
		return err;

	if (message.type != TAPDISK_URING_MESSAGE_KICK)
		return -EINVAL;

	return 0;
}

int
tapdisk_uring_kick(td_uring_t *ring)
{
	td_uring_message_t message;

	memset(&message, 0, sizeof(td_uring_message_t));
	message.type = TAPDISK_URING_MESSAGE_KICK;

	return tapdisk_uring_write_message(ring->ctlfd, &message, 1);
}
