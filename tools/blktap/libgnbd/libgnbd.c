/* libgnbd.c
 * 
 * gnbd client library
 *
 * Copyright (c) 2005, Christian Limpach
 */
  
#include <byteswap.h>
#include <endian.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <stdio.h>

#include "libgnbd.h"

#define	PROTOCOL_VERSION	2

#define	EXTERN_KILL_GSERV_REQ	5
#define	EXTERN_LOGIN_REQ	6

#define	GNBD_REQUEST_MAGIC	0x37a07e00
#define	GNBD_KEEP_ALIVE_MAGIC	0x5b46d8c2
#define	GNBD_REPLY_MAGIC	0x41f09370

enum {
	GNBD_CMD_READ = 0,
	GNBD_CMD_WRITE = 1,
	GNBD_CMD_DISC = 2,
	GNBD_CMD_PING = 3
};

#if __BYTE_ORDER == __BIG_ENDIAN
#define htonll(x) (x)
#define ntohll(x) (x)
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htonll(x) bswap_64(x)
#define ntohll(x) bswap_64(x)
#endif

#define PRINTF(x) printf x
#if 0
#define DFPRINTF(x...) fprintf(stderr, ##x)
#define DPRINTF(x) DFPRINTF x
#else
#define DPRINTF(x)
#endif

struct gnbd_request {
	struct gnbd_request	*gr_next;
	unsigned char		*gr_buf;
	ssize_t			gr_size;
	ssize_t			gr_done;
	unsigned long		gr_cookie;
};

struct gnbd_handle {
	int			gh_fd;
	unsigned int		gh_flags;
	uint64_t		gh_sectors;
	char			gh_devname[32];
	char			gh_nodename[65];
	struct sockaddr_in	gh_sin;
	struct gnbd_request	*gh_outstanding_requests;
	struct gnbd_request	**gh_outstanding_requests_last;
	struct gnbd_request	*gh_incoming_request;
	unsigned long		gh_finished_request;
};
#define	GHF_EXPECT_KILL_GSERV_REPLY	0x0001
#define	GHF_EXPECT_LOGIN_REPLY		0x0002
#define	GHF_INCOMING_REQUEST		0x0004

struct device_req {
	char		name[32];
};

struct node_req {
	char		node_name[65];
};

struct login_req {
        uint64_t	timestamp;
        uint16_t	version;
        uint8_t		pad[6];
        char		devname[32];
};

struct login_reply {
        uint64_t	sectors;
        uint16_t	version;
        uint8_t		err;
        uint8_t		pad[5];
};

struct gnbd_server_request {
	uint32_t	magic;
	uint32_t	type;
	char		handle[8];
	uint64_t	from;
	uint32_t	len;
} __attribute__ ((packed));

struct gnbd_server_reply {
	uint32_t	magic;
	uint32_t	error;
	char		handle[8];
} __attribute__ ((packed));

static int
read_buf(int fd, void *buf, size_t count, size_t *read_count)
{
	int err;

	err = read(fd, buf, count);
	if (read_count) {
		if (err >= 0)
			*read_count = err;
	} else if (err != count)
		return EINTR;	/* xxx */
	return err < 0;
}

static int
read_4(int fd, unsigned long *val)
{
	unsigned long buf;
	int err;

	err = read_buf(fd, &buf, sizeof(buf), NULL);
	if (err == 0)
		*val = ntohl(buf);
	return err;
}

static int
write_buf(int fd, void *buf, size_t count)
{
	int err;

	err = write(fd, buf, count);
	return err < 0;
}

static int
write_4(int fd, unsigned long val)
{
	unsigned long buf;
	int err;

	buf = htonl(val);
	err = write_buf(fd, &buf, sizeof(buf));
	return err;
}


static int
socket_connect(struct gnbd_handle *gh)
{
	int err;

	if (gh->gh_fd >= 0)
		return 0;

	gh->gh_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (gh->gh_fd < 0) {
		warn("socket");
		return gh->gh_fd;
	}

	err = connect(gh->gh_fd, (struct sockaddr *)&gh->gh_sin,
	    sizeof(gh->gh_sin));
	if (err) {
		warn("connect");
		goto out;
	}

	return 0;
 out:
	close (gh->gh_fd);
	gh->gh_fd = -1;
	return err;
}

static int
socket_shutdown(struct gnbd_handle *gh)
{

	close (gh->gh_fd);
	gh->gh_fd = -1;
	return 0;
}

static int
find_request(struct gnbd_handle *gh, struct gnbd_request *gr)
{
	struct gnbd_request **tmp;

	for (tmp = &gh->gh_outstanding_requests; *tmp;
	     tmp = &(*tmp)->gr_next) {
		if (*tmp == gr) {
			*tmp = (*tmp)->gr_next;
			if (*tmp == NULL)
				gh->gh_outstanding_requests_last = tmp;
			return 0;
		}
	}
	return ENOENT;
}

static int
kill_gserv(struct gnbd_handle *gh)
{
	struct device_req dr;
	struct node_req nr;
	int err;

	DPRINTF(("gnbd_kill_gserv\n"));
	err = socket_connect(gh);
	if (err) {
		warnx("socket_connect");
		return err;
	}

	err = write_4(gh->gh_fd, EXTERN_KILL_GSERV_REQ);
	if (err) {
		warnx("send EXTERN_LOGIN_REQ failed");
		goto out;
	}

	strncpy(dr.name, gh->gh_devname, sizeof(dr.name));
	err = write_buf(gh->gh_fd, &dr, sizeof(dr));
	if (err) {
		warnx("send device_req failed");
		goto out;
	}

	strncpy(nr.node_name, gh->gh_nodename, sizeof(nr.node_name));
	err = write_buf(gh->gh_fd, &nr, sizeof(nr));
	if (err) {
		warnx("send node_req failed");
		goto out;
	}

	gh->gh_flags |= GHF_EXPECT_KILL_GSERV_REPLY;
	DPRINTF(("gnbd_kill_gserv ok\n"));

	return 0;
 out:
	socket_shutdown(gh);
	return err;
}

static int
login(struct gnbd_handle *gh)
{
	struct login_req lr;
	struct node_req nr;
	int err;
	uint64_t timestamp;
	struct timeval tv;

	DPRINTF(("gnbd_login\n"));
	err = socket_connect(gh);
	if (err) {
		warnx("socket_connect");
		return err;
	}

	err = write_4(gh->gh_fd, EXTERN_LOGIN_REQ);
	if (err) {
		warnx("send EXTERN_LOGIN_REQ failed");
		goto out;
	}

	err = gettimeofday(&tv, NULL);
	if (err) {
		warnx("gettimeofday");
		goto out;
	}
	timestamp = (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;

	lr.timestamp = htonll(timestamp);
	lr.version = htons(PROTOCOL_VERSION);
	strncpy(lr.devname, gh->gh_devname, sizeof(lr.devname));
	err = write_buf(gh->gh_fd, &lr, sizeof(lr));
	if (err) {
		warnx("send login_req failed");
		goto out;
	}

	strncpy(nr.node_name, gh->gh_nodename, sizeof(nr.node_name));
	err = write_buf(gh->gh_fd, &nr, sizeof(nr));
	if (err) {
		warnx("send node_req failed");
		goto out;
	}

	gh->gh_flags |= GHF_EXPECT_LOGIN_REPLY;

	DPRINTF(("gnbd_login ok\n"));
	return 0;
 out:
	socket_shutdown(gh);
	return err;
}

static int
kill_gserv_reply(struct gnbd_handle *gh)
{
	unsigned long reply;
	int err;

	DPRINTF(("read gnbd_kill_gserv_reply\n"));
	err = read_4(gh->gh_fd, &reply);
	if (err) {
		warnx("read kill_gserv_reply failed");
		return err;
	}

	if (reply && reply != ENODEV) {
		warnx("kill gserv failed: %s", strerror(reply));
		return reply;
	}

	gh->gh_flags &= ~GHF_EXPECT_KILL_GSERV_REPLY;
	socket_shutdown(gh);

	err = login(gh);
	if (err)
		warnx("gnbd_login");

	return err;
}

static int
login_reply(struct gnbd_handle *gh)
{
	struct login_reply lr;
	int err;

	DPRINTF(("read gnbd_login_reply\n"));
	err = read_buf(gh->gh_fd, &lr, sizeof(lr), NULL);
	if (err) {
		warnx("read login_reply failed");
		return err;
	}

	if (lr.err) {
		if (lr.version) {
			warnx("gnbd version mismatch %04x != %04x",
			    PROTOCOL_VERSION, ntohs(lr.version));
			return EINVAL;
		}
		warnx("login refused: %s", strerror(lr.err));
		return lr.err;
	}
	gh->gh_sectors = ntohll(lr.sectors);

	gh->gh_flags &= ~GHF_EXPECT_LOGIN_REPLY;

	return GNBD_LOGIN_DONE;
}

static int
incoming_request(struct gnbd_handle *gh)
{
	struct gnbd_request *gr = gh->gh_incoming_request;
	ssize_t done;
	int err;

	DPRINTF(("incoming_request: done %d size %d\n", gr->gr_done,
		    gr->gr_size));
	err = read_buf(gh->gh_fd, gr->gr_buf + gr->gr_done,
	    gr->gr_size - gr->gr_done, &done);
	if (err)
		goto out;

	DPRINTF(("incoming_request: got %d\n", done));
	gr->gr_done += done;
	if (gr->gr_done == gr->gr_size) {
		gh->gh_flags &= ~GHF_INCOMING_REQUEST;
		gh->gh_finished_request = gr->gr_cookie;
		free(gr);
		return GNBD_REQUEST_DONE;
	}

	return GNBD_CONTINUE;

 out:
	gh->gh_flags &= ~GHF_INCOMING_REQUEST;
	gh->gh_finished_request = 0;
	free(gr);
	return err;
}



int
gnbd_close(struct gnbd_handle *gh)
{
	int err;
	struct gnbd_request **tmp;

	for (tmp = &gh->gh_outstanding_requests; *tmp; tmp = &(*tmp)->gr_next)
		free(*tmp);

	if (gh->gh_flags & GHF_INCOMING_REQUEST)
		free(gh->gh_incoming_request);

	err = close(gh->gh_fd);
	if (err)
		warnx("close");
	free(gh);

	return err;
}

int
gnbd_fd(struct gnbd_handle *gh)
{
	return gh->gh_fd;
}

unsigned long
gnbd_finished_request(struct gnbd_handle *gh)
{
	return gh->gh_finished_request;
}

int
gnbd_read(struct gnbd_handle *gh, uint64_t sector, ssize_t count,
    unsigned char *buf, unsigned long cookie)
{
	struct gnbd_server_request gsr;
	struct gnbd_request *gr;
	int err;

	gr = malloc(sizeof(struct gnbd_request));
	if (gr == NULL)
		return ENOMEM;
	memset(gr, 0, sizeof(gr));

	gr->gr_buf = buf;
	gr->gr_size = count << 9;
	gr->gr_done = 0;
	gr->gr_cookie = cookie;

	gsr.magic = htonl(GNBD_REQUEST_MAGIC);
	gsr.type = htonl(GNBD_CMD_READ);
	gsr.from = htonll(sector << 9);
	gsr.len = htonl(gr->gr_size);
	memset(gsr.handle, 0, sizeof(gsr.handle));
	memcpy(gsr.handle, &gr, sizeof(gr));

	err = write_buf(gh->gh_fd, &gsr, sizeof(gsr));
	if (err) {
		warnx("write_buf");
		goto out;
	}

	*gh->gh_outstanding_requests_last = gr;
	gh->gh_outstanding_requests_last = &gr->gr_next;

	return 0;

 out:
	free(gr);
	return err;
}

int
gnbd_write(struct gnbd_handle *gh, uint64_t sector, ssize_t count,
    unsigned char *buf, unsigned long cookie)
{
	struct gnbd_server_request gsr;
	struct gnbd_request *gr;
	int err;

	gr = malloc(sizeof(struct gnbd_request));
	if (gr == NULL)
		return ENOMEM;
	memset(gr, 0, sizeof(gr));

	gr->gr_buf = buf;
	gr->gr_size = count << 9;
	gr->gr_done = 0;
	gr->gr_cookie = cookie;

	gsr.magic = htonl(GNBD_REQUEST_MAGIC);
	gsr.type = htonl(GNBD_CMD_WRITE);
	gsr.from = htonll(sector << 9);
	gsr.len = htonl(gr->gr_size);
	memset(gsr.handle, 0, sizeof(gsr.handle));
	memcpy(gsr.handle, &gr, sizeof(gr));

	err = write_buf(gh->gh_fd, &gsr, sizeof(gsr));
	if (err) {
		warnx("write_buf");
		goto out;
	}

	/* XXX handle non-blocking socket */
	err = write_buf(gh->gh_fd, buf, gr->gr_size);
	if (err) {
		warnx("write_buf");
		goto out;
	}
	gr->gr_done += gr->gr_size;

	*gh->gh_outstanding_requests_last = gr;
	gh->gh_outstanding_requests_last = &gr->gr_next;

	DPRINTF(("write done\n"));

	return 0;

 out:
	free(gr);
	return err;
}

int
gnbd_reply(struct gnbd_handle *gh)
{
	struct gnbd_server_reply gsr;
	struct gnbd_request *gr;
	int err;

	DPRINTF(("gnbd_reply flags %x\n", gh->gh_flags));
	if ((gh->gh_flags & GHF_EXPECT_KILL_GSERV_REPLY))
		return kill_gserv_reply(gh);
	if ((gh->gh_flags & GHF_EXPECT_LOGIN_REPLY))
		return login_reply(gh);
	if ((gh->gh_flags & GHF_INCOMING_REQUEST))
		return incoming_request(gh);

	DPRINTF(("read response\n"));
	err = read_buf(gh->gh_fd, &gsr, sizeof(gsr), NULL);
	if (err) {
		warnx("read gnbd_reply failed");
		return err;
	}

	if (ntohl(gsr.error)) {
		warnx("gnbd server reply error: %s", strerror(gsr.error));
		return gsr.error;
	}

	switch (ntohl(gsr.magic)) {
	case GNBD_KEEP_ALIVE_MAGIC:
		DPRINTF(("read keep alive magic\n"));
		return GNBD_CONTINUE;
	case GNBD_REPLY_MAGIC:
		DPRINTF(("read reply magic\n"));
		memcpy(&gr, gsr.handle, sizeof(gr));
		err = find_request(gh, gr);
		if (err) {
			warnx("unknown request");
			return err;
		}
		if (gr->gr_done != gr->gr_size) {
			gh->gh_incoming_request = gr;
			gh->gh_flags |= GHF_INCOMING_REQUEST;
			return GNBD_CONTINUE;
		} else {
			gh->gh_finished_request = gr->gr_cookie;
			free(gr);
			return GNBD_REQUEST_DONE;
		}
	default:
		break;
	}

	return GNBD_CONTINUE;
}

uint64_t
gnbd_sectors(struct gnbd_handle *gh)
{

	return gh->gh_sectors;
}

struct gnbd_handle *
gnbd_setup(char *server, unsigned int port, char *devname, char *nodename)
{
	struct gnbd_handle *gh;
	struct addrinfo *res, *ai;
	int err;

	gh = malloc(sizeof(struct gnbd_handle));
	if (gh == NULL)
		return NULL;
	memset(gh, 0, sizeof(gh));
	gh->gh_fd = -1;
	gh->gh_outstanding_requests_last = &gh->gh_outstanding_requests;

	strncpy(gh->gh_devname, devname, sizeof(gh->gh_devname));
	strncpy(gh->gh_nodename, nodename, sizeof(gh->gh_nodename));

	err = getaddrinfo(server, NULL, NULL, &res);
	if (err) {
		if (err != EAI_SYSTEM)
			warnx("getaddrinfo: %s", gai_strerror(err));
		else
			warn("getaddrinfo: %s", gai_strerror(err));
		goto out;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_socktype != SOCK_STREAM)
			continue;
		if (ai->ai_family == AF_INET)
			break;
	}

	if (ai == NULL)
		goto out;

	gh->gh_sin.sin_family = ai->ai_family;
	gh->gh_sin.sin_port = htons(port);
	memcpy(&gh->gh_sin.sin_addr,
	    &((struct sockaddr_in *)ai->ai_addr)->sin_addr,
	    sizeof(gh->gh_sin.sin_addr));

	err = kill_gserv(gh);
	if (err) {
		warnx("gnbd_kill_gserv");
		goto out;
	}

	freeaddrinfo(res);
	return gh;
 out:
	free(gh);
	freeaddrinfo(res);
	return NULL;
}
