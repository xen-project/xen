#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "minixend.h"

struct command {
	const char *name;
	void (*func)(struct open_connection *oc, const struct command *c,
		     const char *, const char *);
};

static void
domain_created(const char *name, int mem_kb, int domid)
{
	struct domain *d;
	d = xmalloc(sizeof(*d));
	d->domid = domid;
	d->name = xstrdup(name);
	d->mem_kb = mem_kb;
	d->state = DOM_STATE_CREATED;
	d->control_evtchn = -1; /* Not connected yet. */

	memcpy(d->netif_mac, "\xaa\x00\x00\x02\x00\x00", 6);
	d->netif_mac[5] = d->domid;

	pthread_mutex_init(&d->mux, NULL);
	pthread_cond_init(&d->cond, NULL);
	pthread_create(&d->thread, NULL, domain_thread_func, d);

	list_insert_after(&d->domain_list, &head_domain);
}

static struct domain *
find_domain(int domain_id)
{
	struct domain *d;

	foreach_domain(d) {
		if (d->domid == domain_id)
			return d;
	}
	return NULL;
}

static int
free_event_port(struct domain *d, int port)
{
	if (d == NULL)
		return xc_evtchn_close(xc_handle, DOMID_SELF, port);
	else
		return xc_evtchn_close(xc_handle, d->domid, port);
}

static char *
readline(struct open_connection *oc)
{
	char *end;
	char *res;
	int line_length;

	if (oc->state == OC_STATE_ERROR)
		return NULL;

	end = memchr(oc->buf, '\r', oc->buf_used);
	assert(end != NULL);
	line_length = end - oc->buf;

	res = xmalloc(line_length + 1);
	memcpy(res, oc->buf, line_length);
	res[line_length] = 0;
	memmove(oc->buf, oc->buf + line_length + 2,
		oc->buf_used - line_length - 2);

	oc->buf_used -= line_length + 2;

	if (memchr(oc->buf, '\n', oc->buf_used))
		oc->state = OC_STATE_COMMAND_PENDING;
	else
		oc->state = OC_STATE_CONNECTED;

	return res;
}

static unsigned long
find_domain_shared_info_mfn(struct domain *d)
{
	xc_dominfo_t info;

	xc_domain_getinfo(xc_handle, d->domid, 1, &info);
	return info.shared_info_frame;
}

static void
send_message(struct open_connection *oc, const char *fmt, ...)
{
	char *buf;
	va_list ap;
	int size;
	int off;
	ssize_t r;

	if (oc->state == OC_STATE_ERROR)
		return;

	va_start(ap, fmt);
	size = vasprintf(&buf, fmt, ap);
	va_end(ap);
	if (size < 0)
		err(1, "preparing response to a query");
	assert(buf[0] == 'E' || buf[0] == 'N');
	assert(isdigit(buf[1]));
	assert(isdigit(buf[2]));
	assert(buf[3] == ' ' || buf[3] == '\n');

	off = 0;
	while (off < size) {
		r = write(oc->fd, buf + off, size - off);
		if (r < 0) {
			warn("sending response to remote");
			oc->state = OC_STATE_ERROR;
			free(buf);
			return;
		}
		off += r;
	}
	free(buf);
}

static void
default_command_handler(struct open_connection *oc, const struct command *ign,
			const char *buf, const char *args)
{
	warnx("bad command %s", buf);
	send_message(oc, "E00 unknown command %s\n", buf);
}

static void
create_command_handler(struct open_connection *oc, const struct command *ign,
		       const char *buf, const char *args)
{
	char *name;
	unsigned mem_kb;
	int r;
	u32 domid = -1;

	r = sscanf(args, "%d %a[^\n]", &mem_kb, &name);
	if (r != 2) {
		send_message(oc, "E01 failed to parse %s\n", args);
		return;
	}
	r = xc_domain_create(xc_handle, mem_kb, -1, 0, &domid);
	if (r < 0) {
		send_message(oc, "E02 creating domain (%s)\n",
			     strerror(errno));
		free(name);
		return;
	}

	domain_created(name, mem_kb, domid);

	send_message(oc, "N00 %d\n", domid);
	free(name);
}

static void
build_command_handler(struct open_connection *oc, const struct command *ign,
		      const char *buf, const char *args)
{
	struct domain *d;
	int domain_id;
	char *image, *cmdline;
	int event_ports[2];
	int r;

	r = sscanf(args, "%d %a[^\t] %a[^\n]", &domain_id,
		   &image, &cmdline);
	if (r != 3) {
		send_message(oc, "E03 failed to parse %s\n", args);
		return;
	}
	d = find_domain(domain_id);
	if (d == NULL) {
		send_message(oc, "E04 unknown domain %d\n", domain_id);
		goto out;
	}
	if (d->state != DOM_STATE_CREATED) {
		send_message(oc, "E05 domain %d in bad state\n", domain_id);
		goto out;
	}

	r = allocate_event_channel(d, event_ports);
	if (r < 0) {
		send_message(oc, "E06 allocating control event channel: %s\n",
			     strerror(errno));
		goto out;
	}

	r = xc_linux_build(xc_handle, domain_id, image, NULL, cmdline,
			   event_ports[1], 0);
	if (r < 0) {
		send_message(oc, "E07 building domain: %s\n",
			     strerror(errno));
		free_event_port(NULL, event_ports[0]);
		free_event_port(d, event_ports[1]);
		goto out;
	}

	if (ioctl(evtchn_fd, EVTCHN_BIND, event_ports[0]) < 0)
		err(1, "binding to event control event channel");

	d->shared_info_mfn = find_domain_shared_info_mfn(d);
	d->shared_info = map_domain_mem(d, d->shared_info_mfn);
	if (d->shared_info == NULL)
		err(1, "maping domain shared info page at %lx.\n",
		    d->shared_info_mfn);
	d->ctrl_if = (control_if_t *)((unsigned)d->shared_info + 2048);

	d->control_evtchn = event_ports[0];
	d->state = DOM_STATE_PAUSED;

	send_message(oc, "N00\n");

 out:
	free(image);
	free(cmdline);
	return;
}

static void
unpause_command_handler(struct open_connection *oc,
			const struct command *ign,
			const char *buf,
			const char *args)
{
	int domain_id;
	int r;
	struct domain *d;

	r = sscanf(args, "%d", &domain_id);
	if (r != 1) {
		send_message(oc, "E08 cannot parse %s\n", args);
		return;
	}
	d = find_domain(domain_id);
	if (d == NULL) {
		send_message(oc, "E09 cannot find domain %d\n", domain_id);
		return;
	}
	if (d->state != DOM_STATE_PAUSED) {
		send_message(oc, "E10 domain not paused\n");
		return;
	}

	r = xc_domain_unpause(xc_handle, d->domid);
	if (r < 0) {
		send_message(oc, "E11 unpausing domain: %s\n",
			     strerror(errno));
		return;
	}

	d->state = DOM_STATE_RUNNING;
	send_message(oc, "N00\n");
}

static void
console_command_handler(struct open_connection *oc,
			const struct command *ign,
			const char *buf,
			const char *args)
{
	int domain_id;
	struct domain *d;
	int r;
	struct sockaddr_in name;
	socklen_t namelen;

	r = sscanf(args, "%d", &domain_id);
	if (r != 1) {
		send_message(oc, "E12 cannot parse %s\n", args);
		return;
	}
	d = find_domain(domain_id);
	if (d == NULL) {
		send_message(oc, "E13 cannot find domain %d\n", domain_id);
		return;
	}
	if (d->cc != NULL) {
		send_message(oc, "E14 console already exists\n");
		return;
	}

	d->cc = xmalloc(sizeof(*d->cc));
	d->cc->fd = socket(PF_INET, SOCK_STREAM, 0);
	if (d->cc->fd < 0)
		err(1, "creating console socket");
	d->cc->dom = d;
	d->cc->state = CC_STATE_PENDING;
	d->cc->buf_used = 0;
	d->cc->buf_allocated = 0;
	d->cc->buf = NULL;

	r = listen(d->cc->fd, 1);
	if (r < 0)
		err(1, "listening on console socket");
	namelen = sizeof(name);
	r = getsockname(d->cc->fd, (struct sockaddr *)&name, &namelen);
	if (r < 0)
		err(1, "getting name of console socket");
	assert(name.sin_family == AF_INET);
	assert(namelen == sizeof(name));
	list_insert_after(&d->cc->list, &head_console);
	send_message(oc, "N00 %d\n", ntohs(name.sin_port));
}

static void
plug_command_handler(struct open_connection *oc,
		     const struct command *ign,
		     const char *buf,
		     const char *args)
{
	unsigned domid;
	int r;
	struct domain *d;

	r = sscanf(args, "%d", &domid);
	if (r != 1) {
		send_message(oc, "E15 cannot parse %s\n", args);
		return;
	}
	d = find_domain(domid);
	if (d == NULL) {
		send_message(oc, "E16 cannot find domain %d\n", domid);
		return;
	}

	d->plugged = 1;
	send_message(oc, "N00\n");
	PRINTF(1, "set domain %d plug state to %d\n", d->domid, d->plugged);
}

static void
destroy_command_handler(struct open_connection *oc,
			const struct command *ign,
			const char *buf,
			const char *args)
{
	unsigned domid;
	int r;
	struct domain *d;

	r = sscanf(args, "%d", &domid);
	if (r != 1) {
		send_message(oc, "E17 cannot parse %s\n", args);
		return;
	}
	d = find_domain(domid);
	if (d == NULL) {
		send_message(oc, "E18 cannot find domain %d\n", domid);
		return;
	}

	r = xc_domain_destroy(xc_handle, domid);
	if (r < 0) {
		send_message( oc, "E19 error destroying domain %d: %s\n",
			      domid, strerror(errno) );
		return;
	}
	d->state = DOM_STATE_DEAD;

	send_message(oc, "N00\n");
}

static void
list_command_handler(struct open_connection *oc,
		     const struct command *ign,
		     const char *buf,
		     const char *args)
{
	struct domain *d;
	static const char *const state_strings[] = {
		[DOM_STATE_CREATED] = "created",
		[DOM_STATE_PAUSED] = "paused",
		[DOM_STATE_RUNNING] = "running",
		[DOM_STATE_DEAD] = "dead"
	};

	foreach_domain(d) {
		send_message(oc, "N01 %d %s %d %s\n",
			     d->domid,
			     d->name,
			     d->mem_kb,
			     state_strings[d->state]);
	}
	send_message(oc, "N00\n");
}

static struct command
default_command = { NULL, default_command_handler };

static struct command
commands[] = {
	{ "build", build_command_handler },
	{ "console", console_command_handler },
	{ "create", create_command_handler },
	{ "destroy", destroy_command_handler },
	{ "plug", plug_command_handler },
	{ "list", list_command_handler },
	{ "unpause", unpause_command_handler }
};

void
process_command(struct open_connection *oc)
{
	char *buf, *b;
	int command_len;
	int x;
	struct command *cmd;

	buf = readline(oc);
	if (buf == NULL)
		return;
	b = strchr(buf, ' ');
	if (b == NULL)
		command_len = strlen(buf);
	else
		command_len = b - buf;
	b = buf + command_len;
	while (b[0] && b[0] == ' ')
		b++;

	cmd = &default_command;
	for (x = 0; x < sizeof(commands) / sizeof(commands[0]); x++) {
		if (strlen(commands[x].name) == command_len &&
		    memcmp(commands[x].name, buf, command_len) == 0) {
			cmd = &commands[x];
			break;
		}
	}
	cmd->func(oc, cmd, buf, b);
	free(buf);
	return;
}
