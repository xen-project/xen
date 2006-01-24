/*
    Domain communications for Xen Store Daemon.
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
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdio.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//#define DEBUG
#include "utils.h"
#include "talloc.h"
#include "xenstored_core.h"
#include "xenstored_domain.h"
#include "xenstored_proc.h"
#include "xenstored_watch.h"
#include "xenstored_test.h"

#include <xenctrl.h>
#include <xen/linux/evtchn.h>

static int *xc_handle;
static evtchn_port_t virq_port;

int eventchn_fd = -1; 

struct domain
{
	struct list_head list;

	/* The id of this domain */
	unsigned int domid;

	/* Event channel port */
	evtchn_port_t port;

	/* The remote end of the event channel, used only to validate
	   repeated domain introductions. */
	evtchn_port_t remote_port;

	/* The mfn associated with the event channel, used only to validate
	   repeated domain introductions. */
	unsigned long mfn;

	/* Domain path in store. */
	char *path;

	/* Shared page. */
	struct xenstore_domain_interface *interface;

	/* The connection associated with this. */
	struct connection *conn;

	/* Have we noticed that this domain is shutdown? */
	int shutdown;
};

static LIST_HEAD(domains);

#ifndef TESTING
static void evtchn_notify(int port)
{
	int rc; 

	struct ioctl_evtchn_notify notify;
	notify.port = port;
	rc = ioctl(eventchn_fd, IOCTL_EVTCHN_NOTIFY, &notify);
}
#else
extern void evtchn_notify(int port);
#endif

/* FIXME: Mark connection as broken (close it?) when this happens. */
static bool check_indexes(XENSTORE_RING_IDX cons, XENSTORE_RING_IDX prod)
{
	return ((prod - cons) <= XENSTORE_RING_SIZE);
}

static void *get_output_chunk(XENSTORE_RING_IDX cons,
			      XENSTORE_RING_IDX prod,
			      char *buf, uint32_t *len)
{
	*len = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod);
	if ((XENSTORE_RING_SIZE - (prod - cons)) < *len)
		*len = XENSTORE_RING_SIZE - (prod - cons);
	return buf + MASK_XENSTORE_IDX(prod);
}

static const void *get_input_chunk(XENSTORE_RING_IDX cons,
				   XENSTORE_RING_IDX prod,
				   const char *buf, uint32_t *len)
{
	*len = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(cons);
	if ((prod - cons) < *len)
		*len = prod - cons;
	return buf + MASK_XENSTORE_IDX(cons);
}

static int writechn(struct connection *conn, const void *data, unsigned int len)
{
	uint32_t avail;
	void *dest;
	struct xenstore_domain_interface *intf = conn->domain->interface;
	XENSTORE_RING_IDX cons, prod;

	/* Must read indexes once, and before anything else, and verified. */
	cons = intf->rsp_cons;
	prod = intf->rsp_prod;
	mb();
	if (!check_indexes(cons, prod)) {
		errno = EIO;
		return -1;
	}

	dest = get_output_chunk(cons, prod, intf->rsp, &avail);
	if (avail < len)
		len = avail;

	memcpy(dest, data, len);
	mb();
	intf->rsp_prod += len;

	evtchn_notify(conn->domain->port);

	return len;
}

static int readchn(struct connection *conn, void *data, unsigned int len)
{
	uint32_t avail;
	const void *src;
	struct xenstore_domain_interface *intf = conn->domain->interface;
	XENSTORE_RING_IDX cons, prod;

	/* Must read indexes once, and before anything else, and verified. */
	cons = intf->req_cons;
	prod = intf->req_prod;
	mb();

	if (!check_indexes(cons, prod)) {
		errno = EIO;
		return -1;
	}

	src = get_input_chunk(cons, prod, intf->req, &avail);
	if (avail < len)
		len = avail;

	memcpy(data, src, len);
	mb();
	intf->req_cons += len;

	evtchn_notify(conn->domain->port);

	return len;
}

static int destroy_domain(void *_domain)
{
	struct domain *domain = _domain;
	struct ioctl_evtchn_unbind unbind;

	list_del(&domain->list);

	if (domain->port) {
		unbind.port = domain->port;
		if (ioctl(eventchn_fd, IOCTL_EVTCHN_UNBIND, &unbind) == -1)
			eprintf("> Unbinding port %i failed!\n", domain->port);
	}

	if (domain->interface)
		munmap(domain->interface, getpagesize());

	return 0;
}

static void domain_cleanup(void)
{
	xc_dominfo_t dominfo;
	struct domain *domain, *tmp;
	int notify = 0;

	list_for_each_entry_safe(domain, tmp, &domains, list) {
		if (xc_domain_getinfo(*xc_handle, domain->domid, 1,
				      &dominfo) == 1 &&
		    dominfo.domid == domain->domid) {
			if ((dominfo.crashed || dominfo.shutdown)
			    && !domain->shutdown) {
				domain->shutdown = 1;
				notify = 1;
			}
			if (!dominfo.dying)
				continue;
		}
		talloc_free(domain->conn);
		notify = 1;
	}

	if (notify)
		fire_watches(NULL, "@releaseDomain", false);
}

/* We scan all domains rather than use the information given here. */
void handle_event(void)
{
	evtchn_port_t port;

	if (read(eventchn_fd, &port, sizeof(port)) != sizeof(port))
		barf_perror("Failed to read from event fd");

	if (port == virq_port)
		domain_cleanup();

#ifndef TESTING
	if (write(eventchn_fd, &port, sizeof(port)) != sizeof(port))
		barf_perror("Failed to write to event fd");
#endif
}

bool domain_can_read(struct connection *conn)
{
	struct xenstore_domain_interface *intf = conn->domain->interface;
	return (intf->req_cons != intf->req_prod);
}

bool domain_can_write(struct connection *conn)
{
	struct xenstore_domain_interface *intf = conn->domain->interface;
	return ((intf->rsp_prod - intf->rsp_cons) != XENSTORE_RING_SIZE);
}

static char *talloc_domain_path(void *context, unsigned int domid)
{
	return talloc_asprintf(context, "/local/domain/%u", domid);
}

static struct domain *new_domain(void *context, unsigned int domid,
				 unsigned long mfn, int port)
{
	struct domain *domain;
	struct ioctl_evtchn_bind_interdomain bind;
	int rc;


	domain = talloc(context, struct domain);
	domain->port = 0;
	domain->shutdown = 0;
	domain->domid = domid;
	domain->path = talloc_domain_path(domain, domid);
	domain->interface = xc_map_foreign_range(
		*xc_handle, domain->domid,
		getpagesize(), PROT_READ|PROT_WRITE, mfn);
	if (!domain->interface)
		return NULL;

	list_add(&domain->list, &domains);
	talloc_set_destructor(domain, destroy_domain);

	/* Tell kernel we're interested in this event. */
	bind.remote_domain = domid;
	bind.remote_port   = port;
	rc = ioctl(eventchn_fd, IOCTL_EVTCHN_BIND_INTERDOMAIN, &bind);
	if (rc == -1)
	    return NULL;
	domain->port = rc;

	domain->conn = new_connection(writechn, readchn);
	domain->conn->domain = domain;
	domain->conn->id = domid;

	domain->remote_port = port;
	domain->mfn = mfn;

	return domain;
}


static struct domain *find_domain_by_domid(unsigned int domid)
{
	struct domain *i;

	list_for_each_entry(i, &domains, list) {
		if (i->domid == domid)
			return i;
	}
	return NULL;
}


/* domid, mfn, evtchn, path */
void do_introduce(struct connection *conn, struct buffered_data *in)
{
	struct domain *domain;
	char *vec[3];
	unsigned int domid;
	unsigned long mfn;
	evtchn_port_t port;

	if (get_strings(in, vec, ARRAY_SIZE(vec)) < ARRAY_SIZE(vec)) {
		send_error(conn, EINVAL);
		return;
	}

	if (conn->id != 0 || !conn->can_write) {
		send_error(conn, EACCES);
		return;
	}

	domid = atoi(vec[0]);
	mfn = atol(vec[1]);
	port = atoi(vec[2]);

	/* Sanity check args. */
	if (port <= 0) { 
		send_error(conn, EINVAL);
		return;
	}

	domain = find_domain_by_domid(domid);

	if (domain == NULL) {
		/* Hang domain off "in" until we're finished. */
		domain = new_domain(in, domid, mfn, port);
		if (!domain) {
			send_error(conn, errno);
			return;
		}

		/* Now domain belongs to its connection. */
		talloc_steal(domain->conn, domain);

		fire_watches(conn, "@introduceDomain", false);
	}
	else {
		/* Check that the given details match the ones we have
		   previously recorded. */
		if (port != domain->remote_port ||
		    mfn != domain->mfn) {
			send_error(conn, EINVAL);
			return;
		}
	}

	send_ack(conn, XS_INTRODUCE);
}

/* domid */
void do_release(struct connection *conn, const char *domid_str)
{
	struct domain *domain;
	unsigned int domid;

	if (!domid_str) {
		send_error(conn, EINVAL);
		return;
	}

	domid = atoi(domid_str);
	if (!domid) {
		send_error(conn, EINVAL);
		return;
	}

	if (conn->id != 0) {
		send_error(conn, EACCES);
		return;
	}

	domain = find_domain_by_domid(domid);
	if (!domain) {
		send_error(conn, ENOENT);
		return;
	}

	if (!domain->conn) {
		send_error(conn, EINVAL);
		return;
	}

	talloc_free(domain->conn);

	fire_watches(conn, "@releaseDomain", false);

	send_ack(conn, XS_RELEASE);
}

void do_get_domain_path(struct connection *conn, const char *domid_str)
{
	char *path;

	if (!domid_str) {
		send_error(conn, EINVAL);
		return;
	}

	path = talloc_domain_path(conn, atoi(domid_str));

	send_reply(conn, XS_GET_DOMAIN_PATH, path, strlen(path) + 1);

	talloc_free(path);
}

void do_is_domain_introduced(struct connection *conn, const char *domid_str)
{
	int result;
	unsigned int domid;

	if (!domid_str) {
		send_error(conn, EINVAL);
		return;
	}

	domid = atoi(domid_str);
	if (domid == DOMID_SELF)
		result = 1;
	else
		result = (find_domain_by_domid(domid) != NULL);

	send_reply(conn, XS_IS_DOMAIN_INTRODUCED, result ? "T" : "F", 2);
}

static int close_xc_handle(void *_handle)
{
	xc_interface_close(*(int *)_handle);
	return 0;
}

/* Returns the implicit path of a connection (only domains have this) */
const char *get_implicit_path(const struct connection *conn)
{
	if (!conn->domain)
		return NULL;
	return conn->domain->path;
}

/* Restore existing connections. */
void restore_existing_connections(void)
{
}

static int dom0_init(void) 
{ 
	int rc, fd;
	evtchn_port_t port; 
	unsigned long mfn; 
	char str[20]; 
	struct domain *dom0; 

	fd = open(XENSTORED_PROC_MFN, O_RDONLY); 
	if (fd == -1)
		return -1;

	rc = read(fd, str, sizeof(str)); 
	if (rc == -1)
		goto outfd;
	str[rc] = '\0'; 
	mfn = strtoul(str, NULL, 0); 

	close(fd); 

	fd = open(XENSTORED_PROC_PORT, O_RDONLY); 
	if (fd == -1)
		return -1;

	rc = read(fd, str, sizeof(str)); 
	if (rc == -1)
		goto outfd;
	str[rc] = '\0'; 
	port = strtoul(str, NULL, 0); 

	close(fd); 

	dom0 = new_domain(NULL, 0, mfn, port); 
	talloc_steal(dom0->conn, dom0); 

	evtchn_notify(dom0->port); 

	return 0; 
outfd:
	close(fd);
	return -1;
}



#define EVTCHN_DEV_NAME  "/dev/xen/evtchn"
#define EVTCHN_DEV_MAJOR 10
#define EVTCHN_DEV_MINOR 201


/* Returns the event channel handle. */
int domain_init(void)
{
	struct stat st;
	struct ioctl_evtchn_bind_virq bind;
	int rc;

	xc_handle = talloc(talloc_autofree_context(), int);
	if (!xc_handle)
		barf_perror("Failed to allocate domain handle");

	*xc_handle = xc_interface_open();
	if (*xc_handle < 0)
		barf_perror("Failed to open connection to hypervisor");

	talloc_set_destructor(xc_handle, close_xc_handle);

#ifdef TESTING
	eventchn_fd = fake_open_eventchn();
	(void)&st;
#else
	/* Make sure any existing device file links to correct device. */
	if ((lstat(EVTCHN_DEV_NAME, &st) != 0) || !S_ISCHR(st.st_mode) ||
	    (st.st_rdev != makedev(EVTCHN_DEV_MAJOR, EVTCHN_DEV_MINOR)))
		(void)unlink(EVTCHN_DEV_NAME);

 reopen:
	eventchn_fd = open(EVTCHN_DEV_NAME, O_NONBLOCK|O_RDWR);
	if (eventchn_fd == -1) {
		if ((errno == ENOENT) &&
		    ((mkdir("/dev/xen", 0755) == 0) || (errno == EEXIST)) &&
		    (mknod(EVTCHN_DEV_NAME, S_IFCHR|0600,
			   makedev(EVTCHN_DEV_MAJOR, EVTCHN_DEV_MINOR)) == 0))
			goto reopen;
		return -errno;
	}
#endif
	if (eventchn_fd < 0)
		barf_perror("Failed to open evtchn device");

	if (dom0_init() != 0) 
		barf_perror("Failed to initialize dom0 state"); 

	bind.virq = VIRQ_DOM_EXC;
	rc = ioctl(eventchn_fd, IOCTL_EVTCHN_BIND_VIRQ, &bind);
	if (rc == -1)
		barf_perror("Failed to bind to domain exception virq port");
	virq_port = rc;

	return eventchn_fd;
}

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
