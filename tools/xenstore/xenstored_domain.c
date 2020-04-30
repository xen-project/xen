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
    along with this program; If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>

#include "utils.h"
#include "talloc.h"
#include "xenstored_core.h"
#include "xenstored_domain.h"
#include "xenstored_transaction.h"
#include "xenstored_watch.h"

#include <xenevtchn.h>
#include <xenctrl.h>
#include <xen/grant_table.h>

static xc_interface **xc_handle;
xengnttab_handle **xgt_handle;
static evtchn_port_t virq_port;

xenevtchn_handle *xce_handle = NULL;

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

	/* Domain path in store. */
	char *path;

	/* Shared page. */
	struct xenstore_domain_interface *interface;

	/* The connection associated with this. */
	struct connection *conn;

	/* Have we noticed that this domain is shutdown? */
	int shutdown;

	/* number of entry from this domain in the store */
	int nbentry;

	/* number of watch for this domain */
	int nbwatch;

	/* write rate limit */
	wrl_creditt wrl_credit; /* [ -wrl_config_writecost, +_dburst ] */
	struct wrl_timestampt wrl_timestamp;
	bool wrl_delay_logged;
};

static LIST_HEAD(domains);

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

static int writechn(struct connection *conn,
		    const void *data, unsigned int len)
{
	uint32_t avail;
	void *dest;
	struct xenstore_domain_interface *intf = conn->domain->interface;
	XENSTORE_RING_IDX cons, prod;

	/* Must read indexes once, and before anything else, and verified. */
	cons = intf->rsp_cons;
	prod = intf->rsp_prod;
	xen_mb();

	if (!check_indexes(cons, prod)) {
		errno = EIO;
		return -1;
	}

	dest = get_output_chunk(cons, prod, intf->rsp, &avail);
	if (avail < len)
		len = avail;

	memcpy(dest, data, len);
	xen_mb();
	intf->rsp_prod += len;

	xenevtchn_notify(xce_handle, conn->domain->port);

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
	xen_mb();

	if (!check_indexes(cons, prod)) {
		errno = EIO;
		return -1;
	}

	src = get_input_chunk(cons, prod, intf->req, &avail);
	if (avail < len)
		len = avail;

	memcpy(data, src, len);
	xen_mb();
	intf->req_cons += len;

	xenevtchn_notify(xce_handle, conn->domain->port);

	return len;
}

static void *map_interface(domid_t domid)
{
	return xengnttab_map_grant_ref(*xgt_handle, domid,
				       GNTTAB_RESERVED_XENSTORE,
				       PROT_READ|PROT_WRITE);
}

static void unmap_interface(void *interface)
{
	xengnttab_unmap(*xgt_handle, interface, 1);
}

static int destroy_domain(void *_domain)
{
	struct domain *domain = _domain;

	list_del(&domain->list);

	if (domain->port) {
		if (xenevtchn_unbind(xce_handle, domain->port) == -1)
			eprintf("> Unbinding port %i failed!\n", domain->port);
	}

	if (domain->interface) {
		/* Domain 0 was mapped by dom0_init, so it must be unmapped
		   using munmap() and not the grant unmap call. */
		if (domain->domid == 0)
			unmap_xenbus(domain->interface);
		else
			unmap_interface(domain->interface);
	}

	fire_watches(NULL, domain, "@releaseDomain", false);

	wrl_domain_destroy(domain);

	return 0;
}

static void domain_cleanup(void)
{
	xc_dominfo_t dominfo;
	struct domain *domain;
	struct connection *conn;
	int notify = 0;

 again:
	list_for_each_entry(domain, &domains, list) {
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
		if (domain->conn) {
			/* domain is a talloc child of domain->conn. */
			conn = domain->conn;
			domain->conn = NULL;
			talloc_unlink(talloc_autofree_context(), conn);
			notify = 0; /* destroy_domain() fires the watch */
			goto again;
		}
	}

	if (notify)
		fire_watches(NULL, NULL, "@releaseDomain", false);
}

/* We scan all domains rather than use the information given here. */
void handle_event(void)
{
	evtchn_port_t port;

	if ((port = xenevtchn_pending(xce_handle)) == -1)
		barf_perror("Failed to read from event fd");

	if (port == virq_port)
		domain_cleanup();

	if (xenevtchn_unmask(xce_handle, port) == -1)
		barf_perror("Failed to write to event fd");
}

bool domain_can_read(struct connection *conn)
{
	struct xenstore_domain_interface *intf = conn->domain->interface;

	if (domain_is_unprivileged(conn) && conn->domain->wrl_credit < 0)
		return false;
	return (intf->req_cons != intf->req_prod);
}

static bool domid_is_unprivileged(unsigned int domid)
{
	return domid != 0 && domid != priv_domid;
}

bool domain_is_unprivileged(struct connection *conn)
{
	return conn && conn->domain &&
	       domid_is_unprivileged(conn->domain->domid);
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
				 int port)
{
	struct domain *domain;
	int rc;

	domain = talloc(context, struct domain);
	if (!domain)
		return NULL;

	domain->port = 0;
	domain->shutdown = 0;
	domain->domid = domid;
	domain->path = talloc_domain_path(domain, domid);
	if (!domain->path)
		return NULL;

	wrl_domain_new(domain);

	list_add(&domain->list, &domains);
	talloc_set_destructor(domain, destroy_domain);

	/* Tell kernel we're interested in this event. */
	rc = xenevtchn_bind_interdomain(xce_handle, domid, port);
	if (rc == -1)
	    return NULL;
	domain->port = rc;

	domain->conn = new_connection(writechn, readchn);
	if (!domain->conn)
		return NULL;

	domain->conn->domain = domain;
	domain->conn->id = domid;

	domain->remote_port = port;
	domain->nbentry = 0;
	domain->nbwatch = 0;

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

static void domain_conn_reset(struct domain *domain)
{
	struct connection *conn = domain->conn;
	struct buffered_data *out;

	conn_delete_all_watches(conn);
	conn_delete_all_transactions(conn);

	while ((out = list_top(&conn->out_list, struct buffered_data, list))) {
		list_del(&out->list);
		talloc_free(out);
	}

	talloc_free(conn->in);

	domain->interface->req_cons = domain->interface->req_prod = 0;
	domain->interface->rsp_cons = domain->interface->rsp_prod = 0;
}

/* domid, gfn, evtchn, path */
int do_introduce(struct connection *conn, struct buffered_data *in)
{
	struct domain *domain;
	char *vec[3];
	unsigned int domid;
	evtchn_port_t port;
	int rc;
	struct xenstore_domain_interface *interface;

	if (get_strings(in, vec, ARRAY_SIZE(vec)) < ARRAY_SIZE(vec))
		return EINVAL;

	if (domain_is_unprivileged(conn) || !conn->can_write)
		return EACCES;

	domid = atoi(vec[0]);
	/* Ignore the gfn, we don't need it. */
	port = atoi(vec[2]);

	/* Sanity check args. */
	if (port <= 0)
		return EINVAL;

	domain = find_domain_by_domid(domid);

	if (domain == NULL) {
		interface = map_interface(domid);
		if (!interface)
			return errno;
		/* Hang domain off "in" until we're finished. */
		domain = new_domain(in, domid, port);
		if (!domain) {
			rc = errno;
			unmap_interface(interface);
			return rc;
		}
		domain->interface = interface;

		/* Now domain belongs to its connection. */
		talloc_steal(domain->conn, domain);

		fire_watches(NULL, in, "@introduceDomain", false);
	} else {
		/* Use XS_INTRODUCE for recreating the xenbus event-channel. */
		if (domain->port)
			xenevtchn_unbind(xce_handle, domain->port);
		rc = xenevtchn_bind_interdomain(xce_handle, domid, port);
		domain->port = (rc == -1) ? 0 : rc;
		domain->remote_port = port;
	}

	domain_conn_reset(domain);

	send_ack(conn, XS_INTRODUCE);

	return 0;
}

static struct domain *find_connected_domain(unsigned int domid)
{
	struct domain *domain;

	domain = find_domain_by_domid(domid);
	if (!domain)
		return ERR_PTR(-ENOENT);
	if (!domain->conn)
		return ERR_PTR(-EINVAL);
	return domain;
}

int do_set_target(struct connection *conn, struct buffered_data *in)
{
	char *vec[2];
	unsigned int domid, tdomid;
        struct domain *domain, *tdomain;
	if (get_strings(in, vec, ARRAY_SIZE(vec)) < ARRAY_SIZE(vec))
		return EINVAL;

	if (domain_is_unprivileged(conn) || !conn->can_write)
		return EACCES;

	domid = atoi(vec[0]);
	tdomid = atoi(vec[1]);

        domain = find_connected_domain(domid);
	if (IS_ERR(domain))
		return -PTR_ERR(domain);

        tdomain = find_connected_domain(tdomid);
	if (IS_ERR(tdomain))
		return -PTR_ERR(tdomain);

        talloc_reference(domain->conn, tdomain->conn);
        domain->conn->target = tdomain->conn;

	send_ack(conn, XS_SET_TARGET);

	return 0;
}

static struct domain *onearg_domain(struct connection *conn,
				    struct buffered_data *in)
{
	const char *domid_str = onearg(in);
	unsigned int domid;

	if (!domid_str)
		return ERR_PTR(-EINVAL);

	domid = atoi(domid_str);
	if (!domid)
		return ERR_PTR(-EINVAL);

	if (domain_is_unprivileged(conn))
		return ERR_PTR(-EACCES);

	return find_connected_domain(domid);
}

/* domid */
int do_release(struct connection *conn, struct buffered_data *in)
{
	struct domain *domain;

	domain = onearg_domain(conn, in);
	if (IS_ERR(domain))
		return -PTR_ERR(domain);

	talloc_free(domain->conn);

	send_ack(conn, XS_RELEASE);

	return 0;
}

int do_resume(struct connection *conn, struct buffered_data *in)
{
	struct domain *domain;

	domain = onearg_domain(conn, in);
	if (IS_ERR(domain))
		return -PTR_ERR(domain);

	domain->shutdown = 0;
	
	send_ack(conn, XS_RESUME);

	return 0;
}

int do_get_domain_path(struct connection *conn, struct buffered_data *in)
{
	char *path;
	const char *domid_str = onearg(in);

	if (!domid_str)
		return EINVAL;

	path = talloc_domain_path(conn, atoi(domid_str));
	if (!path)
		return errno;

	send_reply(conn, XS_GET_DOMAIN_PATH, path, strlen(path) + 1);

	talloc_free(path);

	return 0;
}

int do_is_domain_introduced(struct connection *conn, struct buffered_data *in)
{
	int result;
	unsigned int domid;
	const char *domid_str = onearg(in);

	if (!domid_str)
		return EINVAL;

	domid = atoi(domid_str);
	if (domid == DOMID_SELF)
		result = 1;
	else
		result = (find_domain_by_domid(domid) != NULL);

	send_reply(conn, XS_IS_DOMAIN_INTRODUCED, result ? "T" : "F", 2);

	return 0;
}

/* Allow guest to reset all watches */
int do_reset_watches(struct connection *conn, struct buffered_data *in)
{
	conn_delete_all_watches(conn);
	conn_delete_all_transactions(conn);

	send_ack(conn, XS_RESET_WATCHES);

	return 0;
}

static int close_xc_handle(void *_handle)
{
	xc_interface_close(*(xc_interface**)_handle);
	return 0;
}

static int close_xgt_handle(void *_handle)
{
	xengnttab_close(*(xengnttab_handle **)_handle);
	return 0;
}

/* Returns the implicit path of a connection (only domains have this) */
const char *get_implicit_path(const struct connection *conn)
{
	if (!conn->domain)
		return "/local/domain/0";
	return conn->domain->path;
}

/* Restore existing connections. */
void restore_existing_connections(void)
{
}

static int dom0_init(void) 
{ 
	evtchn_port_t port;
	struct domain *dom0;

	port = xenbus_evtchn();
	if (port == -1)
		return -1;

	dom0 = new_domain(NULL, xenbus_master_domid(), port);
	if (dom0 == NULL)
		return -1;

	dom0->interface = xenbus_map();
	if (dom0->interface == NULL)
		return -1;

	talloc_steal(dom0->conn, dom0); 

	xenevtchn_notify(xce_handle, dom0->port);

	return 0; 
}

void domain_init(void)
{
	int rc;

	xc_handle = talloc(talloc_autofree_context(), xc_interface*);
	if (!xc_handle)
		barf_perror("Failed to allocate domain handle");

	*xc_handle = xc_interface_open(0,0,0);
	if (!*xc_handle)
		barf_perror("Failed to open connection to hypervisor");

	talloc_set_destructor(xc_handle, close_xc_handle);

	xgt_handle = talloc(talloc_autofree_context(), xengnttab_handle*);
	if (!xgt_handle)
		barf_perror("Failed to allocate domain gnttab handle");

	*xgt_handle = xengnttab_open(NULL, 0);
	if (*xgt_handle == NULL)
		barf_perror("Failed to open connection to gnttab");

	talloc_set_destructor(xgt_handle, close_xgt_handle);

	xce_handle = xenevtchn_open(NULL, 0);

	if (xce_handle == NULL)
		barf_perror("Failed to open evtchn device");

	if (dom0_init() != 0) 
		barf_perror("Failed to initialize dom0 state"); 

	if ((rc = xenevtchn_bind_virq(xce_handle, VIRQ_DOM_EXC)) == -1)
		barf_perror("Failed to bind to domain exception virq port");
	virq_port = rc;
}

void domain_entry_inc(struct connection *conn, struct node *node)
{
	struct domain *d;

	if (!conn)
		return;

	if (node->perms && node->perms[0].id != conn->id) {
		if (conn->transaction) {
			transaction_entry_inc(conn->transaction,
				node->perms[0].id);
		} else {
			d = find_domain_by_domid(node->perms[0].id);
			if (d)
				d->nbentry++;
		}
	} else if (conn->domain) {
		if (conn->transaction) {
			transaction_entry_inc(conn->transaction,
				conn->domain->domid);
 		} else {
 			conn->domain->nbentry++;
		}
	}
}

void domain_entry_dec(struct connection *conn, struct node *node)
{
	struct domain *d;

	if (!conn)
		return;

	if (node->perms && node->perms[0].id != conn->id) {
		if (conn->transaction) {
			transaction_entry_dec(conn->transaction,
				node->perms[0].id);
		} else {
			d = find_domain_by_domid(node->perms[0].id);
			if (d && d->nbentry)
				d->nbentry--;
		}
	} else if (conn->domain && conn->domain->nbentry) {
		if (conn->transaction) {
			transaction_entry_dec(conn->transaction,
				conn->domain->domid);
		} else {
			conn->domain->nbentry--;
		}
	}
}

int domain_entry_fix(unsigned int domid, int num, bool update)
{
	struct domain *d;
	int cnt;

	d = find_domain_by_domid(domid);
	if (!d)
		return 0;

	cnt = d->nbentry + num;
	if (cnt < 0)
		cnt = 0;

	if (update)
		d->nbentry = cnt;

	return domid_is_unprivileged(domid) ? cnt : 0;
}

int domain_entry(struct connection *conn)
{
	return (domain_is_unprivileged(conn))
		? conn->domain->nbentry
		: 0;
}

void domain_watch_inc(struct connection *conn)
{
	if (!conn || !conn->domain)
		return;
	conn->domain->nbwatch++;
}

void domain_watch_dec(struct connection *conn)
{
	if (!conn || !conn->domain)
		return;
	if (conn->domain->nbwatch)
		conn->domain->nbwatch--;
}

int domain_watch(struct connection *conn)
{
	return (domain_is_unprivileged(conn))
		? conn->domain->nbwatch
		: 0;
}

static wrl_creditt wrl_config_writecost      = WRL_FACTOR;
static wrl_creditt wrl_config_rate           = WRL_RATE   * WRL_FACTOR;
static wrl_creditt wrl_config_dburst         = WRL_DBURST * WRL_FACTOR;
static wrl_creditt wrl_config_gburst         = WRL_GBURST * WRL_FACTOR;
static wrl_creditt wrl_config_newdoms_dburst =
	                         WRL_DBURST * WRL_NEWDOMS * WRL_FACTOR;

long wrl_ntransactions;

static long wrl_ndomains;
static wrl_creditt wrl_reserve; /* [-wrl_config_newdoms_dburst, +_gburst ] */
static time_t wrl_log_last_warning; /* 0: no previous warning */

void wrl_gettime_now(struct wrl_timestampt *now_wt)
{
	struct timespec now_ts;
	int r;

	r = clock_gettime(CLOCK_MONOTONIC, &now_ts);
	if (r)
		barf_perror("Could not find time (clock_gettime failed)");

	now_wt->sec = now_ts.tv_sec;
	now_wt->msec = now_ts.tv_nsec / 1000000;
}

static void wrl_xfer_credit(wrl_creditt *debit,  wrl_creditt debit_floor,
			    wrl_creditt *credit, wrl_creditt credit_ceil)
	/*
	 * Transfers zero or more credit from "debit" to "credit".
	 * Transfers as much as possible while maintaining
	 * debit >= debit_floor and credit <= credit_ceil.
	 * (If that's violated already, does nothing.)
	 *
	 * Sufficient conditions to avoid overflow, either of:
	 *  |every argument| <= 0x3fffffff
	 *  |every argument| <= 1E9
	 *  |every argument| <= WRL_CREDIT_MAX
	 * (And this condition is preserved.)
	 */
{
	wrl_creditt xfer = MIN( *debit      - debit_floor,
			        credit_ceil - *credit      );
	if (xfer > 0) {
		*debit -= xfer;
		*credit += xfer;
	}
}

void wrl_domain_new(struct domain *domain)
{
	domain->wrl_credit = 0;
	wrl_gettime_now(&domain->wrl_timestamp);
	wrl_ndomains++;
	/* Steal up to DBURST from the reserve */
	wrl_xfer_credit(&wrl_reserve, -wrl_config_newdoms_dburst,
			&domain->wrl_credit, wrl_config_dburst);
}

void wrl_domain_destroy(struct domain *domain)
{
	wrl_ndomains--;
	/*
	 * Don't bother recalculating domain's credit - this just
	 * means we don't give the reserve the ending domain's credit
	 * for time elapsed since last update.
	 */
	wrl_xfer_credit(&domain->wrl_credit, 0,
			&wrl_reserve, wrl_config_dburst);
}

void wrl_credit_update(struct domain *domain, struct wrl_timestampt now)
{
	/*
	 * We want to calculate
	 *    credit += (now - timestamp) * RATE / ndoms;
	 * But we want it to saturate, and to avoid floating point.
	 * To avoid rounding errors from constantly adding small
	 * amounts of credit, we only add credit for whole milliseconds.
	 */
	long seconds      = now.sec -  domain->wrl_timestamp.sec;
	long milliseconds = now.msec - domain->wrl_timestamp.msec;
	long msec;
	int64_t denom, num;
	wrl_creditt surplus;

	seconds = MIN(seconds, 1000*1000); /* arbitrary, prevents overflow */
	msec = seconds * 1000 + milliseconds;

	if (msec < 0)
                /* shouldn't happen with CLOCK_MONOTONIC */
		msec = 0;

	/* 32x32 -> 64 cannot overflow */
	denom = (int64_t)msec * wrl_config_rate;
	num  =  (int64_t)wrl_ndomains * 1000;
	/* denom / num <= 1E6 * wrl_config_rate, so with
	   reasonable wrl_config_rate, denom / num << 2^64 */

	/* at last! */
	domain->wrl_credit = MIN( (int64_t)domain->wrl_credit + denom / num,
				  WRL_CREDIT_MAX );
	/* (maybe briefly violating the DBURST cap on wrl_credit) */

	/* maybe take from the reserve to make us nonnegative */
	wrl_xfer_credit(&wrl_reserve,        0,
			&domain->wrl_credit, 0);

	/* return any surplus (over DBURST) to the reserve */
	surplus = 0;
	wrl_xfer_credit(&domain->wrl_credit, wrl_config_dburst,
			&surplus,            WRL_CREDIT_MAX);
	wrl_xfer_credit(&surplus,     0,
			&wrl_reserve, wrl_config_gburst);
	/* surplus is now implicitly discarded */

	domain->wrl_timestamp = now;

	trace("wrl: dom %4d %6ld  msec  %9ld credit   %9ld reserve"
	      "  %9ld discard\n",
	      domain->domid,
	      msec,
	      (long)domain->wrl_credit, (long)wrl_reserve,
	      (long)surplus);
}

void wrl_check_timeout(struct domain *domain,
		       struct wrl_timestampt now,
		       int *ptimeout)
{
	uint64_t num, denom;
	int wakeup;

	wrl_credit_update(domain, now);

	if (domain->wrl_credit >= 0)
		/* not blocked */
		return;

	if (!*ptimeout)
		/* already decided on immediate wakeup,
		   so no need to calculate our timeout */
		return;

	/* calculate  wakeup = now + -credit / (RATE / ndoms); */

	/* credit cannot go more -ve than one transaction,
	 * so the first multiplication cannot overflow even 32-bit */
	num   = (uint64_t)(-domain->wrl_credit * 1000) * wrl_ndomains;
	denom = wrl_config_rate;

	wakeup = MIN( num / denom /* uint64_t */, INT_MAX );
	if (*ptimeout==-1 || wakeup < *ptimeout)
		*ptimeout = wakeup;

	trace("wrl: domain %u credit=%ld (reserve=%ld) SLEEPING for %d\n",
	      domain->domid,
	      (long)domain->wrl_credit, (long)wrl_reserve,
	      wakeup);
}

#define WRL_LOG(now, ...) \
	(syslog(LOG_WARNING, "write rate limit: " __VA_ARGS__))

void wrl_apply_debit_actual(struct domain *domain)
{
	struct wrl_timestampt now;

	if (!domain || !domid_is_unprivileged(domain->domid))
		/* sockets and privileged domain escape the write rate limit */
		return;

	wrl_gettime_now(&now);
	wrl_credit_update(domain, now);

	domain->wrl_credit -= wrl_config_writecost;
	trace("wrl: domain %u credit=%ld (reserve=%ld)\n",
	      domain->domid,
	      (long)domain->wrl_credit, (long)wrl_reserve);

	if (domain->wrl_credit < 0) {
		if (!domain->wrl_delay_logged) {
			domain->wrl_delay_logged = true;
			WRL_LOG(now, "domain %ld is affected",
				(long)domain->domid);
		} else if (!wrl_log_last_warning) {
			WRL_LOG(now, "rate limiting restarts");
		}
		wrl_log_last_warning = now.sec;
	}
}

void wrl_log_periodic(struct wrl_timestampt now)
{
	if (wrl_log_last_warning &&
	    (now.sec - wrl_log_last_warning) > WRL_LOGEVERY) {
		WRL_LOG(now, "not in force recently");
		wrl_log_last_warning = 0;
	}
}

void wrl_apply_debit_direct(struct connection *conn)
{
	if (!conn)
		/* some writes are generated internally */
		return;

	if (conn->transaction)
		/* these are accounted for when the transaction ends */
		return;

	if (!wrl_ntransactions)
		/* we don't conflict with anyone */
		return;

	wrl_apply_debit_actual(conn->domain);
}

void wrl_apply_debit_trans_commit(struct connection *conn)
{
	if (wrl_ntransactions <= 1)
		/* our own transaction appears in the counter */
		return;

	wrl_apply_debit_actual(conn->domain);
}

/*
 * Local variables:
 *  mode: C
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
