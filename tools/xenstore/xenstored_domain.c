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

#include <assert.h>
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
#include "xenstored_control.h"

#include <xenevtchn.h>
#include <xenctrl.h>
#include <xen/grant_table.h>

static xc_interface **xc_handle;
xengnttab_handle **xgt_handle;
static evtchn_port_t virq_port;

xenevtchn_handle *xce_handle = NULL;

struct domain
{
	/* The id of this domain */
	unsigned int domid;

	/* Event channel port */
	evtchn_port_t port;

	/* Domain path in store. */
	char *path;

	/* Shared page. */
	struct xenstore_domain_interface *interface;

	/* The connection associated with this. */
	struct connection *conn;

	/* Generation count at domain introduction time. */
	uint64_t generation;

	/* Have we noticed that this domain is shutdown? */
	bool shutdown;

	/* Has domain been officially introduced? */
	bool introduced;

	/* Accounting data for this domain. */
	unsigned int acc[ACC_N];

	/* Amount of memory allocated for this domain. */
	int memory;
	bool soft_quota_reported;
	bool hard_quota_reported;
	time_t mem_last_msg;
#define MEM_WARN_MINTIME_SEC 10

	/* number of watch for this domain */
	int nbwatch;

	/* Number of outstanding requests. */
	int nboutstanding;

	/* write rate limit */
	wrl_creditt wrl_credit; /* [ -wrl_config_writecost, +_dburst ] */
	struct wrl_timestampt wrl_timestamp;
	bool wrl_delay_logged;
};

struct changed_domain
{
	/* List of all changed domains. */
	struct list_head list;

	/* Identifier of the changed domain. */
	unsigned int domid;

	/* Accounting data. */
	int acc[ACC_CHD_N];
};

static struct hashtable *domhash;

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

static bool domain_can_write(struct connection *conn)
{
	struct xenstore_domain_interface *intf = conn->domain->interface;

	return ((intf->rsp_prod - intf->rsp_cons) != XENSTORE_RING_SIZE);
}

static bool domain_can_read(struct connection *conn)
{
	struct xenstore_domain_interface *intf = conn->domain->interface;

	if (domain_is_unprivileged(conn)) {
		if (conn->domain->wrl_credit < 0)
			return false;
		if (conn->domain->nboutstanding >= quota_req_outstanding)
			return false;
		if (conn->domain->memory >= quota_memory_per_domain_hard &&
		    quota_memory_per_domain_hard)
			return false;
	}

	return (intf->req_cons != intf->req_prod);
}

static const struct interface_funcs domain_funcs = {
	.write = writechn,
	.read = readchn,
	.can_write = domain_can_write,
	.can_read = domain_can_read,
};

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

static int domain_tree_remove_sub(const void *ctx, struct connection *conn,
				  struct node *node, void *arg)
{
	struct domain *domain = arg;
	TDB_DATA key;
	int ret = WALK_TREE_OK;

	if (node->perms.p[0].id != domain->domid)
		return WALK_TREE_OK;

	if (keep_orphans) {
		set_tdb_key(node->name, &key);
		domain_nbentry_dec(NULL, domain->domid);
		node->perms.p[0].id = priv_domid;
		node->acc.memory = 0;
		domain_nbentry_inc(NULL, priv_domid);
		if (write_node_raw(NULL, &key, node, true)) {
			/* That's unfortunate. We only can try to continue. */
			syslog(LOG_ERR,
			       "error when moving orphaned node %s to dom0\n",
			       node->name);
		} else
			trace("orphaned node %s moved to dom0\n", node->name);
	} else {
		if (rm_node(NULL, ctx, node->name)) {
			/* That's unfortunate. We only can try to continue. */
			syslog(LOG_ERR,
			       "error when deleting orphaned node %s\n",
			       node->name);
		} else
			trace("orphaned node %s deleted\n", node->name);

		/* Skip children in all cases in order to avoid more errors. */
		ret = WALK_TREE_SKIP_CHILDREN;
	}

	return domain->acc[ACC_NODES] ? ret : WALK_TREE_SUCCESS_STOP;
}

static void domain_tree_remove(struct domain *domain)
{
	int ret;
	struct walk_funcs walkfuncs = { .enter = domain_tree_remove_sub };

	if (domain->acc[ACC_NODES]) {
		ret = walk_node_tree(domain, NULL, "/", &walkfuncs, domain);
		if (ret == WALK_TREE_ERROR_STOP)
			syslog(LOG_ERR,
			       "error when looking for orphaned nodes\n");
	}

	walk_node_tree(domain, NULL, "@releaseDomain", &walkfuncs, domain);
	walk_node_tree(domain, NULL, "@introduceDomain", &walkfuncs, domain);
}

static void fire_special_watches(const char *name)
{
	void *ctx = talloc_new(NULL);
	struct node *node;

	if (!ctx)
		return;

	node = read_node(NULL, ctx, name);

	if (node)
		fire_watches(NULL, ctx, name, node, true, NULL);
	else
		log("special node %s not found\n", name);

	talloc_free(ctx);
}

static int destroy_domain(void *_domain)
{
	struct domain *domain = _domain;

	domain_tree_remove(domain);

	hashtable_remove(domhash, &domain->domid);

	if (!domain->introduced)
		return 0;

	if (domain->port) {
		if (xenevtchn_unbind(xce_handle, domain->port) == -1)
			eprintf("> Unbinding port %i failed!\n", domain->port);
	}

	if (domain->interface) {
		/* Domain 0 was mapped by dom0_init, so it must be unmapped
		   using munmap() and not the grant unmap call. */
		if (domain->domid == dom0_domid)
			unmap_xenbus(domain->interface);
		else
			unmap_interface(domain->interface);
	}

	fire_special_watches("@releaseDomain");

	wrl_domain_destroy(domain);

	return 0;
}

static bool get_domain_info(unsigned int domid, xc_domaininfo_t *dominfo)
{
	return xc_domain_getinfo_single(*xc_handle, domid, dominfo) == 0;
}

static int check_domain(const void *k, void *v, void *arg)
{
	xc_domaininfo_t dominfo;
	struct connection *conn;
	bool dom_valid;
	struct domain *domain = v;
	bool *notify = arg;

	dom_valid = get_domain_info(domain->domid, &dominfo);
	if (!domain->introduced) {
		if (!dom_valid)
			talloc_free(domain);
		return 0;
	}
	if (dom_valid) {
		if ((dominfo.flags & XEN_DOMINF_shutdown)
		    && !domain->shutdown) {
			domain->shutdown = true;
			*notify = true;
		}
		if (!(dominfo.flags & XEN_DOMINF_dying))
			return 0;
	}
	if (domain->conn) {
		/* domain is a talloc child of domain->conn. */
		conn = domain->conn;
		domain->conn = NULL;
		talloc_unlink(talloc_autofree_context(), conn);
		*notify = false; /* destroy_domain() fires the watch */

		/* Above unlink might result in 2 domains being freed! */
		return 1;
	}

	return 0;
}

void check_domains(void)
{
	bool notify = false;

	while (hashtable_iterate(domhash, check_domain, &notify))
		;

	if (notify)
		fire_special_watches("@releaseDomain");
}

/* We scan all domains rather than use the information given here. */
void handle_event(void)
{
	evtchn_port_t port;

	if ((port = xenevtchn_pending(xce_handle)) == -1)
		barf_perror("Failed to read from event fd");

	if (port == virq_port)
		check_domains();

	if (xenevtchn_unmask(xce_handle, port) == -1)
		barf_perror("Failed to write to event fd");
}

static char *talloc_domain_path(const void *context, unsigned int domid)
{
	return talloc_asprintf(context, "/local/domain/%u", domid);
}

static struct domain *find_domain_struct(unsigned int domid)
{
	return hashtable_search(domhash, &domid);
}

int domain_get_quota(const void *ctx, struct connection *conn,
		     unsigned int domid)
{
	struct domain *d = find_domain_struct(domid);
	char *resp;
	int ta;

	if (!d)
		return ENOENT;

	ta = d->conn ? d->conn->transaction_started : 0;
	resp = talloc_asprintf(ctx, "Domain %u:\n", domid);
	if (!resp)
		return ENOMEM;

#define ent(t, e) \
	resp = talloc_asprintf_append(resp, "%-16s: %8d\n", #t, e); \
	if (!resp) return ENOMEM

	ent(nodes, d->acc[ACC_NODES]);
	ent(watches, d->nbwatch);
	ent(transactions, ta);
	ent(outstanding, d->nboutstanding);
	ent(memory, d->memory);

#undef ent

	send_reply(conn, XS_CONTROL, resp, strlen(resp) + 1);

	return 0;
}

static struct domain *alloc_domain(const void *context, unsigned int domid)
{
	struct domain *domain;

	domain = talloc_zero(context, struct domain);
	if (!domain) {
		errno = ENOMEM;
		return NULL;
	}

	domain->domid = domid;
	domain->generation = generation;
	domain->introduced = false;

	if (!hashtable_insert(domhash, &domain->domid, domain)) {
		talloc_free(domain);
		errno = ENOMEM;
		return NULL;
	}

	talloc_set_destructor(domain, destroy_domain);

	return domain;
}

static struct domain *find_or_alloc_domain(const void *ctx, unsigned int domid)
{
	struct domain *domain;

	domain = find_domain_struct(domid);
	return domain ? : alloc_domain(ctx, domid);
}

static struct domain *find_or_alloc_existing_domain(unsigned int domid)
{
	struct domain *domain;
	xc_domaininfo_t dominfo;

	domain = find_domain_struct(domid);
	if (!domain && get_domain_info(domid, &dominfo))
		domain = alloc_domain(NULL, domid);

	return domain;
}

static int new_domain(struct domain *domain, int port, bool restore)
{
	int rc;

	domain->port = 0;
	domain->shutdown = false;
	domain->path = talloc_domain_path(domain, domain->domid);
	if (!domain->path) {
		errno = ENOMEM;
		return errno;
	}

	wrl_domain_new(domain);

	if (restore)
		domain->port = port;
	else {
		/* Tell kernel we're interested in this event. */
		rc = xenevtchn_bind_interdomain(xce_handle, domain->domid,
						port);
		if (rc == -1)
			return errno;
		domain->port = rc;
	}

	domain->introduced = true;

	domain->conn = new_connection(&domain_funcs);
	if (!domain->conn)  {
		errno = ENOMEM;
		return errno;
	}

	domain->conn->domain = domain;
	domain->conn->id = domain->domid;

	return 0;
}


static struct domain *find_domain_by_domid(unsigned int domid)
{
	struct domain *d;

	d = find_domain_struct(domid);

	return (d && d->introduced) ? d : NULL;
}

int acc_fix_domains(struct list_head *head, bool chk_quota, bool update)
{
	struct changed_domain *cd;
	int cnt;

	list_for_each_entry(cd, head, list) {
		cnt = domain_nbentry_fix(cd->domid, cd->acc[ACC_NODES], update);
		if (!update) {
			if (chk_quota && cnt >= quota_nb_entry_per_domain)
				return ENOSPC;
			if (cnt < 0)
				return ENOMEM;
		}
	}

	return 0;
}

static struct changed_domain *acc_find_changed_domain(struct list_head *head,
						      unsigned int domid)
{
	struct changed_domain *cd;

	list_for_each_entry(cd, head, list) {
		if (cd->domid == domid)
			return cd;
	}

	return NULL;
}

static struct changed_domain *acc_get_changed_domain(const void *ctx,
						     struct list_head *head,
						     unsigned int domid)
{
	struct changed_domain *cd;

	cd = acc_find_changed_domain(head, domid);
	if (cd)
		return cd;

	cd = talloc_zero(ctx, struct changed_domain);
	if (!cd)
		return NULL;

	cd->domid = domid;
	list_add_tail(&cd->list, head);

	return cd;
}

static int acc_add_changed_dom(const void *ctx, struct list_head *head,
			       enum accitem what, int val, unsigned int domid)
{
	struct changed_domain *cd;

	assert(what < ARRAY_SIZE(cd->acc));

	cd = acc_get_changed_domain(ctx, head, domid);
	if (!cd)
		return 0;

	errno = 0;
	cd->acc[what] += val;

	return cd->acc[what];
}

static void domain_conn_reset(struct domain *domain)
{
	struct connection *conn = domain->conn;

	conn_delete_all_watches(conn);
	conn_delete_all_transactions(conn);
	conn_free_buffered_data(conn);

	talloc_free(conn->in);

	domain->interface->req_cons = domain->interface->req_prod = 0;
	domain->interface->rsp_cons = domain->interface->rsp_prod = 0;
}

/*
 * Keep the connection alive but stop processing any new request or sending
 * reponse. This is to allow sending @releaseDomain watch event at the correct
 * moment and/or to allow the connection to restart (not yet implemented).
 *
 * All watches, transactions, buffers will be freed.
 */
void ignore_connection(struct connection *conn, unsigned int err)
{
	trace("CONN %p ignored, reason %u\n", conn, err);

	if (conn->domain && conn->domain->interface)
		conn->domain->interface->error = err;

	conn->is_ignored = true;
	conn_delete_all_watches(conn);
	conn_delete_all_transactions(conn);
	conn_free_buffered_data(conn);

	talloc_free(conn->in);
	conn->in = NULL;
	/* if this is a socket connection, drop it now */
	if (conn->fd >= 0)
		talloc_free(conn);
}

static struct domain *introduce_domain(const void *ctx,
				       unsigned int domid,
				       evtchn_port_t port, bool restore)
{
	struct domain *domain;
	int rc;
	struct xenstore_domain_interface *interface;
	bool is_master_domain = (domid == xenbus_master_domid());

	domain = find_or_alloc_domain(ctx, domid);
	if (!domain)
		return NULL;

	if (!domain->introduced) {
		interface = is_master_domain ? xenbus_map()
					     : map_interface(domid);
		if (!interface && !restore)
			return NULL;
		if (new_domain(domain, port, restore)) {
			rc = errno;
			if (interface) {
				if (is_master_domain)
					unmap_xenbus(interface);
				else
					unmap_interface(interface);
			}
			errno = rc;
			return NULL;
		}
		domain->interface = interface;

		if (is_master_domain)
			setup_structure(restore);

		/* Now domain belongs to its connection. */
		talloc_steal(domain->conn, domain);

		if (!restore) {
			/* Notify the domain that xenstore is available */
			interface->connection = XENSTORE_CONNECTED;
			xenevtchn_notify(xce_handle, domain->port);
		}

		if (!is_master_domain && !restore)
			fire_special_watches("@introduceDomain");
	} else {
		/* Use XS_INTRODUCE for recreating the xenbus event-channel. */
		if (domain->port)
			xenevtchn_unbind(xce_handle, domain->port);
		rc = xenevtchn_bind_interdomain(xce_handle, domid, port);
		domain->port = (rc == -1) ? 0 : rc;
	}

	return domain;
}

/* domid, gfn, evtchn, path */
int do_introduce(const void *ctx, struct connection *conn,
		 struct buffered_data *in)
{
	struct domain *domain;
	char *vec[3];
	unsigned int domid;
	evtchn_port_t port;

	if (get_strings(in, vec, ARRAY_SIZE(vec)) < ARRAY_SIZE(vec))
		return EINVAL;

	domid = atoi(vec[0]);
	/* Ignore the gfn, we don't need it. */
	port = atoi(vec[2]);

	/* Sanity check args. */
	if (port <= 0)
		return EINVAL;

	domain = introduce_domain(ctx, domid, port, false);
	if (!domain)
		return errno;

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

int do_set_target(const void *ctx, struct connection *conn,
		  struct buffered_data *in)
{
	char *vec[2];
	unsigned int domid, tdomid;
        struct domain *domain, *tdomain;
	if (get_strings(in, vec, ARRAY_SIZE(vec)) < ARRAY_SIZE(vec))
		return EINVAL;

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
	if (domid == dom0_domid)
		return ERR_PTR(-EINVAL);

	return find_connected_domain(domid);
}

/* domid */
int do_release(const void *ctx, struct connection *conn,
	       struct buffered_data *in)
{
	struct domain *domain;

	domain = onearg_domain(conn, in);
	if (IS_ERR(domain))
		return -PTR_ERR(domain);

	/* Avoid triggering watch events when the domain's nodes are deleted. */
	conn_delete_all_watches(domain->conn);

	talloc_free(domain->conn);

	send_ack(conn, XS_RELEASE);

	return 0;
}

int do_resume(const void *ctx, struct connection *conn,
	      struct buffered_data *in)
{
	struct domain *domain;

	domain = onearg_domain(conn, in);
	if (IS_ERR(domain))
		return -PTR_ERR(domain);

	domain->shutdown = false;

	send_ack(conn, XS_RESUME);

	return 0;
}

int do_get_domain_path(const void *ctx, struct connection *conn,
		       struct buffered_data *in)
{
	char *path;
	const char *domid_str = onearg(in);

	if (!domid_str)
		return EINVAL;

	path = talloc_domain_path(ctx, atoi(domid_str));
	if (!path)
		return errno;

	send_reply(conn, XS_GET_DOMAIN_PATH, path, strlen(path) + 1);

	return 0;
}

int do_is_domain_introduced(const void *ctx, struct connection *conn,
			    struct buffered_data *in)
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
int do_reset_watches(const void *ctx, struct connection *conn,
		     struct buffered_data *in)
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

void dom0_init(void)
{
	evtchn_port_t port;
	struct domain *dom0;

	port = xenbus_evtchn();
	if (port == -1)
		barf_perror("Failed to initialize dom0 port");

	dom0 = introduce_domain(NULL, xenbus_master_domid(), port, false);
	if (!dom0)
		barf_perror("Failed to initialize dom0");

	xenevtchn_notify(xce_handle, dom0->port);
}

static unsigned int domhash_fn(const void *k)
{
	return *(const unsigned int *)k;
}

static int domeq_fn(const void *key1, const void *key2)
{
	return *(const unsigned int *)key1 == *(const unsigned int *)key2;
}

void domain_init(int evtfd)
{
	int rc;

	/* Start with a random rather low domain count for the hashtable. */
	domhash = create_hashtable(NULL, 8, domhash_fn, domeq_fn, 0);
	if (!domhash)
		barf_perror("Failed to allocate domain hashtable");

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

	/*
	 * Allow max number of domains for mappings. We allow one grant per
	 * domain so the theoretical maximum is DOMID_FIRST_RESERVED.
	 */
	xengnttab_set_max_grants(*xgt_handle, DOMID_FIRST_RESERVED);

	talloc_set_destructor(xgt_handle, close_xgt_handle);

	if (evtfd < 0)
		xce_handle = xenevtchn_open(NULL, XENEVTCHN_NO_CLOEXEC);
	else
		xce_handle = xenevtchn_fdopen(NULL, evtfd, 0);

	if (xce_handle == NULL)
		barf_perror("Failed to open evtchn device");

	if ((rc = xenevtchn_bind_virq(xce_handle, VIRQ_DOM_EXC)) == -1)
		barf_perror("Failed to bind to domain exception virq port");
	virq_port = rc;
}

void domain_deinit(void)
{
	if (virq_port)
		xenevtchn_unbind(xce_handle, virq_port);
}

/*
 * Check whether a domain was created before or after a specific generation
 * count (used for testing whether a node permission is older than a domain).
 *
 * Return values:
 *  false: domain has higher generation count (it is younger than a node with
 *     the given count), or domain isn't existing any longer
 *  true: domain is older than the node
 */
static bool chk_domain_generation(unsigned int domid, uint64_t gen)
{
	struct domain *d;

	if (!xc_handle && domid == dom0_domid)
		return true;

	d = find_domain_struct(domid);

	return d && d->generation <= gen;
}

/*
 * Allocate all missing struct domain referenced by a permission set.
 * Any permission entries for not existing domains will be marked to be
 * ignored.
 */
int domain_alloc_permrefs(struct node_perms *perms)
{
	unsigned int i, domid;
	struct domain *d;
	xc_domaininfo_t dominfo;

	for (i = 0; i < perms->num; i++) {
		domid = perms->p[i].id;
		d = find_domain_struct(domid);
		if (!d) {
			if (!get_domain_info(domid, &dominfo))
				perms->p[i].perms |= XS_PERM_IGNORE;
			else if (!alloc_domain(NULL, domid))
				return ENOMEM;
		}
	}

	return 0;
}

/*
 * Remove permissions for no longer existing domains in order to avoid a new
 * domain with the same domid inheriting the permissions.
 */
int domain_adjust_node_perms(struct node *node)
{
	unsigned int i;

	for (i = 1; i < node->perms.num; i++) {
		if (node->perms.p[i].perms & XS_PERM_IGNORE)
			continue;
		if (!chk_domain_generation(node->perms.p[i].id,
					   node->generation))
			node->perms.p[i].perms |= XS_PERM_IGNORE;
	}

	return 0;
}

static int domain_acc_add_valid(struct domain *d, enum accitem what, int add)
{
	assert(what < ARRAY_SIZE(d->acc));

	if ((add < 0 && -add > d->acc[what]) ||
	    (add > 0 && (INT_MAX - d->acc[what]) < add)) {
		/*
		 * In a transaction when a node is being added/removed AND the
		 * same node has been added/removed outside the transaction in
		 * parallel, the resulting value will be wrong. This is no
		 * problem, as the transaction will fail due to the resulting
		 * conflict.
		 */
		return (add < 0) ? 0 : INT_MAX;
	}

	return d->acc[what] + add;
}

static int domain_acc_add(struct connection *conn, unsigned int domid,
			  enum accitem what, int add, bool no_dom_alloc)
{
	struct domain *d;
	struct changed_domain *cd;
	struct list_head *head;
	int ret;

	if (conn && domid == conn->id && conn->domain)
		d = conn->domain;
	else if (no_dom_alloc) {
		d = find_domain_struct(domid);
		if (!d) {
			errno = ENOENT;
			corrupt(conn, "Missing domain %u\n", domid);
			return -1;
		}
	} else {
		d = find_or_alloc_existing_domain(domid);
		if (!d) {
			errno = ENOMEM;
			return -1;
		}
	}

	/* Temporary accounting data until final commit? */
	if (conn && conn->in && what < ACC_REQ_N) {
		/* Consider transaction local data. */
		ret = 0;
		if (conn->transaction && what < ACC_TR_N) {
			head = transaction_get_changed_domains(
				conn->transaction);
			cd = acc_find_changed_domain(head, domid);
			if (cd)
				ret = cd->acc[what];
		}
		ret += acc_add_changed_dom(conn->in, &conn->acc_list, what,
					   add, domid);
		return errno ? -1 : domain_acc_add_valid(d, what, ret);
	}

	if (conn && conn->transaction && what < ACC_TR_N) {
		head = transaction_get_changed_domains(conn->transaction);
		ret = acc_add_changed_dom(conn->transaction, head, what,
					  add, domid);
		if (errno) {
			fail_transaction(conn->transaction);
			return -1;
		}
		return domain_acc_add_valid(d, what, ret);
	}

	d->acc[what] = domain_acc_add_valid(d, what, add);

	return d->acc[what];
}

void acc_drop(struct connection *conn)
{
	struct changed_domain *cd;

	while ((cd = list_top(&conn->acc_list, struct changed_domain, list))) {
		list_del(&cd->list);
		talloc_free(cd);
	}
}

void acc_commit(struct connection *conn)
{
	struct changed_domain *cd;
	enum accitem what;
	struct buffered_data *in = conn->in;

	/*
	 * Make sure domain_acc_add() below can't add additional data to
	 * to be committed accounting records.
	 */
	conn->in = NULL;

	while ((cd = list_top(&conn->acc_list, struct changed_domain, list))) {
		list_del(&cd->list);
		for (what = 0; what < ACC_REQ_N; what++)
			if (cd->acc[what])
				domain_acc_add(conn, cd->domid, what,
					       cd->acc[what], true);

		talloc_free(cd);
	}

	conn->in = in;
}

int domain_nbentry_inc(struct connection *conn, unsigned int domid)
{
	return (domain_acc_add(conn, domid, ACC_NODES, 1, false) < 0)
	       ? errno : 0;
}

int domain_nbentry_dec(struct connection *conn, unsigned int domid)
{
	return (domain_acc_add(conn, domid, ACC_NODES, -1, true) < 0)
	       ? errno : 0;
}

int domain_nbentry_fix(unsigned int domid, int num, bool update)
{
	int ret;

	ret = domain_acc_add(NULL, domid, ACC_NODES, update ? num : 0, update);
	if (ret < 0 || update)
		return ret;

	return domid_is_unprivileged(domid) ? ret + num : 0;
}

unsigned int domain_nbentry(struct connection *conn)
{
	return domain_is_unprivileged(conn)
	       ? domain_acc_add(conn, conn->id, ACC_NODES, 0, true) : 0;
}

static bool domain_chk_quota(struct domain *domain, int mem)
{
	time_t now;

	if (!domain || !domid_is_unprivileged(domain->domid) ||
	    (domain->conn && domain->conn->is_ignored))
		return false;

	now = time(NULL);

	if (mem >= quota_memory_per_domain_hard &&
	    quota_memory_per_domain_hard) {
		if (domain->hard_quota_reported)
			return true;
		syslog(LOG_ERR, "Domain %u exceeds hard memory quota, Xenstore interface to domain stalled\n",
		       domain->domid);
		domain->mem_last_msg = now;
		domain->hard_quota_reported = true;
		return true;
	}

	if (now - domain->mem_last_msg >= MEM_WARN_MINTIME_SEC) {
		if (domain->hard_quota_reported) {
			domain->mem_last_msg = now;
			domain->hard_quota_reported = false;
			syslog(LOG_INFO, "Domain %u below hard memory quota again\n",
			       domain->domid);
		}
		if (mem >= quota_memory_per_domain_soft &&
		    quota_memory_per_domain_soft &&
		    !domain->soft_quota_reported) {
			domain->mem_last_msg = now;
			domain->soft_quota_reported = true;
			syslog(LOG_WARNING, "Domain %u exceeds soft memory quota\n",
			       domain->domid);
		}
		if (mem < quota_memory_per_domain_soft &&
		    domain->soft_quota_reported) {
			domain->mem_last_msg = now;
			domain->soft_quota_reported = false;
			syslog(LOG_INFO, "Domain %u below soft memory quota again\n",
			       domain->domid);
		}

	}

	return false;
}

int domain_memory_add(struct connection *conn, unsigned int domid, int mem,
		      bool no_quota_check)
{
	struct domain *domain;

	domain = find_domain_struct(domid);
	if (domain) {
		/*
		 * domain_chk_quota() will print warning and also store whether
		 * the soft/hard quota has been hit. So check no_quota_check
		 * *after*.
		 */
		if (domain_chk_quota(domain, domain->memory + mem) &&
		    !no_quota_check)
			return ENOMEM;
		domain->memory += mem;
	} else {
		/*
		 * The domain the memory is to be accounted for should always
		 * exist, as accounting is done either for a domain related to
		 * the current connection, or for the domain owning a node
		 * (which is always existing, as the owner of the node is
		 * tested to exist and deleted or replaced by domid 0 if not).
		 * So not finding the related domain MUST be an error in the
		 * data base.
		 */
		errno = ENOENT;
		corrupt(NULL, "Accounting called for non-existing domain %u\n",
			domid);
		return ENOENT;
	}

	return 0;
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

void domain_outstanding_inc(struct connection *conn)
{
	if (!conn || !conn->domain)
		return;
	conn->domain->nboutstanding++;
}

void domain_outstanding_dec(struct connection *conn)
{
	if (!conn || !conn->domain)
		return;
	conn->domain->nboutstanding--;
}

void domain_outstanding_domid_dec(unsigned int domid)
{
	struct domain *d = find_domain_by_domid(domid);

	if (d)
		d->nboutstanding--;
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

#define trace_wrl(...)				\
do {						\
	if (trace_flags & TRACE_WRL)		\
		trace("wrl: " __VA_ARGS__);	\
} while (0)

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

	trace_wrl("dom %4d %6ld msec %9ld credit %9ld reserve %9ld discard\n",
		  domain->domid, msec, (long)domain->wrl_credit,
		  (long)wrl_reserve, (long)surplus);
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

	trace_wrl("domain %u credit=%ld (reserve=%ld) SLEEPING for %d\n",
		  domain->domid, (long)domain->wrl_credit, (long)wrl_reserve,
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
	trace_wrl("domain %u credit=%ld (reserve=%ld)\n", domain->domid,
		  (long)domain->wrl_credit, (long)wrl_reserve);

	if (domain->wrl_credit < 0) {
		if (!domain->wrl_delay_logged) {
			domain->wrl_delay_logged = true;
			WRL_LOG(now, "domain %ld is affected\n",
				(long)domain->domid);
		} else if (!wrl_log_last_warning) {
			WRL_LOG(now, "rate limiting restarts\n");
		}
		wrl_log_last_warning = now.sec;
	}
}

void wrl_log_periodic(struct wrl_timestampt now)
{
	if (wrl_log_last_warning &&
	    (now.sec - wrl_log_last_warning) > WRL_LOGEVERY) {
		WRL_LOG(now, "not in force recently\n");
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

const char *dump_state_connections(FILE *fp)
{
	const char *ret = NULL;
	unsigned int conn_id = 1;
	struct xs_state_connection sc;
	struct xs_state_record_header head;
	struct connection *c;

	list_for_each_entry(c, &connections, list) {
		head.type = XS_STATE_TYPE_CONN;
		head.length = sizeof(sc);

		sc.conn_id = conn_id++;
		sc.pad = 0;
		memset(&sc.spec, 0, sizeof(sc.spec));
		if (c->domain) {
			sc.conn_type = XS_STATE_CONN_TYPE_RING;
			sc.spec.ring.domid = c->id;
			sc.spec.ring.tdomid = c->target ? c->target->id
						: DOMID_INVALID;
			sc.spec.ring.evtchn = c->domain->port;
		} else {
			sc.conn_type = XS_STATE_CONN_TYPE_SOCKET;
			sc.spec.socket_fd = c->fd;
		}

		ret = dump_state_buffered_data(NULL, c, &sc);
		if (ret)
			return ret;
		head.length += sc.data_in_len + sc.data_out_len;
		head.length = ROUNDUP(head.length, 3);
		if (fwrite(&head, sizeof(head), 1, fp) != 1)
			return "Dump connection state error";
		if (fwrite(&sc, offsetof(struct xs_state_connection, data),
			   1, fp) != 1)
			return "Dump connection state error";
		ret = dump_state_buffered_data(fp, c, NULL);
		if (ret)
			return ret;
		ret = dump_state_align(fp);
		if (ret)
			return ret;

		ret = dump_state_watches(fp, c, sc.conn_id);
		if (ret)
			return ret;
	}

	return ret;
}

void read_state_connection(const void *ctx, const void *state)
{
	const struct xs_state_connection *sc = state;
	struct connection *conn;
	struct domain *domain, *tdomain;

	if (sc->conn_type == XS_STATE_CONN_TYPE_SOCKET) {
#ifdef NO_SOCKETS
		barf("socket based connection without sockets");
#else
		conn = new_connection(&socket_funcs);
		if (!conn)
			barf("error restoring connection");
		conn->fd = sc->spec.socket_fd;
#endif
	} else {
		domain = introduce_domain(ctx, sc->spec.ring.domid,
					  sc->spec.ring.evtchn, true);
		if (!domain)
			barf("domain allocation error");

		conn = domain->conn;

		/*
		 * We may not have been able to restore the domain (for
		 * instance because it revoked the Xenstore grant). We need
		 * to keep it around to send @releaseDomain when it is
		 * dead. So mark it as ignored.
		 */
		if (!domain->port || !domain->interface)
			ignore_connection(conn, XENSTORE_ERROR_COMM);

		if (sc->spec.ring.tdomid != DOMID_INVALID) {
			tdomain = find_or_alloc_domain(ctx,
						       sc->spec.ring.tdomid);
			if (!tdomain)
				barf("target domain allocation error");
			talloc_reference(domain->conn, tdomain->conn);
			domain->conn->target = tdomain->conn;
		}
	}

	conn->conn_id = sc->conn_id;

	read_state_buffered_data(ctx, conn, sc);
}

struct domain_acc {
	unsigned int domid;
	int nodes;
};

static int domain_check_acc_init_sub(const void *k, void *v, void *arg)
{
	struct hashtable *domains = arg;
	struct domain *d = v;
	struct domain_acc *dom;

	dom = talloc_zero(NULL, struct domain_acc);
	if (!dom)
		return -1;

	dom->domid = d->domid;
	/*
	 * Set the initial value to the negative one of the current domain.
	 * If everything is correct incrementing the value for each node will
	 * result in dom->nodes being 0 at the end.
	 */
	dom->nodes = -d->acc[ACC_NODES];

	if (!hashtable_insert(domains, &dom->domid, dom)) {
		talloc_free(dom);
		return -1;
	}

	return 0;
}

struct hashtable *domain_check_acc_init(void)
{
	struct hashtable *domains;

	domains = create_hashtable(NULL, 8, domhash_fn, domeq_fn,
				   HASHTABLE_FREE_VALUE);
	if (!domains)
		return NULL;

	if (hashtable_iterate(domhash, domain_check_acc_init_sub, domains)) {
		hashtable_destroy(domains);
		return NULL;
	}

	return domains;
}

void domain_check_acc_add(const struct node *node, struct hashtable *domains)
{
	struct domain_acc *dom;
	unsigned int domid;

	domid = get_node_owner(node);
	dom = hashtable_search(domains, &domid);
	if (!dom)
		log("Node %s owned by unknown domain %u", node->name, domid);
	else
		dom->nodes++;
}

static int domain_check_acc_cb(const void *k, void *v, void *arg)
{
	struct domain_acc *dom = v;
	struct domain *d;

	if (!dom->nodes)
		return 0;

	log("Correct accounting data for domain %u: nodes are %d off",
	    dom->domid, dom->nodes);

	d = find_domain_struct(dom->domid);
	if (!d)
		return 0;

	d->acc[ACC_NODES] += dom->nodes;

	return 0;
}

void domain_check_acc(struct hashtable *domains)
{
	hashtable_iterate(domains, domain_check_acc_cb, NULL);
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
