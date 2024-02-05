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

#ifndef _XENSTORED_DOMAIN_H
#define _XENSTORED_DOMAIN_H

/*
 * All accounting data is stored in a per-domain array.
 * Depending on the account item there might be other scopes as well, like e.g.
 * a per transaction array.
 */
enum accitem {
	ACC_NODES,
	ACC_REQ_N,		/* Number of elements per request. */
	ACC_TR_N = ACC_REQ_N,	/* Number of elements per transaction. */
	ACC_CHD_N = ACC_TR_N,	/* max(ACC_REQ_N, ACC_TR_N), for changed dom. */
	ACC_WATCH = ACC_TR_N,
	ACC_OUTST,
	ACC_MEM,
	ACC_TRANS,
	ACC_TRANSNODES,
	ACC_NPERM,
	ACC_PATHLEN,
	ACC_NODESZ,
	ACC_N,			/* Number of elements per domain. */
};

struct quota {
	const char *name;
	const char *descr;
	unsigned int val;
	unsigned int max;
};

extern struct quota hard_quotas[ACC_N];
extern struct quota soft_quotas[ACC_N];

void handle_event(void);

void check_domains(void);

/* domid, mfn, eventchn, path */
int do_introduce(const void *ctx, struct connection *conn,
		 struct buffered_data *in);

/* domid */
int do_is_domain_introduced(const void *ctx, struct connection *conn,
			    struct buffered_data *in);

/* domid */
int do_release(const void *ctx, struct connection *conn,
	       struct buffered_data *in);

/* domid */
int do_resume(const void *ctx, struct connection *conn,
	      struct buffered_data *in);

/* domid, target */
int do_set_target(const void *ctx, struct connection *conn,
		  struct buffered_data *in);

/* domid */
int do_get_domain_path(const void *ctx, struct connection *conn,
		       struct buffered_data *in);

/* Allow guest to reset all watches */
int do_reset_watches(const void *ctx, struct connection *conn,
		     struct buffered_data *in);

void domain_early_init(void);
void domain_init(int evtfd);
void dom0_init(void);
void stubdom_init(void);
void domain_deinit(void);
void ignore_connection(struct connection *conn, unsigned int err);

/* Returns the implicit path of a connection (only domains have this) */
const char *get_implicit_path(const struct connection *conn);

/*
 * Remove node permissions for no longer existing domains.
 * In case of a change of permissions the related array is reallocated in
 * order to avoid a data base change when operating on a node directly
 * referencing the data base contents.
 */
int domain_adjust_node_perms(struct node *node);

int domain_alloc_permrefs(struct node_perms *perms);

/* Quota manipulation */
int domain_nbentry_inc(struct connection *conn, unsigned int domid);
int domain_nbentry_dec(struct connection *conn, unsigned int domid);
int domain_nbentry_fix(unsigned int domid, int num, bool update);
unsigned int domain_nbentry(struct connection *conn);
int domain_memory_add(struct connection *conn, unsigned int domid, int mem,
		      bool no_quota_check);

/*
 * domain_memory_add_chk(): to be used when memory quota should be checked.
 * Not to be used when specifying a negative mem value, as lowering the used
 * memory should always be allowed.
 */
static inline int domain_memory_add_chk(struct connection *conn,
					unsigned int domid, int mem)
{
	return domain_memory_add(conn, domid, mem, false);
}

/*
 * domain_memory_add_nochk(): to be used when memory quota should not be
 * checked, e.g. when lowering memory usage, or in an error case for undoing
 * a previous memory adjustment.
 */
static inline void domain_memory_add_nochk(struct connection *conn,
					   unsigned int domid, int mem)
{
	domain_memory_add(conn, domid, mem, true);
}
void domain_watch_inc(struct connection *conn);
void domain_watch_dec(struct connection *conn);
int domain_watch(struct connection *conn);
void domain_outstanding_inc(struct connection *conn);
void domain_outstanding_dec(struct connection *conn, unsigned int domid);
void domain_transaction_inc(struct connection *conn);
void domain_transaction_dec(struct connection *conn);
unsigned int domain_transaction_get(struct connection *conn);
int domain_get_quota(const void *ctx, struct connection *conn,
		     unsigned int domid);

/*
 * Update or check number of nodes per domain at the end of a transaction.
 * If "update" is true, "chk_quota" is ignored.
 */
int acc_fix_domains(struct list_head *head, bool chk_quota, bool update);
void acc_drop(struct connection *conn);
void acc_commit(struct connection *conn);
int domain_max_global_acc(const void *ctx, struct connection *conn);
void domain_reset_global_acc(void);
bool domain_max_chk(const struct connection *conn, enum accitem what,
		    unsigned int val);

extern long wrl_ntransactions;

void wrl_check_timeout(struct domain *domain, uint64_t now, int *ptimeout);
void wrl_log_periodic(uint64_t now);
void wrl_apply_debit_direct(struct connection *conn);
void wrl_apply_debit_trans_commit(struct connection *conn);

const char *dump_state_connections(FILE *fp);

void read_state_connection(const void *ctx, const void *state);

struct hashtable *domain_check_acc_init(void);
void domain_check_acc_add(const struct node *node, struct hashtable *domains);
void domain_check_acc(struct hashtable *domains);

#endif /* _XENSTORED_DOMAIN_H */
