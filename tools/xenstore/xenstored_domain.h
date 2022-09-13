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

void handle_event(void);

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

void domain_init(void);

/* Returns the implicit path of a connection (only domains have this) */
const char *get_implicit_path(const struct connection *conn);

/* Read existing connection information from store. */
void restore_existing_connections(void);

/* Can connection attached to domain read/write. */
bool domain_can_read(struct connection *conn);
bool domain_can_write(struct connection *conn);

bool domain_is_unprivileged(struct connection *conn);

/* Remove node permissions for no longer existing domains. */
int domain_adjust_node_perms(struct node *node);
int domain_alloc_permrefs(struct node_perms *perms);

/* Quota manipulation */
int domain_entry_inc(struct connection *conn, struct node *);
void domain_entry_dec(struct connection *conn, struct node *);
int domain_entry_fix(unsigned int domid, int num, bool update);
int domain_entry(struct connection *conn);
int domain_memory_add(unsigned int domid, int mem, bool no_quota_check);

/*
 * domain_memory_add_chk(): to be used when memory quota should be checked.
 * Not to be used when specifying a negative mem value, as lowering the used
 * memory should always be allowed.
 */
static inline int domain_memory_add_chk(unsigned int domid, int mem)
{
	return domain_memory_add(domid, mem, false);
}
/*
 * domain_memory_add_nochk(): to be used when memory quota should not be
 * checked, e.g. when lowering memory usage, or in an error case for undoing
 * a previous memory adjustment.
 */
static inline void domain_memory_add_nochk(unsigned int domid, int mem)
{
	domain_memory_add(domid, mem, true);
}
void domain_watch_inc(struct connection *conn);
void domain_watch_dec(struct connection *conn);
int domain_watch(struct connection *conn);
void domain_outstanding_inc(struct connection *conn);
void domain_outstanding_dec(struct connection *conn);
void domain_outstanding_domid_dec(unsigned int domid);
int domain_get_quota(const void *ctx, struct connection *conn,
		     unsigned int domid);

/* Special node permission handling. */
int set_perms_special(struct connection *conn, const char *name,
		      struct node_perms *perms);
bool check_perms_special(const char *name, struct connection *conn);

/* Write rate limiting */

#define WRL_FACTOR   1000 /* for fixed-point arithmetic */
#define WRL_RATE      200
#define WRL_DBURST     10
#define WRL_GBURST   1000
#define WRL_NEWDOMS     5
#define WRL_LOGEVERY  120 /* seconds */

struct wrl_timestampt {
	time_t sec;
	int msec;
};

extern long wrl_ntransactions;

void wrl_gettime_now(struct wrl_timestampt *now_ts);
void wrl_domain_new(struct domain *domain);
void wrl_domain_destroy(struct domain *domain);
void wrl_credit_update(struct domain *domain, struct wrl_timestampt now);
void wrl_check_timeout(struct domain *domain,
                       struct wrl_timestampt now,
                       int *ptimeout);
void wrl_log_periodic(struct wrl_timestampt now);
void wrl_apply_debit_direct(struct connection *conn);
void wrl_apply_debit_trans_commit(struct connection *conn);

#endif /* _XENSTORED_DOMAIN_H */
