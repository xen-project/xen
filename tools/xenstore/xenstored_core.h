/* 
    Internal interfaces for Xen Store Daemon.
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

#ifndef _XENSTORED_CORE_H
#define _XENSTORED_CORE_H

#define XC_WANT_COMPAT_MAP_FOREIGN_API
#include <xenctrl.h>
#include <xengnttab.h>

#include <sys/types.h>
#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#include "xenstore_lib.h"
#include "list.h"
#include "tdb.h"
#include "hashtable.h"
#include "utils.h"

/* DEFAULT_BUFFER_SIZE should be large enough for each errno string. */
#define DEFAULT_BUFFER_SIZE 16

typedef int32_t wrl_creditt;
#define WRL_CREDIT_MAX (1000*1000*1000)
/* ^ satisfies non-overflow condition for wrl_xfer_credit */

struct buffered_data
{
	struct list_head list;
	bool on_out_list;
	bool on_ref_list;

	/* Are we still doing the header? */
	bool inhdr;

	/* Is this a watch event? */
	bool watch_event;

	/* How far are we? */
	unsigned int used;

	/* Outstanding request accounting. */
	union {
		/* ref is being used for requests. */
		struct {
			unsigned int event_cnt; /* # of outstanding events. */
			unsigned int domid;     /* domid of request. */
		} ref;
		/* req is being used for watch events. */
		struct buffered_data *req;      /* request causing event. */
	} pend;

	union {
		struct xsd_sockmsg msg;
		char raw[sizeof(struct xsd_sockmsg)];
	} hdr;

	uint64_t timeout_msec;

	/* The actual data. */
	char *buffer;
	char default_buffer[DEFAULT_BUFFER_SIZE];
};

struct connection;
typedef int connwritefn_t(struct connection *, const void *, unsigned int);
typedef int connreadfn_t(struct connection *, void *, unsigned int);

struct connection
{
	struct list_head list;

	/* The file descriptor we came in on. */
	int fd;
	/* The index of pollfd in global pollfd array */
	int pollfd_idx;

	/* Who am I? Domid of connection. */
	unsigned int id;

	/* Is this a read-only connection? */
	bool can_write;

	/* Is this connection ignored? */
	bool is_ignored;

	/* Buffered incoming data. */
	struct buffered_data *in;

	/* Buffered output data */
	struct list_head out_list;
	uint64_t timeout_msec;

	/* Referenced requests no longer pending. */
	struct list_head ref_list;

	/* Transaction context for current request (NULL if none). */
	struct transaction *transaction;

	/* List of in-progress transactions. */
	struct list_head transaction_list;
	uint32_t next_transaction_id;
	unsigned int transaction_started;

	/* The domain I'm associated with, if any. */
	struct domain *domain;

        /* The target of the domain I'm associated with. */
        struct connection *target;

	/* My watches. */
	struct list_head watches;

	/* Methods for communicating over this connection: write can be NULL */
	connwritefn_t *write;
	connreadfn_t *read;
};
extern struct list_head connections;

struct node_perms {
	unsigned int num;
	struct xs_permissions *p;
};

struct node_account_data {
	unsigned int domid;
	int memory;		/* -1 if unknown */
};

struct node {
	const char *name;
	/* Key used to update TDB */
	TDB_DATA key;

	/* Parent (optional) */
	struct node *parent;

	/* Generation count. */
	uint64_t generation;
#define NO_GENERATION ~((uint64_t)0)

	/* Permissions. */
	struct node_perms perms;

	/* Contents. */
	unsigned int datalen;
	void *data;

	/* Children, each nul-terminated. */
	unsigned int childlen;
	unsigned int childoff;	/* Used by walk_node_tree() internally. */
	char *children;

	/* Allocation information for node currently in store. */
	struct node_account_data acc;
};

/* Return the only argument in the input. */
const char *onearg(struct buffered_data *in);

/* Break input into vectors, return the number, fill in up to num of them. */
unsigned int get_strings(struct buffered_data *data,
			 char *vec[], unsigned int num);

void send_reply(struct connection *conn, enum xsd_sockmsg_type type,
		const void *data, unsigned int len);
void send_event(struct buffered_data *req, struct connection *conn,
		const char *path, const char *token);

/* Some routines (write, mkdir, etc) just need a non-error return */
void send_ack(struct connection *conn, enum xsd_sockmsg_type type);

/* Canonicalize this path if possible. */
char *canonicalize(struct connection *conn, const void *ctx, const char *node);

/* Get access permissions. */
enum xs_perm_type perm_for_conn(struct connection *conn,
				const struct node_perms *perms);

/* Write a node to the tdb data base. */
int write_node_raw(struct connection *conn, TDB_DATA *key, struct node *node,
		   bool no_quota_check);

/* Get a node from the tdb data base. */
struct node *read_node(struct connection *conn, const void *ctx,
		       const char *name);

/* Remove a node and its children. */
int rm_node(struct connection *conn, const void *ctx, const char *name);

void setup_structure(void);
struct connection *new_connection(connwritefn_t *write, connreadfn_t *read);
void check_store(void);
void corrupt(struct connection *conn, const char *fmt, ...);
enum xs_perm_type perm_for_conn(struct connection *conn,
				const struct node_perms *perms);

/* Is this a valid node name? */
bool is_valid_nodename(const char *node);

/* Get name of parent node. */
char *get_parent(const void *ctx, const char *node);

/* Tracing infrastructure. */
void trace_create(const void *data, const char *type);
void trace_destroy(const void *data, const char *type);
void trace(const char *fmt, ...);
void dtrace_io(const struct connection *conn, const struct buffered_data *data, int out);
void reopen_log(void);
void close_log(void);

extern char *tracefile;
extern int tracefd;

extern TDB_CONTEXT *tdb_ctx;
extern int dom0_domid;
extern int dom0_event;
extern int priv_domid;
extern int quota_nb_watch_per_domain;
extern int quota_max_transaction;
extern int quota_max_entry_size;
extern int quota_nb_perms_per_node;
extern int quota_max_path_len;
extern int quota_nb_entry_per_domain;
extern int quota_req_outstanding;
extern int quota_trans_nodes;
extern int quota_memory_per_domain_soft;
extern int quota_memory_per_domain_hard;
extern bool keep_orphans;

extern unsigned int timeout_watch_event_msec;

/* Map the kernel's xenstore page. */
void *xenbus_map(void);
void unmap_xenbus(void *interface);

static inline int xenbus_master_domid(void) { return dom0_domid; }

/* Return the event channel used by xenbus. */
evtchn_port_t xenbus_evtchn(void);

/* Tell the kernel xenstored is running. */
void xenbus_notify_running(void);

/* Write out the pidfile */
void write_pidfile(const char *pidfile);

/* Fork but do not close terminal FDs */
void daemonize(void);
/* Close stdin/stdout/stderr to complete daemonize */
void finish_daemonize(void);

/* Open a pipe for signal handling */
void init_pipe(int reopen_log_pipe[2]);

extern xengnttab_handle **xgt_handle;

int remember_string(struct hashtable *hash, const char *str);

int do_tdb_write(struct connection *conn, TDB_DATA *key, TDB_DATA *data,
		 struct node_account_data *acc, bool no_quota_check);
int do_tdb_delete(struct connection *conn, TDB_DATA *key,
		  struct node_account_data *acc);

void conn_free_buffered_data(struct connection *conn);

/*
 * Walk the node tree below root calling funcs->enter() and funcs->exit() for
 * each node. funcs->enter() is being called when entering a node, so before
 * any of the children of the node is processed. funcs->exit() is being
 * called when leaving the node, so after all children have been processed.
 * funcs->enoent() is being called when a node isn't existing.
 * funcs->*() return values:
 *  < 0: tree walk is stopped, walk_node_tree() returns funcs->*() return value
 *       in case WALK_TREE_ERROR_STOP is returned, errno should be set
 *  WALK_TREE_OK: tree walk is continuing
 *  WALK_TREE_SKIP_CHILDREN: tree walk won't descend below current node, but
 *       walk continues
 *  WALK_TREE_RM_CHILDENTRY: Remove the child entry from its parent and write
 *       the modified parent node back to the data base, implies to not descend
 *       below the current node, but to continue the walk
 * funcs->*() is allowed to modify the node it is called for in the data base.
 * In case funcs->enter() is deleting the node, it must not return WALK_TREE_OK
 * in order to avoid descending into no longer existing children.
 */
/* Return values for funcs->*() and walk_node_tree(). */
#define WALK_TREE_SUCCESS_STOP  -100    /* Stop walk early, no error. */
#define WALK_TREE_ERROR_STOP    -1      /* Stop walk due to error. */
#define WALK_TREE_OK            0       /* No error. */
/* Return value for funcs->*() only. */
#define WALK_TREE_SKIP_CHILDREN 1       /* Don't recurse below current node. */
#define WALK_TREE_RM_CHILDENTRY 2       /* Remove child entry from parent. */

struct walk_funcs {
	int (*enter)(const void *ctx, struct connection *conn,
		     struct node *node, void *arg);
	int (*exit)(const void *ctx, struct connection *conn,
		    struct node *node, void *arg);
	int (*enoent)(const void *ctx, struct connection *conn,
		      struct node *parent, char *name, void *arg);
};

int walk_node_tree(const void *ctx, struct connection *conn, const char *root,
		   struct walk_funcs *funcs, void *arg);

#endif /* _XENSTORED_CORE_H */

/*
 * Local variables:
 *  mode: C
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
