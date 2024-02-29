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

#include <xenctrl.h>
#include <xengnttab.h>

#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#include "xenstore_lib.h"
#include "xenstore_state.h"
#include "list.h"
#include "hashtable.h"

#define XENSTORE_LIB_DIR	XEN_LIB_DIR "/xenstore"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
/* O_CLOEXEC support is needed for Live Update in the daemon case. */
#ifndef __MINIOS__
#define NO_LIVE_UPDATE
#endif
#endif

/* DEFAULT_BUFFER_SIZE should be large enough for each errno string. */
#define DEFAULT_BUFFER_SIZE 16

struct xs_state_connection;

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

struct delayed_request {
	/* Next delayed request. */
	struct list_head list;

	/* The delayed request. */
	struct buffered_data *in;

	/* Function to call. */
	bool (*func)(struct delayed_request *req);

	/* Further data. */
	void *data;
};

struct connection;

struct interface_funcs {
	int (*write)(struct connection *, const void *, unsigned int);
	int (*read)(struct connection *, void *, unsigned int);
	bool (*can_write)(struct connection *);
	bool (*can_read)(struct connection *);
};

struct connection
{
	struct list_head list;

	/* The file descriptor we came in on. */
	int fd;
	/* The index of pollfd in global pollfd array */
	int pollfd_idx;

	/* Who am I? Domid of connection. */
	unsigned int id;

	/* Is this connection ignored? */
	bool is_ignored;

	/* Is the connection stalled? */
	bool is_stalled;

	/* Buffered incoming data. */
	struct buffered_data *in;

	/* Buffered output data */
	struct list_head out_list;
	uint64_t timeout_msec;

	/* Not yet committed accounting data (valid if in != NULL). */
	struct list_head acc_list;

	/* Referenced requests no longer pending. */
	struct list_head ref_list;

	/* Transaction context for current request (NULL if none). */
	struct transaction *transaction;

	/* List of in-progress transactions. */
	struct list_head transaction_list;
	uint32_t next_transaction_id;
	time_t ta_start_time;

	/* List of delayed requests. */
	struct list_head delayed;

	/* The domain I'm associated with, if any. */
	struct domain *domain;

        /* The target of the domain I'm associated with. */
        struct connection *target;

	/* My watches. */
	struct list_head watches;

	/* Methods for communicating over this connection. */
	const struct interface_funcs *funcs;

	/* Support for live update: connection id. */
	unsigned int conn_id;
};
extern struct list_head connections;

/*
 * Header of the node record in the data base.
 * In the data base the memory of the node is a single memory chunk with the
 * following format:
 * struct {
 *     node_hdr hdr;
 *     struct xs_permissions perms[hdr.num_perms];
 *     char data[hdr.datalen];
 *     char children[hdr.childlen];
 * };
 */
struct node_hdr {
	uint64_t generation;
#define NO_GENERATION ~((uint64_t)0)
	uint16_t num_perms;
	uint16_t datalen;
	uint32_t childlen;
};

struct node_perms {
	unsigned int num;
	struct xs_permissions *p;
};

struct node_account_data {
	unsigned int domid;
	int memory;		/* -1 if unknown */
};

struct node {
	/* Copied to/from data base. */
	struct node_hdr hdr;

	/* Xenstore path. */
	const char *name;
	/* Name used to access data base. */
	const char *db_name;

	/* Parent (optional) */
	struct node *parent;

	/* Permissions. */
	struct xs_permissions *perms;

	/* Contents. */
	void *data;

	/* Children, each nul-terminated. */
	unsigned int childoff;	/* Used by walk_node_tree() internally. */
	char *children;

	/* Allocation information for node currently in store. */
	struct node_account_data acc;
};

/* Return the only argument in the input. */
const char *onearg(struct buffered_data *in);

/* Break input into vectors, return the number, fill in up to num of them. */
unsigned int get_strings(struct buffered_data *data,
			 const char *vec[], unsigned int num);
unsigned int get_string(const struct buffered_data *data, unsigned int offset);

void send_reply(struct connection *conn, enum xsd_sockmsg_type type,
		const void *data, unsigned int len);
void send_event(struct buffered_data *req, struct connection *conn,
		const char *path, const char *token);

/* Some routines (write, mkdir, etc) just need a non-error return */
void send_ack(struct connection *conn, enum xsd_sockmsg_type type);

/* Canonicalize this path if possible. */
const char *canonicalize(struct connection *conn, const void *ctx,
			 const char *node, bool allow_special);

/* Get access permissions. */
unsigned int perm_for_conn(struct connection *conn,
			   const struct node_perms *perms);

/* Get owner of a node. */
static inline unsigned int get_node_owner(const struct node *node)
{
	return node->perms[0].id;
}

/* Transfer permissions from node to struct node_perms. */
static inline void node_to_node_perms(const struct node *node,
				      struct node_perms *perms)
{
	perms->num = node->hdr.num_perms;
	perms->p = node->perms;
}

static inline unsigned int perm_for_conn_from_node(struct connection *conn,
						   const struct node *node)
{
	struct node_perms perms;

	node_to_node_perms(node, &perms);

	return perm_for_conn(conn, &perms);
}

/* Transfer permissions from struct node_perms to node. */
static inline void node_perms_to_node(const struct node_perms *perms,
				      struct node *node)
{
	node->hdr.num_perms = perms->num;
	node->perms = perms->p;
}

/* Write a node to the data base. */
enum write_node_mode {
	NODE_CREATE,
	NODE_MODIFY
};

int write_node_raw(struct connection *conn, const char *db_name,
		   struct node *node, enum write_node_mode mode,
		   bool no_quota_check);

/* Get a node from the data base. */
struct node *read_node(struct connection *conn, const void *ctx,
		       const char *name);
const struct node *read_node_const(struct connection *conn, const void *ctx,
				   const char *name);

/* Remove a node and its children. */
int rm_node(struct connection *conn, const void *ctx, const char *name);

void setup_structure(bool live_update);
struct connection *new_connection(const struct interface_funcs *funcs);
struct connection *add_socket_connection(int fd);
struct connection *get_connection_by_id(unsigned int conn_id);
void check_store(void);
void corrupt(struct connection *conn, const char *fmt, ...);

/* Get name of parent node. */
char *get_parent(const void *ctx, const char *node);

/* Delay a request. */
int delay_request(struct connection *conn, struct buffered_data *in,
		  bool (*func)(struct delayed_request *), void *data,
		  bool no_quota_check);

/* Tracing infrastructure. */
void trace_create(const void *data, const char *type);
void trace_destroy(const void *data, const char *type);
void trace(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
void reopen_log(void);
void close_log(void);

#define log(...)							\
	do {								\
		int _saved_errno = errno;				\
		char *s = talloc_asprintf(NULL, __VA_ARGS__);		\
		if (s) {						\
			trace("%s\n", s);				\
			syslog(LOG_ERR, "%s\n",	s);			\
			talloc_free(s);					\
		} else {						\
			trace("talloc failure during logging\n");	\
			syslog(LOG_ERR, "talloc failure during logging\n"); \
		}							\
		errno = _saved_errno;					\
	} while (0)

extern int orig_argc;
extern char **orig_argv;

extern const char *tracefile;
extern int tracefd;

/* Trace flag values must be kept in sync with trace_switches[] contents. */
extern unsigned int trace_flags;
#define TRACE_OBJ	0x00000001
#define TRACE_IO	0x00000002
#define TRACE_WRL	0x00000004
#define TRACE_ACC	0x00000008
#define TRACE_TDB	0x00000010
extern const char *const trace_switches[];
int set_trace_switch(const char *arg);

#define trace_tdb(...)				\
do {						\
	if (trace_flags & TRACE_TDB)		\
		trace("tdb: " __VA_ARGS__);	\
} while (0)

extern int dom0_domid;
extern int dom0_event;
extern int priv_domid;
extern domid_t stub_domid;
extern bool keep_orphans;

extern struct pollfd *poll_fds;

extern unsigned int timeout_watch_event_msec;

/* Get internal time in milliseconds. */
uint64_t get_now_msec(void);

/* Map the kernel's xenstore page. */
void *xenbus_map(void);
void unmap_xenbus(void *interface);

static inline int xenbus_master_domid(void) { return dom0_domid; }

static inline bool domid_is_unprivileged(unsigned int domid)
{
	return domid != dom0_domid && domid != priv_domid;
}

static inline bool domain_is_unprivileged(const struct connection *conn)
{
	return conn && domid_is_unprivileged(conn->id);
}

/* Return the event channel used by xenbus. */
evtchn_port_t get_xenbus_evtchn(void);
void early_init(bool live_update, bool dofork, const char *pidfile);
void late_init(bool live_update);

int set_fd(int fd, short events);
void set_special_fds(void);
void handle_special_fds(void);

int get_socket_fd(void);
void set_socket_fd(int fd);

#ifdef __MINIOS__
void mount_9pfs(void);
#endif

const char *xenstore_rundir(void);
const char *absolute_filename(const void *ctx, const char *filename);

/* Close stdin/stdout/stderr to complete daemonize */
void finish_daemonize(void);

extern xengnttab_handle **xgt_handle;

int remember_string(struct hashtable *hash, const char *str);

/* Data base access functions. */
const struct node_hdr *db_fetch(const char *db_name, size_t *size);
int db_write(struct connection *conn, const char *db_name, void *data,
	     size_t size, struct node_account_data *acc,
	     enum write_node_mode mode, bool no_quota_check);
void db_delete(struct connection *conn, const char *name,
	       struct node_account_data *acc);

void conn_free_buffered_data(struct connection *conn);

const char *dump_state_global(FILE *fp);
const char *dump_state_buffered_data(FILE *fp, const struct connection *c,
				     struct xs_state_connection *sc);
const char *dump_state_nodes(FILE *fp, const void *ctx);
const char *dump_state_node_perms(FILE *fp, const struct xs_permissions *perms,
				  unsigned int n_perms);

void read_state_global(const void *ctx, const void *state);
void read_state_buffered_data(const void *ctx, struct connection *conn,
			      const struct xs_state_connection *sc);
void read_state_node(const void *ctx, const void *state);

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
