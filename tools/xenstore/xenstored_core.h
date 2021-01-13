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
#include <errno.h>

#include "xenstore_lib.h"
#include "xenstore_state.h"
#include "list.h"
#include "tdb.h"
#include "hashtable.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
/* O_CLOEXEC support is needed for Live Update in the daemon case. */
#ifndef __MINIOS__
#define NO_LIVE_UPDATE
#endif
#endif

/* DEFAULT_BUFFER_SIZE should be large enough for each errno string. */
#define DEFAULT_BUFFER_SIZE 16

typedef int32_t wrl_creditt;
#define WRL_CREDIT_MAX (1000*1000*1000)
/* ^ satisfies non-overflow condition for wrl_xfer_credit */

struct xs_state_connection;

struct buffered_data
{
	struct list_head list;

	/* Are we still doing the header? */
	bool inhdr;

	/* How far are we? */
	unsigned int used;

	union {
		struct xsd_sockmsg msg;
		char raw[sizeof(struct xsd_sockmsg)];
	} hdr;

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
typedef int connwritefn_t(struct connection *, const void *, unsigned int);
typedef int connreadfn_t(struct connection *, void *, unsigned int);

struct connection
{
	struct list_head list;

	/* The file descriptor we came in on. */
	int fd;
	/* The index of pollfd in global pollfd array */
	int pollfd_idx;

	/* Who am I? 0 for socket connections. */
	unsigned int id;

	/* Is this connection ignored? */
	bool is_ignored;

	/* Buffered incoming data. */
	struct buffered_data *in;

	/* Buffered output data */
	struct list_head out_list;

	/* Transaction context for current request (NULL if none). */
	struct transaction *transaction;

	/* List of in-progress transactions. */
	struct list_head transaction_list;
	uint32_t next_transaction_id;
	unsigned int transaction_started;
	time_t ta_start_time;

	/* List of delayed requests. */
	struct list_head delayed;

	/* The domain I'm associated with, if any. */
	struct domain *domain;

        /* The target of the domain I'm associated with. */
        struct connection *target;

	/* My watches. */
	struct list_head watches;

	/* Methods for communicating over this connection: write can be NULL */
	connwritefn_t *write;
	connreadfn_t *read;

	/* Support for live update: connection id. */
	unsigned int conn_id;
};
extern struct list_head connections;

struct node_perms {
	unsigned int num;
	struct xs_permissions *p;
};

struct node {
	const char *name;

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
	char *children;
};

/* Return the only argument in the input. */
const char *onearg(struct buffered_data *in);

/* Break input into vectors, return the number, fill in up to num of them. */
unsigned int get_strings(struct buffered_data *data,
			 char *vec[], unsigned int num);
unsigned int get_string(const struct buffered_data *data, unsigned int offset);

void send_reply(struct connection *conn, enum xsd_sockmsg_type type,
		const void *data, unsigned int len);

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

struct connection *new_connection(connwritefn_t *write, connreadfn_t *read);
struct connection *get_connection_by_id(unsigned int conn_id);
void check_store(void);
void corrupt(struct connection *conn, const char *fmt, ...);
enum xs_perm_type perm_for_conn(struct connection *conn,
				const struct node_perms *perms);

/* Is this a valid node name? */
bool is_valid_nodename(const char *node);

/* Get name of parent node. */
char *get_parent(const void *ctx, const char *node);

/* Delay a request. */
int delay_request(struct connection *conn, struct buffered_data *in,
		  bool (*func)(struct delayed_request *), void *data);

/* Tracing infrastructure. */
void trace_create(const void *data, const char *type);
void trace_destroy(const void *data, const char *type);
void trace(const char *fmt, ...);
void dtrace_io(const struct connection *conn, const struct buffered_data *data, int out);
void reopen_log(void);
void close_log(void);

extern int orig_argc;
extern char **orig_argv;

extern char *tracefile;
extern int tracefd;

extern TDB_CONTEXT *tdb_ctx;
extern int dom0_domid;
extern int dom0_event;
extern int priv_domid;
extern int quota_nb_entry_per_domain;

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

int writefd(struct connection *conn, const void *data, unsigned int len);
int readfd(struct connection *conn, void *data, unsigned int len);

extern struct interface_funcs socket_funcs;
extern xengnttab_handle **xgt_handle;

int remember_string(struct hashtable *hash, const char *str);

void set_tdb_key(const char *name, TDB_DATA *key);

const char *dump_state_global(FILE *fp);
const char *dump_state_buffered_data(FILE *fp, const struct connection *c,
				     const struct connection *conn,
				     struct xs_state_connection *sc);
const char *dump_state_nodes(FILE *fp, const void *ctx);
const char *dump_state_node_perms(FILE *fp, struct xs_state_node *sn,
				  const struct xs_permissions *perms,
				  unsigned int n_perms);

void read_state_global(const void *ctx, const void *state);
void read_state_buffered_data(const void *ctx, struct connection *conn,
			      const struct xs_state_connection *sc);
void read_state_node(const void *ctx, const void *state);

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
