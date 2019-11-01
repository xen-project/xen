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
#include "list.h"
#include "tdb.h"
#include "hashtable.h"

/* DEFAULT_BUFFER_SIZE should be large enough for each errno string. */
#define DEFAULT_BUFFER_SIZE 16

typedef int32_t wrl_creditt;
#define WRL_CREDIT_MAX (1000*1000*1000)
/* ^ satisfies non-overflow condition for wrl_xfer_credit */

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

	/* Is this a read-only connection? */
	bool can_write;

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

struct node {
	const char *name;

	/* Parent (optional) */
	struct node *parent;

	/* Generation count. */
	uint64_t generation;
#define NO_GENERATION ~((uint64_t)0)

	/* Permissions. */
	unsigned int num_perms;
	struct xs_permissions *perms;

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

void send_reply(struct connection *conn, enum xsd_sockmsg_type type,
		const void *data, unsigned int len);

/* Some routines (write, mkdir, etc) just need a non-error return */
void send_ack(struct connection *conn, enum xsd_sockmsg_type type);

/* Canonicalize this path if possible. */
char *canonicalize(struct connection *conn, const void *ctx, const char *node);

/* Write a node to the tdb data base. */
int write_node_raw(struct connection *conn, TDB_DATA *key, struct node *node);

/* Get this node, checking we have permissions. */
struct node *get_node(struct connection *conn,
		      const void *ctx,
		      const char *name,
		      enum xs_perm_type perm);

struct connection *new_connection(connwritefn_t *write, connreadfn_t *read);
void check_store(void);
void corrupt(struct connection *conn, const char *fmt, ...);

/* Is this a valid node name? */
bool is_valid_nodename(const char *node);

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

xengnttab_handle **xgt_handle;

int remember_string(struct hashtable *hash, const char *str);

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
