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
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef _XENSTORED_CORE_H
#define _XENSTORED_CORE_H

#include <sys/types.h>
#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include "xs_lib.h"
#include "xenstored.h"
#include "list.h"

struct buffered_data
{
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
};

struct connection;
typedef int connwritefn_t(struct connection *, const void *, unsigned int);
typedef int connreadfn_t(struct connection *, void *, unsigned int);

enum state
{
	/* Blocked by transaction. */
	BLOCKED,
	/* Doing action, not listening */
	BUSY,
	/* Completed */
	OK,
};

struct connection
{
	struct list_head list;

	/* The file descriptor we came in on. */
	int fd;

	/* Who am I?  0 for socket connections. */
	domid_t id;

	/* Blocked on transaction?  Busy? */
	enum state state;

	/* Node we are waiting for (if state == BLOCKED) */
	char *blocked_by;

	/* Is this a read-only connection? */
	bool can_write;

	/* Are we waiting for a watch event ack? */
	struct watch *waiting_for_ack;

	/* Buffered incoming data. */
	struct buffered_data *in;

	/* Buffered output data */
	struct buffered_data *out;

	/* If we had a watch fire outgoing when we needed to reply... */
	struct buffered_data *waiting_reply;

	/* My transaction, if any. */
	struct transaction *transaction;

	/* The domain I'm associated with, if any. */
	struct domain *domain;

	/* My watches. */
	struct list_head watches;

	/* Methods for communicating over this connection: write can be NULL */
	connwritefn_t *write;
	connreadfn_t *read;
};
extern struct list_head connections;

/* Return length of string (including nul) at this offset. */
unsigned int get_string(const struct buffered_data *data,
			unsigned int offset);

/* Break input into vectors, return the number, fill in up to num of them. */
unsigned int get_strings(struct buffered_data *data,
			 char *vec[], unsigned int num);

/* Is child node a child or equal to parent node? */
bool is_child(const char *child, const char *parent);

/* Create a new buffer with lifetime of context. */
struct buffered_data *new_buffer(void *ctx);

void send_reply(struct connection *conn, enum xsd_sockmsg_type type,
		const void *data, unsigned int len);

/* Some routines (write, mkdir, etc) just need a non-error return */
void send_ack(struct connection *conn, enum xsd_sockmsg_type type);

/* Send an error: error is usually "errno". */
void send_error(struct connection *conn, int error);

/* Canonicalize this path if possible. */
char *canonicalize(struct connection *conn, const char *node);

/* Check permissions on this node. */
bool check_node_perms(struct connection *conn, const char *node,
		      enum xs_perm_type perm);

/* Path to this node outside transaction. */
char *node_dir_outside_transaction(const char *node);

/* Fail due to excessive corruption, capitalist pigdogs! */
void __attribute__((noreturn)) corrupt(struct connection *conn,
				       const char *fmt, ...);

struct connection *new_connection(connwritefn_t *write, connreadfn_t *read);

void handle_input(struct connection *conn);
void handle_output(struct connection *conn);

/* Is this a valid node name? */
bool is_valid_nodename(const char *node);

/* Return a pointer to an open dir, self-closig and attached to pathname. */
DIR **talloc_opendir(const char *pathname);

/* Return a pointer to an fd, self-closing and attached to this pathname. */
int *talloc_open(const char *pathname, int flags, int mode);

/* Convenient talloc-style destructor for paths. */
int destroy_path(void *path);

/* Read entire contents of a talloced fd. */
void *read_all(int *fd, unsigned int *size);

/* Tracing infrastructure. */
void trace_create(const void *data, const char *type);
void trace_destroy(const void *data, const char *type);
void trace_watch_timeout(const struct connection *conn, const char *node, const char *token);
void trace(const char *fmt, ...);

#endif /* _XENSTORED_CORE_H */
