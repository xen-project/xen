/* 
    Transaction code for Xen Store Daemon.
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
#ifndef _XENSTORED_TRANSACTION_H
#define _XENSTORED_TRANSACTION_H
#include "core.h"

enum node_access_type {
    NODE_ACCESS_READ,
    NODE_ACCESS_WRITE,
    NODE_ACCESS_DELETE
};

struct transaction;

extern uint64_t generation;

int do_transaction_start(const void *ctx, struct connection *conn,
			 struct buffered_data *node);
int do_transaction_end(const void *ctx, struct connection *conn,
		       struct buffered_data *in);

struct transaction *transaction_lookup(struct connection *conn, uint32_t id);

/* Set flag for created node. */
void ta_node_created(struct transaction *trans);

/* This node was accessed. */
int __must_check access_node(struct connection *conn, struct node *node,
                             enum node_access_type type, const char **db_name);

/* Queue watches for a modified node. */
void queue_watches(struct connection *conn, const char *name, bool watch_exact);

/* Prepend the transaction to name if appropriate. */
const char *transaction_prepend(struct connection *conn, const char *name);

/* Mark the transaction as failed. This will prevent it to be committed. */
void fail_transaction(struct transaction *trans);

/* Get the list head of the changed domains. */
struct list_head *transaction_get_changed_domains(struct transaction *trans);

void conn_delete_all_transactions(struct connection *conn);
int check_transactions(struct hashtable *hash);

#endif /* _XENSTORED_TRANSACTION_H */
