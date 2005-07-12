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
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#ifndef _XENSTORED_TRANSACTION_H
#define _XENSTORED_TRANSACTION_H
#include "xenstored_core.h"

struct transaction;

bool do_transaction_start(struct connection *conn, const char *node);
bool do_transaction_end(struct connection *conn, const char *arg);

/* Is node covered by this transaction? */
bool within_transaction(struct transaction *trans, const char *node);

/* If a write op on this node blocked by another connections' transaction,
 * mark conn, setup transaction timeout and return true.
 */
bool transaction_block(struct connection *conn, const char *node);

/* Return transaction which covers this node. */
struct transaction *transaction_covering_node(const char *node);

/* Return directory of node within transaction t. */
char *node_dir_inside_transaction(struct transaction *t, const char *node);

/* This node was changed: can fail and longjmp. */
void add_change_node(struct transaction *trans, const char *node, bool recurse);

/* Get shortest timeout: leave tv unset if none. */
void shortest_transaction_timeout(struct timeval *tv);

/* Have any transactions timed out yet? */
void check_transaction_timeout(void);
#endif /* _XENSTORED_TRANSACTION_H */
