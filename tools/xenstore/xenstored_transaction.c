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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include "talloc.h"
#include "list.h"
#include "xenstored_transaction.h"
#include "xenstored_watch.h"
#include "xs_lib.h"
#include "utils.h"
#include "xenstored_test.h"

struct changed_node
{
	/* The list within this transaction. */
	struct list_head list;

	/* The name of the node. */
	char *node;
};

struct transaction
{
	/* Global list of transactions. */
	struct list_head list;

	/* My owner (conn->transaction == me). */
	struct connection *conn;

	/* Subtree this transaction covers */
	char *node;

	/* Base for this transaction. */
	char *divert;

	/* List of changed nodes. */
	struct list_head changes;

	/* Someone's waiting: time limit. */
	struct timeval timeout;

	/* We've timed out. */
	bool destined_to_fail;
};
static LIST_HEAD(transactions);

bool within_transaction(struct transaction *trans, const char *node)
{
	if (!trans)
		return true;
	return is_child(node, trans->node);
}

/* You are on notice: this transaction is blocking someone. */
static void start_transaction_timeout(struct transaction *trans)
{
	if (timerisset(&trans->timeout))
		return;

	/* One second timeout. */
	gettimeofday(&trans->timeout, NULL);
	trans->timeout.tv_sec += 1;
}

struct transaction *transaction_covering_node(const char *node)
{
	struct transaction *i;

	list_for_each_entry(i, &transactions, list) {
		if (i->destined_to_fail)
			continue;
		if (is_child(i->node, node) || is_child(node, i->node))
			return i;
	}
	return NULL;
}

bool transaction_block(struct connection *conn, const char *node)
{
	struct transaction *trans;

	/* Transactions don't overlap, so we can't be blocked by
	 * others if we're in one. */
	if (conn->transaction)
		return false;

	trans = transaction_covering_node(node);
	if (trans) {
		start_transaction_timeout(trans);
		conn->blocked = talloc_strdup(conn, node);
		return true;
	}
	return false;
}

/* Callers get a change node (which can fail) and only commit after they've
 * finished.  This way they don't have to unwind eg. a write. */
void add_change_node(struct transaction *trans, const char *node)
{
	struct changed_node *i;

	if (!trans)
		return;

	list_for_each_entry(i, &trans->changes, list)
		if (streq(i->node, node))
			return;

	i = talloc(trans, struct changed_node);
	i->node = talloc_strdup(i, node);
	INIT_LIST_HEAD(&i->list);
	list_add_tail(&i->list, &trans->changes);
}

char *node_dir_inside_transaction(struct transaction *trans, const char *node)
{
	return talloc_asprintf(node, "%s%s", trans->divert,
			       node + strlen(trans->node));
}

void shortest_transaction_timeout(struct timeval *tv)
{
	struct transaction *i;

	list_for_each_entry(i, &transactions, list) {
		if (!timerisset(&i->timeout))
			continue;

		if (!timerisset(tv) || timercmp(&i->timeout, tv, <))
			*tv = i->timeout;
	}
}	

void check_transaction_timeout(void)
{
	struct transaction *i;
	struct timeval now;

	gettimeofday(&now, NULL);

	list_for_each_entry(i, &transactions, list) {
		if (!timerisset(&i->timeout))
			continue;

		if (timercmp(&i->timeout, &now, <))
			i->destined_to_fail = true;
	}
}

/* FIXME: Eliminate all uses of this */
static bool do_command(const char *cmd)
{
	int ret;

	ret = system(cmd);
	if (ret == -1)
		return false;
	if (!WIFEXITED(ret) || WEXITSTATUS(ret) != 0) {
		errno = EIO;
		return false;
	}
	return true;
}

static int destroy_transaction(void *_transaction)
{
	struct transaction *trans = _transaction;

	list_del(&trans->list);
	return destroy_path(trans->divert);
}

bool do_transaction_start(struct connection *conn, const char *node)
{
	struct transaction *transaction;
	char *dir, *cmd;

	if (conn->transaction)
		return send_error(conn, EBUSY);

	if (!check_node_perms(conn, node, XS_PERM_READ))
		return send_error(conn, errno);

	if (transaction_block(conn, node))
		return true;

	dir = node_dir_outside_transaction(node);

	/* Attach transaction to node for autofree until it's complete */
	transaction = talloc(node, struct transaction);
	transaction->node = talloc_strdup(transaction, node);
	transaction->divert = talloc_asprintf(transaction, "%s/%p/", 
					      xs_daemon_transactions(),
					      transaction);
	cmd = talloc_asprintf(node, "cp -a %s %s", dir, transaction->divert);
	if (!do_command(cmd))
		corrupt(conn, "Creating transaction %s", transaction->divert);

	talloc_steal(conn, transaction);
	INIT_LIST_HEAD(&transaction->changes);
	transaction->conn = conn;
	timerclear(&transaction->timeout);
	transaction->destined_to_fail = false;
	list_add_tail(&transaction->list, &transactions);
	conn->transaction = transaction;
	talloc_set_destructor(transaction, destroy_transaction);
	return send_ack(transaction->conn, XS_TRANSACTION_START);
}

static bool commit_transaction(struct transaction *trans)
{
	char *tmp, *dir;
	struct changed_node *i;

	/* Move: orig -> .old, repl -> orig.  Cleanup deletes .old. */
	dir = node_dir_outside_transaction(trans->node);
	tmp = talloc_asprintf(trans, "%s.old", dir);

	if (rename(dir, tmp) != 0)
		return false;
	if (rename(trans->divert, dir) != 0)
		corrupt(trans->conn, "Failed rename %s to %s",
			trans->divert, dir);

	trans->divert = tmp;

	/* Fire off the watches for everything that changed. */
	list_for_each_entry(i, &trans->changes, list)
		fire_watches(NULL, i->node);
	return true;
}

bool do_transaction_end(struct connection *conn, const char *arg)
{
	if (!arg || (!streq(arg, "T") && !streq(arg, "F")))
		return send_error(conn, EINVAL);

	if (!conn->transaction)
		return send_error(conn, ENOENT);

	if (streq(arg, "T")) {
		if (conn->transaction->destined_to_fail) {
			send_error(conn, ETIMEDOUT);
			goto failed;
		}
		if (!commit_transaction(conn->transaction)) {
			send_error(conn, errno);
			goto failed;
		}
	}

	talloc_free(conn->transaction);
	conn->transaction = NULL;
	return send_ack(conn, XS_TRANSACTION_END);

failed:
	talloc_free(conn->transaction);
	conn->transaction = NULL;
	return false;
}

