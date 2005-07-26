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
#include <fcntl.h>
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

	/* And the children? (ie. rm) */
	bool recurse;
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
		conn->state = BLOCKED;
		conn->blocked_by = talloc_strdup(conn, node);
		return true;
	}
	return false;
}

/* Callers get a change node (which can fail) and only commit after they've
 * finished.  This way they don't have to unwind eg. a write. */
void add_change_node(struct transaction *trans, const char *node, bool recurse)
{
	struct changed_node *i;

	if (!trans)
		return;

	list_for_each_entry(i, &trans->changes, list)
		if (streq(i->node, node))
			return;

	i = talloc(trans, struct changed_node);
	i->node = talloc_strdup(i, node);
	i->recurse = recurse;
	list_add_tail(&i->list, &trans->changes);
}

char *node_dir_inside_transaction(struct transaction *trans, const char *node)
{
	return talloc_asprintf(node, "%s/%s", trans->divert,
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

static int destroy_transaction(void *_transaction)
{
	struct transaction *trans = _transaction;

	list_del(&trans->list);
	trace_destroy(trans, "transaction");
	return destroy_path(trans->divert);
}

static bool copy_file(const char *src, const char *dst)
{
	int *infd, *outfd;
	void *data;
	unsigned int size;

	infd = talloc_open(src, O_RDONLY, 0);
	if (!infd)
		return false;
	outfd = talloc_open(dst, O_WRONLY|O_CREAT|O_EXCL, 0640);
	if (!outfd)
		return false;
	data = read_all(infd, &size);
	if (!data)
		return false;
	return xs_write_all(*outfd, data, size);
}

static bool copy_dir(const char *src, const char *dst)
{
	DIR **dir;
	struct dirent *dirent;

	if (mkdir(dst, 0750) != 0)
		return false;

	dir = talloc_opendir(src);
	if (!dir)
		return false;

	while ((dirent = readdir(*dir)) != NULL) {
		struct stat st;
		char *newsrc, *newdst;

		if (streq(dirent->d_name, ".") || streq(dirent->d_name, ".."))
			continue;

		newsrc = talloc_asprintf(src, "%s/%s", src, dirent->d_name);
		newdst = talloc_asprintf(src, "%s/%s", dst, dirent->d_name);
		if (stat(newsrc, &st) != 0)
			return false;
		
		if (S_ISDIR(st.st_mode)) {
			if (!copy_dir(newsrc, newdst))
				return false;
		} else {
			if (!copy_file(newsrc, newdst))
				return false;
		}
		/* Free now so we don't run out of file descriptors */
		talloc_free(newsrc);
		talloc_free(newdst);
	}
	return true;
}

void do_transaction_start(struct connection *conn, const char *node)
{
	struct transaction *transaction;
	char *dir;

	if (conn->transaction) {
		send_error(conn, EBUSY);
		return;
	}

	node = canonicalize(conn, node);
	if (!check_node_perms(conn, node, XS_PERM_READ)) {
		send_error(conn, errno);
		return;
	}

	if (transaction_block(conn, node))
		return;

	dir = node_dir_outside_transaction(node);

	/* Attach transaction to node for autofree until it's complete */
	transaction = talloc(node, struct transaction);
	transaction->node = talloc_strdup(transaction, node);
	transaction->divert = talloc_asprintf(transaction, "%s/%p", 
					      xs_daemon_transactions(),
					      transaction);
	INIT_LIST_HEAD(&transaction->changes);
	transaction->conn = conn;
	timerclear(&transaction->timeout);
	transaction->destined_to_fail = false;
	list_add_tail(&transaction->list, &transactions);
	talloc_set_destructor(transaction, destroy_transaction);
	trace_create(transaction, "transaction");

	if (!copy_dir(dir, transaction->divert)) {
		send_error(conn, errno);
		return;
	}

	talloc_steal(conn, transaction);
	conn->transaction = transaction;
	send_ack(transaction->conn, XS_TRANSACTION_START);
}

static bool commit_transaction(struct transaction *trans)
{
	char *tmp, *dir;

	/* Move: orig -> .old, repl -> orig.  Cleanup deletes .old. */
	dir = node_dir_outside_transaction(trans->node);
	tmp = talloc_asprintf(trans, "%s.old", dir);

	if (rename(dir, tmp) != 0)
		return false;
	if (rename(trans->divert, dir) != 0)
		corrupt(trans->conn, "Failed rename %s to %s",
			trans->divert, dir);

	trans->divert = tmp;
	return true;
}

void do_transaction_end(struct connection *conn, const char *arg)
{
	struct changed_node *i;
	struct transaction *trans;
	bool fired = false;

	if (!arg || (!streq(arg, "T") && !streq(arg, "F"))) {
		send_error(conn, EINVAL);
		return;
	}

	if (!conn->transaction) {
		send_error(conn, ENOENT);
		return;
	}

	/* Set to NULL so fire_watches sends events. */
	trans = conn->transaction;
	conn->transaction = NULL;
	/* Attach transaction to arg for auto-cleanup */
	talloc_steal(arg, trans);

	if (streq(arg, "T")) {
		if (trans->destined_to_fail) {
			send_error(conn, ETIMEDOUT);
			return;
		}
		if (!commit_transaction(trans)) {
			send_error(conn, errno);
			return;
		}

		/* Fire off the watches for everything that changed. */
		list_for_each_entry(i, &trans->changes, list)
			fired |= fire_watches(conn, i->node, i->recurse);
	}

	if (fired)
		conn->watch_ack = XS_TRANSACTION_END;
	else
		send_ack(conn, XS_TRANSACTION_END);
}

