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

#include <inttypes.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "talloc.h"
#include "list.h"
#include "transaction.h"
#include "watch.h"
#include "domain.h"
#include "xenstore_lib.h"
#include "utils.h"

/*
 * Some notes regarding detection and handling of transaction conflicts:
 *
 * Basic source of reference is the 'generation' count. Each writing access
 * (either normal write or in a transaction) to the tdb data base will set
 * the node specific generation count to the global generation count.
 * For being able to identify a transaction the transaction specific generation
 * count is initialized with the global generation count when starting the
 * transaction.
 * Each time the global generation count is copied to either a node or a
 * transaction it is incremented. This ensures all nodes and/or transactions
 * are having a unique generation count. The increment is done _before_ the
 * copy as that is needed for checking whether a domain was created before
 * or after a node has been written (the domain's generation is set with the
 * actual generation count without incrementing it, in order to support
 * writing a node for a domain before the domain has been officially
 * introduced).
 *
 * Transaction conflicts are detected by checking the generation count of all
 * nodes read in the transaction to match with the generation count in the
 * global data base at the end of the transaction. Nodes which have been
 * modified in the transaction don't have to be checked to match even if they
 * have been read, as the modified node will be globally visible after the
 * succeeded transaction possibly overwriting another modification which may
 * have occurred concurrent to the transaction.
 *
 * Examples:
 * ---------
 * The following notation is used:
 * I:      initial state
 * G       global generation count
 * g(X)    generation count of node X
 * G(1)    generation count of transaction 1
 * g(1:Y)  saved generation count of node Y in transaction 1
 * TA1:    operation in transaction 1
 * X=1:X   replace global node X with transaction 1 specific value of X
 *
 * 1. Simple transaction doing: read node A, write node B
 *    I: g(A) = 1, g(B) = 2, G = 3
 *    Start transaction 1: G(1) = 3, G = 4
 *    TA1: read node A:    g(1:A) = 1
 *    TA1: write node B:   g(1:B) = 4, G = 5
 *    End TA1: g(1:A) == g(A) => okay, B = 1:B, g(B) = 5, G = 6
 *
 * 2. Transaction with conflicting write
 *    I: g(A) = 1, g(B) = 2, G = 3
 *    Start transaction 1: G(1) = 3, G = 4
 *    TA1: read node A:    g(1:A) = 1
 *    write node A:        g(A) = 4, G = 5
 *    TA1: write node B:   g(1:B) = 5, G = 6
 *    End TA1: g(1:A) != g(A) => EAGAIN
 *
 * 3. Transaction with conflicting delete
 *    I: g(A) = 1, g(B) = 2, G = 3
 *    Start transaction 1: G(1) = 3, G = 4
 *    TA1: read node A:    g(1:A) = 1
 *    delete node A:       g(A) = ~0
 *    TA1: write node B:   g(1:B) = 4, G = 5
 *    End TA1: g(1:A) != g(A) => EAGAIN
 *
 * 4. Two interfering transactions
 *    I: g(A) = 1, g(B) = 2, G = 3
 *    Start transaction 1: G(1) = 3, G = 4
 *    Start transaction 2: G(2) = 4, G = 5
 *    TA1: read node A:    g(1:A) = 1
 *    TA2: read node B:    g(2:B) = 2
 *    TA1: write node B:   g(1:B) = 5, G = 6
 *    TA2: write node A:   g(2:A) = 6, G = 7
 *    End TA1: g(1:A) == g(A) => okay, B = 1:B, g(B) = 7, G = 8
 *    End TA2: g(2:B) != g(B) => EAGAIN
 */

struct accessed_node
{
	/* List of all changed nodes in the context of this transaction. */
	struct list_head list;

	/* The name of the node. */
	char *trans_name;	/* Transaction specific name. */
	char *node;		/* Main data base name. */

	/* Generation count (or NO_GENERATION) for conflict checking. */
	uint64_t generation;

	/* Original node permissions. */
	struct node_perms perms;

	/* Generation count checking required? */
	bool check_gen;

	/* Modified? */
	bool modified;

	/* Transaction node in data base? */
	bool ta_node;

	/* Watch event flags. */
	bool fire_watch;
	bool watch_exact;
};

struct transaction
{
	/* List of all transactions active on this connection. */
	struct list_head list;

	/* Connection this transaction is associated with. */
	struct connection *conn;

	/* Connection-local identifier for this transaction. */
	uint32_t id;

	/* Node counter. */
	unsigned int nodes;

	/* Generation when transaction started. */
	uint64_t generation;

	/* List of accessed nodes. */
	struct list_head accessed;

	/* List of changed domains - to record the changed domain entry number */
	struct list_head changed_domains;

	/* There was at least one node created in the transaction. */
	bool node_created;

	/* Flag for letting transaction fail. */
	bool fail;
};

uint64_t generation;

void ta_node_created(struct transaction *trans)
{
	trans->node_created = true;
}

static struct accessed_node *find_accessed_node(struct transaction *trans,
						const char *name)
{
	struct accessed_node *i;

	list_for_each_entry(i, &trans->accessed, list)
		if (streq(i->node, name))
			return i;

	return NULL;
}

static char *transaction_get_node_name(void *ctx, struct transaction *trans,
				       const char *name)
{
	return talloc_asprintf(ctx, "%"PRIu64"/%s", trans->generation, name);
}

/*
 * Prepend the transaction to name if node has been modified in the current
 * transaction.
 */
const char *transaction_prepend(struct connection *conn, const char *name)
{
	struct accessed_node *i;

	if (conn && conn->transaction) {
		i = find_accessed_node(conn->transaction, name);
		if (i)
			return i->trans_name;
	}

	return name;
}

/*
 * A node has been accessed.
 *
 * Modifying accesses (write, delete) always update the generation (global and
 * node->generation).
 *
 * Accesses in a transaction will be added to the list of accessed nodes
 * if not already done. Read type accesses will copy the node to the
 * transaction specific data base part, write type accesses go there
 * anyway.
 *
 * If not NULL, key will be supplied with name and length of name of the node
 * to be accessed in the data base.
 */
int access_node(struct connection *conn, struct node *node,
		enum node_access_type type, const char **db_name)
{
	struct accessed_node *i = NULL;
	struct transaction *trans;
	int ret;
	bool introduce = false;

	if (type != NODE_ACCESS_READ) {
		node->hdr.generation = ++generation;
		if (conn && !conn->transaction)
			wrl_apply_debit_direct(conn);
	}

	if (!conn || !conn->transaction) {
		/* They're changing the global database. */
		if (db_name)
			*db_name = node->name;
		return 0;
	}

	trans = conn->transaction;

	i = find_accessed_node(trans, node->name);
	if (!i) {
		if (domain_max_chk(conn, ACC_TRANSNODES, trans->nodes + 1)) {
			ret = ENOSPC;
			goto err;
		}
		i = talloc_zero(trans, struct accessed_node);
		if (!i)
			goto nomem;
		i->trans_name = transaction_get_node_name(i, trans, node->name);
		if (!i->trans_name)
			goto nomem;
		i->node = strchr(i->trans_name, '/') + 1;
		if (node->hdr.generation != NO_GENERATION &&
		    node->hdr.num_perms) {
			i->perms.p = talloc_array(i, struct xs_permissions,
						  node->hdr.num_perms);
			if (!i->perms.p)
				goto nomem;
			i->perms.num = node->hdr.num_perms;
			memcpy(i->perms.p, node->perms,
			       i->perms.num * sizeof(*i->perms.p));
		}

		introduce = true;
		i->ta_node = false;
		/* acc.memory < 0 means "unknown, get size from TDB". */
		node->acc.memory = -1;

		/*
		 * Additional transaction-specific node for read type. We only
		 * have to verify read nodes if we didn't write them.
		 *
		 * The node is created and written to DB here to distinguish
		 * from the write types.
		 */
		if (type == NODE_ACCESS_READ) {
			i->generation = node->hdr.generation;
			i->check_gen = true;
			if (node->hdr.generation != NO_GENERATION) {
				ret = write_node_raw(conn, i->trans_name, node,
						     NODE_CREATE, true);
				if (ret)
					goto err;
				i->ta_node = true;
			}
		}
		trans->nodes++;
		list_add_tail(&i->list, &trans->accessed);
	}

	if (type != NODE_ACCESS_READ)
		i->modified = true;

	if (introduce && type == NODE_ACCESS_DELETE)
		/* Nothing to delete. */
		return -1;

	if (db_name) {
		*db_name = i->trans_name;
		if (type == NODE_ACCESS_WRITE)
			i->ta_node = true;
		if (type == NODE_ACCESS_DELETE)
			i->ta_node = false;
	}

	return 0;

nomem:
	ret = ENOMEM;
err:
	talloc_free(i);
	trans->fail = true;
	errno = ret;
	return ret;
}

/*
 * A watch event should be fired for a node modified inside a transaction.
 * Set the corresponding information. A non-exact event is replacing an exact
 * one, but not the other way round.
 */
void queue_watches(struct connection *conn, const char *name, bool watch_exact)
{
	struct accessed_node *i;

	i = find_accessed_node(conn->transaction, name);
	if (!i) {
		conn->transaction->fail = true;
		return;
	}

	if (!i->fire_watch) {
		i->fire_watch = true;
		i->watch_exact = watch_exact;
	} else if (!watch_exact) {
		i->watch_exact = false;
	}
}

/*
 * Finalize transaction:
 * Walk through accessed nodes and check generation against global data.
 * If all entries match, read the transaction entries and write them without
 * transaction prepended. Delete all transaction specific nodes in the data
 * base.
 */
static int finalize_transaction(struct connection *conn,
				struct transaction *trans, bool *is_corrupt)
{
	struct accessed_node *i, *n;
	size_t size;
	const struct node_hdr *hdr;
	uint64_t gen;

	list_for_each_entry_safe(i, n, &trans->accessed, list) {
		if (i->check_gen) {
			hdr = db_fetch(i->node, &size);
			if (!hdr) {
				gen = NO_GENERATION;
			} else {
				gen = hdr->generation;
			}
			if (i->generation != gen)
				return EAGAIN;
		}

		/* Entries for unmodified nodes can be removed early. */
		if (!i->modified) {
			if (i->ta_node)
				db_delete(conn, i->trans_name, NULL);
			list_del(&i->list);
			talloc_free(i);
		}
	}

	while ((i = list_top(&trans->accessed, struct accessed_node, list))) {
		if (i->ta_node) {
			hdr = db_fetch(i->trans_name, &size);
			if (hdr) {
				/*
				 * Delete transaction entry and write it as
				 * no-TA entry. As we only hold a reference
				 * to the data, increment its ref count, then
				 * delete it from the DB. Now we own it and can
				 * drop the const attribute for changing the
				 * generation count.
				 */
				enum write_node_mode mode;
				struct node_hdr *own;

				talloc_increase_ref_count(hdr);
				db_delete(conn, i->trans_name, NULL);

				own = (struct node_hdr *)hdr;
				own->generation = ++generation;
				mode = (i->generation == NO_GENERATION)
				       ? NODE_CREATE : NODE_MODIFY;
				*is_corrupt |= db_write(conn, i->node, own,
							size, NULL, mode, true);
			} else {
				*is_corrupt = true;
			}
		} else {
			/*
			 * A node having been created and later deleted
			 * in this transaction will have no generation
			 * information stored.
			 */
			if (i->generation != NO_GENERATION)
				db_delete(conn, i->node, NULL);
		}
		if (i->fire_watch)
			fire_watches(conn, trans, i->node, NULL, i->watch_exact,
				     i->perms.p ? &i->perms : NULL);

		list_del(&i->list);
		talloc_free(i);
	}

	return 0;
}

static int destroy_transaction(void *_transaction)
{
	struct transaction *trans = _transaction;
	struct accessed_node *i;

	wrl_ntransactions--;
	trace_destroy(trans, "transaction");
	while ((i = list_top(&trans->accessed, struct accessed_node, list))) {
		if (i->ta_node)
			db_delete(trans->conn, i->trans_name, NULL);
		list_del(&i->list);
		talloc_free(i);
	}

	return 0;
}

struct transaction *transaction_lookup(struct connection *conn, uint32_t id)
{
	struct transaction *trans;

	if (id == 0)
		return NULL;

	list_for_each_entry(trans, &conn->transaction_list, list)
		if (trans->id == id)
			return trans;

	return ERR_PTR(-ENOENT);
}

int do_transaction_start(const void *ctx, struct connection *conn,
			 struct buffered_data *in)
{
	struct transaction *trans, *exists;
	char id_str[20];

	/* We don't support nested transactions. */
	if (conn->transaction)
		return EBUSY;

	if (domain_transaction_get(conn) > hard_quotas[ACC_TRANS].val)
		return ENOSPC;

	/* Attach transaction to ctx for autofree until it's complete */
	trans = talloc_zero(ctx, struct transaction);
	if (!trans)
		return ENOMEM;

	trace_create(trans, "transaction");
	INIT_LIST_HEAD(&trans->accessed);
	INIT_LIST_HEAD(&trans->changed_domains);
	trans->conn = conn;
	trans->fail = false;
	trans->generation = ++generation;

	/* Pick an unused transaction identifier. */
	do {
		trans->id = conn->next_transaction_id;
		exists = transaction_lookup(conn, conn->next_transaction_id++);
	} while (!IS_ERR(exists));

	if (list_empty(&conn->transaction_list))
		conn->ta_start_time = time(NULL);

	/* Now we own it. */
	list_add_tail(&trans->list, &conn->transaction_list);
	talloc_steal(conn, trans);
	talloc_set_destructor(trans, destroy_transaction);
	domain_transaction_inc(conn);
	wrl_ntransactions++;

	snprintf(id_str, sizeof(id_str), "%u", trans->id);
	send_reply(conn, XS_TRANSACTION_START, id_str, strlen(id_str)+1);

	return 0;
}

int do_transaction_end(const void *ctx, struct connection *conn,
		       struct buffered_data *in)
{
	const char *arg = onearg(in);
	struct transaction *trans;
	bool is_corrupt = false;
	bool chk_quota;
	int ret;

	if (!arg || (!streq(arg, "T") && !streq(arg, "F")))
		return EINVAL;

	if ((trans = conn->transaction) == NULL)
		return ENOENT;

	conn->transaction = NULL;
	list_del(&trans->list);
	domain_transaction_dec(conn);
	if (list_empty(&conn->transaction_list))
		conn->ta_start_time = 0;

	chk_quota = trans->node_created && domain_is_unprivileged(conn);

	/* Attach transaction to ctx for auto-cleanup */
	talloc_steal(ctx, trans);

	if (streq(arg, "T")) {
		if (trans->fail)
			return ENOMEM;
		ret = acc_fix_domains(&trans->changed_domains, chk_quota,
				      false);
		if (ret)
			return ret;
		ret = finalize_transaction(conn, trans, &is_corrupt);
		if (ret)
			return ret;

		wrl_apply_debit_trans_commit(conn);

		/* fix domain entry for each changed domain */
		acc_fix_domains(&trans->changed_domains, false, true);

		if (is_corrupt)
			corrupt(conn, "transaction inconsistency");
	}
	send_ack(conn, XS_TRANSACTION_END);

	return 0;
}

struct list_head *transaction_get_changed_domains(struct transaction *trans)
{
	return &trans->changed_domains;
}

void fail_transaction(struct transaction *trans)
{
	trans->fail = true;
}

void conn_delete_all_transactions(struct connection *conn)
{
	struct transaction *trans;

	while ((trans = list_top(&conn->transaction_list,
				 struct transaction, list))) {
		list_del(&trans->list);
		talloc_free(trans);
	}

	assert(conn->transaction == NULL);

	conn->ta_start_time = 0;
}

int check_transactions(struct hashtable *hash)
{
	struct connection *conn;
	struct transaction *trans;
	struct accessed_node *i;
	char *tname;

	list_for_each_entry(conn, &connections, list) {
		list_for_each_entry(trans, &conn->transaction_list, list) {
			tname = talloc_asprintf(trans, "%"PRIu64,
						trans->generation);
			if (!tname || remember_string(hash, tname))
				goto nomem;

			list_for_each_entry(i, &trans->accessed, list) {
				if (!i->ta_node)
					continue;
				if (remember_string(hash, i->trans_name))
					goto nomem;
			}

			talloc_free(tname);
		}
	}

	return 0;

nomem:
	talloc_free(tname);
	return ENOMEM;
}

/*
 * Local variables:
 *  mode: C
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
