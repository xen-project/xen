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
#include "xenstored_transaction.h"
#include "xenstored_watch.h"
#include "xenstored_domain.h"
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
 * are having a unique generation count.
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
	char *node;

	/* Generation count (or NO_GENERATION) for conflict checking. */
	uint64_t generation;

	/* Generation count checking required? */
	bool check_gen;

	/* Modified? */
	bool modified;

	/* Transaction node in data base? */
	bool ta_node;
};

struct changed_domain
{
	/* List of all changed domains in the context of this transaction. */
	struct list_head list;

	/* Identifier of the changed domain. */
	unsigned int domid;

	/* Amount by which this domain's nbentry field has changed. */
	int nbentry;
};

struct transaction
{
	/* List of all transactions active on this connection. */
	struct list_head list;

	/* Connection-local identifier for this transaction. */
	uint32_t id;

	/* Generation when transaction started. */
	uint64_t generation;

	/* List of accessed nodes. */
	struct list_head accessed;

	/* List of changed domains - to record the changed domain entry number */
	struct list_head changed_domains;

	/* Flag for letting transaction fail. */
	bool fail;
};

extern int quota_max_transaction;
static uint64_t generation;

static void set_tdb_key(const char *name, TDB_DATA *key)
{
	key->dptr = (char *)name;
	key->dsize = strlen(name);
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
int transaction_prepend(struct connection *conn, const char *name,
			TDB_DATA *key)
{
	char *tdb_name;

	if (!conn || !conn->transaction ||
	    !find_accessed_node(conn->transaction, name)) {
		set_tdb_key(name, key);
		return 0;
	}

	tdb_name = transaction_get_node_name(conn->transaction,
					     conn->transaction, name);
	if (!tdb_name)
		return errno;

	set_tdb_key(tdb_name, key);

	return 0;
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
		enum node_access_type type, TDB_DATA *key)
{
	struct accessed_node *i = NULL;
	struct transaction *trans;
	TDB_DATA local_key;
	const char *trans_name = NULL;
	int ret;
	bool introduce = false;

	if (type != NODE_ACCESS_READ) {
		node->generation = generation++;
		if (conn && !conn->transaction)
			wrl_apply_debit_direct(conn);
	}

	if (!conn || !conn->transaction) {
		/* They're changing the global database. */
		if (key)
			set_tdb_key(node->name, key);
		return 0;
	}

	trans = conn->transaction;

	trans_name = transaction_get_node_name(node, trans, node->name);
	if (!trans_name)
		goto nomem;

	i = find_accessed_node(trans, node->name);
	if (!i) {
		i = talloc_zero(trans, struct accessed_node);
		if (!i)
			goto nomem;
		i->node = talloc_strdup(i, node->name);
		if (!i->node)
			goto nomem;

		introduce = true;
		i->ta_node = false;

		/*
		 * Additional transaction-specific node for read type. We only
		 * have to verify read nodes if we didn't write them.
		 *
		 * The node is created and written to DB here to distinguish
		 * from the write types.
		 */
		if (type == NODE_ACCESS_READ) {
			i->generation = node->generation;
			i->check_gen = true;
			if (node->generation != NO_GENERATION) {
				set_tdb_key(trans_name, &local_key);
				ret = write_node_raw(conn, &local_key, node);
				if (ret)
					goto err;
				i->ta_node = true;
			}
		}
		list_add_tail(&i->list, &trans->accessed);
	}

	if (type != NODE_ACCESS_READ)
		i->modified = true;

	if (introduce && type == NODE_ACCESS_DELETE)
		/* Nothing to delete. */
		return -1;

	if (key) {
		set_tdb_key(trans_name, key);
		if (type == NODE_ACCESS_WRITE)
			i->ta_node = true;
		if (type == NODE_ACCESS_DELETE)
			i->ta_node = false;
	}

	return 0;

nomem:
	ret = ENOMEM;
err:
	talloc_free((void *)trans_name);
	talloc_free(i);
	trans->fail = true;
	errno = ret;
	return ret;
}

/*
 * Finalize transaction:
 * Walk through accessed nodes and check generation against global data.
 * If all entries match, read the transaction entries and write them without
 * transaction prepended. Delete all transaction specific nodes in the data
 * base.
 */
static int finalize_transaction(struct connection *conn,
				struct transaction *trans)
{
	struct accessed_node *i;
	TDB_DATA key, ta_key, data;
	struct xs_tdb_record_hdr *hdr;
	uint64_t gen;
	char *trans_name;
	int ret;

	list_for_each_entry(i, &trans->accessed, list) {
		if (!i->check_gen)
			continue;

		set_tdb_key(i->node, &key);
		data = tdb_fetch(tdb_ctx, key);
		hdr = (void *)data.dptr;
		if (!data.dptr) {
			if (tdb_error(tdb_ctx) != TDB_ERR_NOEXIST)
				return EIO;
			gen = NO_GENERATION;
		} else
			gen = hdr->generation;
		talloc_free(data.dptr);
		if (i->generation != gen)
			return EAGAIN;
	}

	while ((i = list_top(&trans->accessed, struct accessed_node, list))) {
		trans_name = transaction_get_node_name(i, trans, i->node);
		if (!trans_name)
			/* We are doomed: the transaction is only partial. */
			goto err;

		set_tdb_key(trans_name, &ta_key);

		if (i->modified) {
			set_tdb_key(i->node, &key);
			if (i->ta_node) {
				data = tdb_fetch(tdb_ctx, ta_key);
				if (!data.dptr)
					goto err;
				hdr = (void *)data.dptr;
				hdr->generation = generation++;
				ret = tdb_store(tdb_ctx, key, data,
						TDB_REPLACE);
				talloc_free(data.dptr);
				if (ret)
					goto err;
			} else if (tdb_delete(tdb_ctx, key))
					goto err;
			fire_watches(conn, trans, i->node, false);
		}

		if (i->ta_node && tdb_delete(tdb_ctx, ta_key))
			goto err;
		list_del(&i->list);
		talloc_free(i);
	}

	return 0;

err:
	corrupt(conn, "Partial transaction");
	return EIO;
}

static int destroy_transaction(void *_transaction)
{
	struct transaction *trans = _transaction;
	struct accessed_node *i;
	char *trans_name;
	TDB_DATA key;

	wrl_ntransactions--;
	trace_destroy(trans, "transaction");
	while ((i = list_top(&trans->accessed, struct accessed_node, list))) {
		if (i->ta_node) {
			trans_name = transaction_get_node_name(i, trans,
							       i->node);
			if (trans_name) {
				set_tdb_key(trans_name, &key);
				tdb_delete(tdb_ctx, key);
			}
		}
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

int do_transaction_start(struct connection *conn, struct buffered_data *in)
{
	struct transaction *trans, *exists;
	char id_str[20];

	/* We don't support nested transactions. */
	if (conn->transaction)
		return EBUSY;

	if (conn->id && conn->transaction_started > quota_max_transaction)
		return ENOSPC;

	/* Attach transaction to input for autofree until it's complete */
	trans = talloc_zero(in, struct transaction);
	if (!trans)
		return ENOMEM;

	INIT_LIST_HEAD(&trans->accessed);
	INIT_LIST_HEAD(&trans->changed_domains);
	trans->fail = false;
	trans->generation = generation++;

	/* Pick an unused transaction identifier. */
	do {
		trans->id = conn->next_transaction_id;
		exists = transaction_lookup(conn, conn->next_transaction_id++);
	} while (!IS_ERR(exists));

	/* Now we own it. */
	list_add_tail(&trans->list, &conn->transaction_list);
	talloc_steal(conn, trans);
	talloc_set_destructor(trans, destroy_transaction);
	conn->transaction_started++;
	wrl_ntransactions++;

	snprintf(id_str, sizeof(id_str), "%u", trans->id);
	send_reply(conn, XS_TRANSACTION_START, id_str, strlen(id_str)+1);

	return 0;
}

static int transaction_fix_domains(struct transaction *trans, bool update)
{
	struct changed_domain *d;
	int cnt;

	list_for_each_entry(d, &trans->changed_domains, list) {
		cnt = domain_entry_fix(d->domid, d->nbentry, update);
		if (!update && cnt >= quota_nb_entry_per_domain)
			return ENOSPC;
	}

	return 0;
}

int do_transaction_end(struct connection *conn, struct buffered_data *in)
{
	const char *arg = onearg(in);
	struct transaction *trans;
	int ret;

	if (!arg || (!streq(arg, "T") && !streq(arg, "F")))
		return EINVAL;

	if ((trans = conn->transaction) == NULL)
		return ENOENT;

	conn->transaction = NULL;
	list_del(&trans->list);
	conn->transaction_started--;

	/* Attach transaction to in for auto-cleanup */
	talloc_steal(in, trans);

	if (streq(arg, "T")) {
		if (trans->fail)
			return ENOMEM;
		ret = transaction_fix_domains(trans, false);
		if (ret)
			return ret;
		if (finalize_transaction(conn, trans))
			return EAGAIN;

		wrl_apply_debit_trans_commit(conn);

		/* fix domain entry for each changed domain */
		transaction_fix_domains(trans, true);
	}
	send_ack(conn, XS_TRANSACTION_END);

	return 0;
}

void transaction_entry_inc(struct transaction *trans, unsigned int domid)
{
	struct changed_domain *d;

	list_for_each_entry(d, &trans->changed_domains, list)
		if (d->domid == domid) {
			d->nbentry++;
			return;
		}

	d = talloc(trans, struct changed_domain);
	if (!d) {
		/* Let the transaction fail. */
		trans->fail = true;
		return;
	}
	d->domid = domid;
	d->nbentry = 1;
	list_add_tail(&d->list, &trans->changed_domains);
}

void transaction_entry_dec(struct transaction *trans, unsigned int domid)
{
	struct changed_domain *d;

	list_for_each_entry(d, &trans->changed_domains, list)
		if (d->domid == domid) {
			d->nbentry--;
			return;
		}

	d = talloc(trans, struct changed_domain);
	if (!d) {
		/* Let the transaction fail. */
		trans->fail = true;
		return;
	}
	d->domid = domid;
	d->nbentry = -1;
	list_add_tail(&d->list, &trans->changed_domains);
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

	conn->transaction_started = 0;
}

int check_transactions(struct hashtable *hash)
{
	struct connection *conn;
	struct transaction *trans;
	struct accessed_node *i;
	char *tname, *tnode;

	list_for_each_entry(conn, &connections, list) {
		list_for_each_entry(trans, &conn->transaction_list, list) {
			tname = talloc_asprintf(trans, "%"PRIu64,
						trans->generation);
			if (!tname || !remember_string(hash, tname))
				goto nomem;

			list_for_each_entry(i, &trans->accessed, list) {
				if (!i->ta_node)
					continue;
				tnode = transaction_get_node_name(tname, trans,
								  i->node);
				if (!tnode || !remember_string(hash, tnode))
					goto nomem;
				talloc_free(tnode);
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
