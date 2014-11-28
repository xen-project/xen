/* 
    Xen Store Daemon providing simple tree-like database.
    Copyright (C) 2005 Rusty Russell IBM Corporation

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef XENSTORE_H
#define XENSTORE_H

#include <xenstore_lib.h>

#define XBT_NULL 0

#define XS_OPEN_READONLY	1UL<<0
#define XS_OPEN_SOCKETONLY      1UL<<1

/*
 * Setting XS_UNWATCH_FILTER arranges that after xs_unwatch, no
 * related watch events will be delivered via xs_read_watch.  But
 * this relies on the couple token, subpath is unique.
 *
 * XS_UNWATCH_FILTER clear          XS_UNWATCH_FILTER set
 *
 * Even after xs_unwatch, "stale"   After xs_unwatch returns, no
 * instances of the watch event     watch events with the same
 * may be delivered.                token and with the same subpath
 *                                  will be delivered.
 *
 * A path and a subpath can be      The application must avoid
 * register with the same token.    registering a path (/foo/) and
 *                                  a subpath (/foo/bar) with the
 *                                  same path until a successful
 *                                  xs_unwatch for the first watch
 *                                  has returned.
 */
#define XS_UNWATCH_FILTER     1UL<<2

struct xs_handle;
typedef uint32_t xs_transaction_t;

/* IMPORTANT: For details on xenstore protocol limits, see
 * docs/misc/xenstore.txt in the Xen public source repository, and use the
 * XENSTORE_*_MAX limit macros defined in xen/io/xs_wire.h.
 */

/* On failure, these routines set errno. */

/* Open a connection to the xs daemon.
 * Attempts to make a connection over the socket interface,
 * and if it fails, then over the  xenbus interface.
 * Mode 0 specifies read-write access, XS_OPEN_READONLY for
 * read-only access.
 *
 * * Connections made with xs_open(0) (which might be shared page or
 *   socket based) are only guaranteed to work in the parent after
 *   fork.
 * * Connections made with xs_open(XS_OPEN_SOCKETONLY) will be usable
 *   in either the parent or the child after fork, but not both.
 * * xs_daemon_open*() and xs_domain_open() are deprecated synonyms
 *   for xs_open(0).
 * * XS_OPEN_READONLY has no bearing on any of this.
 *
 * Returns a handle or NULL.
 */
struct xs_handle *xs_open(unsigned long flags);

/* Close the connection to the xs daemon. */
void xs_close(struct xs_handle *xsh);

/* Connect to the xs daemon.
 * Returns a handle or NULL.
 * Deprecated, please use xs_open(0) instead
 */
struct xs_handle *xs_daemon_open(void);
struct xs_handle *xs_domain_open(void);

/* Connect to the xs daemon (readonly for non-root clients).
 * Returns a handle or NULL.
 * Deprecated, please use xs_open(XS_OPEN_READONLY) instead
 */
struct xs_handle *xs_daemon_open_readonly(void);

/* Close the connection to the xs daemon.
 * Deprecated, please use xs_close() instead
 */
void xs_daemon_close(struct xs_handle *);

/* Throw away the connection to the xs daemon, for use after fork(). */
void xs_daemon_destroy_postfork(struct xs_handle *);

/* Get contents of a directory.
 * Returns a malloced array: call free() on it after use.
 * Num indicates size.
 */
char **xs_directory(struct xs_handle *h, xs_transaction_t t,
		    const char *path, unsigned int *num);

/* Get the value of a single file, nul terminated.
 * Returns a malloced value: call free() on it after use.
 * len indicates length in bytes, not including terminator.
 */
void *xs_read(struct xs_handle *h, xs_transaction_t t,
	      const char *path, unsigned int *len);

/* Write the value of a single file.
 * Returns false on failure.
 */
bool xs_write(struct xs_handle *h, xs_transaction_t t,
	      const char *path, const void *data, unsigned int len);

/* Create a new directory.
 * Returns false on failure, or success if it already exists.
 */
bool xs_mkdir(struct xs_handle *h, xs_transaction_t t,
	      const char *path);

/* Destroy a file or directory (and children).
 * Returns false on failure, or if it doesn't exist.
 */
bool xs_rm(struct xs_handle *h, xs_transaction_t t,
	   const char *path);

/* Restrict a xenstore handle so that it acts as if it had the
 * permissions of domain @domid.  The handle must currently be
 * using domain 0's credentials.
 *
 * Returns false on failure, in which case the handle continues
 * to use the old credentials, or true on success.
 */
bool xs_restrict(struct xs_handle *h, unsigned domid);

/* Get permissions of node (first element is owner, first perms is "other").
 * Returns malloced array, or NULL: call free() after use.
 */
struct xs_permissions *xs_get_permissions(struct xs_handle *h,
					  xs_transaction_t t,
					  const char *path, unsigned int *num);

/* Set permissions of node (must be owner).
 * Returns false on failure.
 */
bool xs_set_permissions(struct xs_handle *h, xs_transaction_t t,
			const char *path, struct xs_permissions *perms,
			unsigned int num_perms);

/* Watch a node for changes (poll on fd to detect, or call read_watch()).
 * When the node (or any child) changes, fd will become readable.
 * Token is returned when watch is read, to allow matching.
 * Returns false on failure.
 */
bool xs_watch(struct xs_handle *h, const char *path, const char *token);

/* Return the FD to poll on to see if a watch has fired. */
int xs_fileno(struct xs_handle *h);

/* Check for node changes.  On success, returns a non-NULL pointer ret
 * such that ret[0] and ret[1] are valid C strings, namely the
 * triggering path (see docs/misc/xenstore.txt) and the token (from
 * xs_watch).  On error return value is NULL setting errno.
 * 
 * Callers should, after xs_fileno has become readable, repeatedly
 * call xs_check_watch until it returns NULL and sets errno to EAGAIN.
 * (If the fd became readable, xs_check_watch is allowed to make it no
 * longer show up as readable even if future calls to xs_check_watch
 * will return more watch events.)
 *
 * After the caller is finished with the returned information it
 * should be freed all in one go with free(ret).
 */
char **xs_check_watch(struct xs_handle *h);

/* Find out what node change was on (will block if nothing pending).
 * Returns array containing the path and token. Use XS_WATCH_* to access these
 * elements. Call free() after use.
 */
char **xs_read_watch(struct xs_handle *h, unsigned int *num);

/* Remove a watch on a node: implicitly acks any outstanding watch.
 * Returns false on failure (no watch on that node).
 */
bool xs_unwatch(struct xs_handle *h, const char *path, const char *token);

/* Start a transaction: changes by others will not be seen during this
 * transaction, and changes will not be visible to others until end.
 * Returns NULL on failure.
 */
xs_transaction_t xs_transaction_start(struct xs_handle *h);

/* End a transaction.
 * If abandon is true, transaction is discarded instead of committed.
 * Returns false on failure: if errno == EAGAIN, you have to restart
 * transaction.
 */
bool xs_transaction_end(struct xs_handle *h, xs_transaction_t t,
			bool abort);

/* Introduce a new domain.
 * This tells the store daemon about a shared memory page, event channel and
 * store path associated with a domain: the domain uses these to communicate.
 */
bool xs_introduce_domain(struct xs_handle *h,
			 unsigned int domid,
			 unsigned long mfn,
                         unsigned int eventchn); 

/* Set the target of a domain
 * This tells the store daemon that a domain is targetting another one, so
 * it should let it tinker with it.
 */
bool xs_set_target(struct xs_handle *h,
		   unsigned int domid,
		   unsigned int target);

/* Resume a domain.
 * Clear the shutdown flag for this domain in the store.
 */
bool xs_resume_domain(struct xs_handle *h, unsigned int domid);

/* Release a domain.
 * Tells the store domain to release the memory page to the domain.
 */
bool xs_release_domain(struct xs_handle *h, unsigned int domid);

/* Query the home path of a domain.  Call free() after use.
 */
char *xs_get_domain_path(struct xs_handle *h, unsigned int domid);

/* Returns true if child is either equal to parent, or a node underneath
 * parent; or false otherwise.  Done by string comparison, so relative and
 * absolute pathnames never in a parent/child relationship by this
 * definition.  Cannot fail.
 */
bool xs_path_is_subpath(const char *parent, const char *child);

/* Return whether the domain specified has been introduced to xenstored.
 */
bool xs_is_domain_introduced(struct xs_handle *h, unsigned int domid);

/* Only useful for DEBUG versions */
char *xs_debug_command(struct xs_handle *h, const char *cmd,
		       void *data, unsigned int len);

int xs_suspend_evtchn_port(int domid);
#endif /* XENSTORE_H */

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
