/*
 * xenbus.c
 * 
 * xenbus interface to the blocktap.
 * 
 * this handles the top-half of integration with block devices through the
 * store -- the tap driver negotiates the device channel etc, while the
 * userland tap clinet needs to sort out the disk parameters etc.
 * 
 * A. Warfield 2005 Based primarily on the blkback and xenbus driver code.  
 * Comments there apply here...
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <stdarg.h>
#include <errno.h>
#include <xs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include "blktaplib.h"
#include "list.h"

#if 0
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

/* --- Xenstore / Xenbus helpers ---------------------------------------- */
/*
 * These should all be pulled out into the xenstore API.  I'm faulting commands
 * in from the xenbus interface as i need them.
 */


/* Takes tuples of names, scanf-style args, and void **, NULL terminated. */
int xs_gather(struct xs_handle *xs, const char *dir, ...)
{
    va_list ap;
    const char *name;
    char *path;
    int ret = 0;
    
    va_start(ap, dir);
    while (ret == 0 && (name = va_arg(ap, char *)) != NULL) {
        const char *fmt = va_arg(ap, char *);
        void *result = va_arg(ap, void *);
        char *p;
        
        if (asprintf(&path, "%s/%s", dir, name) == -1)
        {
            warn("allocation error in xs_gather!\n");
            ret = ENOMEM;
            break;
        }
        p = xs_read(xs, path, NULL);
        free(path);
        if (p == NULL) {
            ret = ENOENT;
            break;
        }
        if (fmt) {
            if (sscanf(p, fmt, result) == 0)
                ret = EINVAL;
            free(p);
        } else
            *(char **)result = p;
    }
    va_end(ap);
    return ret;
}

/* Single printf and write: returns -errno or 0. */
int xs_printf(struct xs_handle *h, const char *dir, const char *node, 
                  const char *fmt, ...)
{
        char *buf, *path;
        va_list ap;
        int ret;
 
        va_start(ap, fmt);
        ret = vasprintf(&buf, fmt, ap);
        va_end(ap);
 
        asprintf(&path, "%s/%s", dir, node);

        if ((path == NULL) || (buf == NULL))
            return 0;

        ret = xs_write(h, path, buf, strlen(buf)+1);

        free(buf);
        free(path);

        return ret;
}


int xs_exists(struct xs_handle *h, const char *path)
{
    char **d;
    int num;

    d = xs_directory(h, path, &num);
    if (d == NULL)
        return 0;
    free(d);
    return 1;
}



/* This assumes that the domain name we are looking for is unique! */
char *get_dom_domid(struct xs_handle *h, const char *name)
{
    char **e, *val, *domid = NULL;
    int num, i, len;
    char *path;

    e = xs_directory(h, "/local/domain", &num);

    i=0;
    while (i < num) {
        asprintf(&path, "/local/domain/%s/name", e[i]);
        val = xs_read(h, path, &len);
        free(path);
        if (val == NULL)
            continue;
        if (strcmp(val, name) == 0) {
            /* match! */
            asprintf(&path, "/local/domain/%s/domid", e[i]);
            domid = xs_read(h, path, &len);
            free(val);
            free(path);
            break;
        }
        free(val);
        i++;
    }

    free(e);
    return domid;
}

static int strsep_len(const char *str, char c, unsigned int len)
{
    unsigned int i;
    
    for (i = 0; str[i]; i++)
        if (str[i] == c) {
            if (len == 0)
                return i;
            len--;
        }
    return (len == 0) ? i : -ERANGE;
}


/* xenbus watches: */     
/* Register callback to watch this node. */
struct xenbus_watch
{
        struct list_head list;
        char *node;
        void (*callback)(struct xs_handle *h, 
                         struct xenbus_watch *, 
                         const  char *node);
};

static LIST_HEAD(watches);

/* A little paranoia: we don't just trust token. */
static struct xenbus_watch *find_watch(const char *token)
{
    struct xenbus_watch *i, *cmp;
    
    cmp = (void *)strtoul(token, NULL, 16);
    
    list_for_each_entry(i, &watches, list)
        if (i == cmp)
            return i;
    return NULL;
}

/* Register callback to watch this node. like xs_watch, return 0 on failure */
int register_xenbus_watch(struct xs_handle *h, struct xenbus_watch *watch)
{
    /* Pointer in ascii is the token. */
    char token[sizeof(watch) * 2 + 1];
    int er;
    
    sprintf(token, "%lX", (long)watch);
    if (find_watch(token)) 
    {
        warn("watch collision!");
        return -EINVAL;
    }
    
    er = xs_watch(h, watch->node, token);
    if (er != 0) {
        list_add(&watch->list, &watches);
    } 
        
    return er;
}

int unregister_xenbus_watch(struct xs_handle *h, struct xenbus_watch *watch)
{
    char token[sizeof(watch) * 2 + 1];
    int er;
    
    sprintf(token, "%lX", (long)watch);
    if (!find_watch(token))
    {
        warn("no such watch!");
        return -EINVAL;
    }
    
    
    er = xs_unwatch(h, watch->node, token);
    list_del(&watch->list);
    
    if (er == 0)
        warn("XENBUS Failed to release watch %s: %i",
             watch->node, er);
    return 0;
}

/* Re-register callbacks to all watches. */
void reregister_xenbus_watches(struct xs_handle *h)
{
    struct xenbus_watch *watch;
    char token[sizeof(watch) * 2 + 1];
    
    list_for_each_entry(watch, &watches, list) {
        sprintf(token, "%lX", (long)watch);
        xs_watch(h, watch->node, token);
    }
}

/* based on watch_thread() */
int xs_fire_next_watch(struct xs_handle *h)
{
    char **res;
    char *token;
    char *node = NULL;
    struct xenbus_watch *w;
    int er;
    unsigned int num;

    res = xs_read_watch(h, &num);
    if (res == NULL) 
        return -EAGAIN; /* in O_NONBLOCK, read_watch returns 0... */

    node  = res[XS_WATCH_PATH];
    token = res[XS_WATCH_TOKEN];

    w = find_watch(token);
    if (!w)
    {
        warn("unregistered watch fired");
        goto done;
    }
    w->callback(h, w, node);

 done:
    free(res);
    return 1;
}




/* ---------------------------------------------------------------------- */

struct backend_info
{
    /* our communications channel */
    blkif_t *blkif;
    
    long int frontend_id;
    long int pdev;
    long int readonly;
    
    /* watch back end for changes */
    struct xenbus_watch backend_watch;
    char *backpath;

    /* watch front end for changes */
    struct xenbus_watch watch;
    char *frontpath;

    struct list_head list;
};

static LIST_HEAD(belist);

static struct backend_info *be_lookup_be(const char *bepath)
{
    struct backend_info *be;

    list_for_each_entry(be, &belist, list)
        if (strcmp(bepath, be->backpath) == 0)
            return be;
    return (struct backend_info *)NULL;
}

static int be_exists_be(const char *bepath)
{
    return ( be_lookup_be(bepath) != NULL );
}

static struct backend_info *be_lookup_fe(const char *fepath)
{
    struct backend_info *be;

    list_for_each_entry(be, &belist, list)
        if (strcmp(fepath, be->frontpath) == 0)
            return be;
    return (struct backend_info *)NULL;
}

static int backend_remove(struct xs_handle *h, struct backend_info *be)
{
    /* Turn off watches. */
    if (be->watch.node)
        unregister_xenbus_watch(h, &be->watch);
    if (be->backend_watch.node)
        unregister_xenbus_watch(h, &be->backend_watch);

    /* Unhook from be list. */
    list_del(&be->list);

    /* Free everything else. */
    if (be->blkif)
        free_blkif(be->blkif);
    free(be->frontpath);
    free(be->backpath);
    free(be);
    return 0;
}

static void frontend_changed(struct xs_handle *h, struct xenbus_watch *w, 
                     const char *fepath_im)
{
    struct backend_info *be;
    char *fepath = NULL;
    int er;

    be = be_lookup_fe(w->node);
    if (be == NULL)
    {
        warn("frontend changed called for nonexistent backend! (%s)", fepath);
        goto fail;
    }
    
    /* If other end is gone, delete ourself. */
    if (w->node && !xs_exists(h, be->frontpath)) {
        DPRINTF("DELETING BE: %s\n", be->backpath);
        backend_remove(h, be);
        return;
    }

    if (be->blkif == NULL || (be->blkif->state == CONNECTED))
        return;

    /* Supply the information about the device the frontend needs */
    er = xs_transaction_start(h, be->backpath);
    if (er == 0) {
        warn("starting transaction");
        goto fail;
    }
    
    er = xs_printf(h, be->backpath, "sectors", "%lu",
			    be->blkif->ops->get_size(be->blkif));
    if (er == 0) {
        warn("writing sectors");
        goto fail;
    }
    
    er = xs_printf(h, be->backpath, "info", "%u",
			    be->blkif->ops->get_info(be->blkif));
    if (er == 0) {
        warn("writing info");
        goto fail;
    }
    
    er = xs_printf(h, be->backpath, "sector-size", "%lu",
			    be->blkif->ops->get_secsize(be->blkif));
    if (er == 0) {
        warn("writing sector-size");
        goto fail;
    }

    be->blkif->state = CONNECTED;

    xs_transaction_end(h, 0);

    return;

 fail:
    free(fepath);
}


static void backend_changed(struct xs_handle *h, struct xenbus_watch *w, 
                     const char *bepath_im)
{
    struct backend_info *be;
    char *path = NULL, *p;
    int len, er;
    long int pdev = 0, handle;

    be = be_lookup_be(w->node);
    if (be == NULL)
    {
        warn("backend changed called for nonexistent backend! (%s)", w->node);
        goto fail;
    }
    
    er = xs_gather(h, be->backpath, "physical-device", "%li", &pdev, NULL);
    if (er != 0) 
        goto fail;

    if (be->pdev && be->pdev != pdev) {
        warn("changing physical-device not supported");
        goto fail;
    }
    be->pdev = pdev;

    asprintf(&path, "%s/%s", w->node, "read-only");
    if (xs_exists(h, path))
        be->readonly = 1;

    if (be->blkif == NULL) {
        /* Front end dir is a number, which is used as the handle. */
        p = strrchr(be->frontpath, '/') + 1;
        handle = strtoul(p, NULL, 0);

        be->blkif = alloc_blkif(be->frontend_id);
        if (be->blkif == NULL) 
            goto fail;

        er = blkif_init(be->blkif, handle, be->pdev, be->readonly);
        if (er) 
            goto fail;

        DPRINTF("[BECHG]: ADDED A NEW BLKIF (%s)\n", w->node);

        /* Pass in NULL node to skip exist test. */
        frontend_changed(h, &be->watch, NULL);
    }

 fail:
    free(path);
}

static void blkback_probe(struct xs_handle *h, struct xenbus_watch *w, 
                         const char *bepath_im)
{
	struct backend_info *be = NULL;
	char *frontend = NULL, *bepath = NULL;
	int er, len;

        bepath = strdup(bepath_im);
        if (!bepath)
            return;
        len = strsep_len(bepath, '/', 6);
        if (len < 0) 
            goto free_be;
        
        bepath[len] = '\0'; /*truncate the passed-in string with predjudice. */

	be = malloc(sizeof(*be));
	if (!be) {
		warn("allocating backend structure");
		goto free_be;
	}
	memset(be, 0, sizeof(*be));

	frontend = NULL;
	er = xs_gather(h, bepath,
                        "frontend-id", "%li", &be->frontend_id,
                        "frontend", NULL, &frontend,
                        NULL);
	if (er)
		goto free_be;

	if (strlen(frontend) == 0 || !xs_exists(h, frontend)) {
            /* If we can't get a frontend path and a frontend-id,
             * then our bus-id is no longer valid and we need to
             * destroy the backend device.
             */
            DPRINTF("No frontend (%s)\n", frontend);
            goto free_be;
	}

        /* Are we already tracking this device? */
        if (be_exists_be(bepath))
            goto free_be;

        be->backpath = bepath;
	be->backend_watch.node = be->backpath;
	be->backend_watch.callback = backend_changed;
	er = register_xenbus_watch(h, &be->backend_watch);
	if (er == 0) {
		be->backend_watch.node = NULL;
		warn("error adding backend watch on %s", bepath);
		goto free_be;
	}

	be->frontpath = frontend;
	be->watch.node = be->frontpath;
	be->watch.callback = frontend_changed;
	er = register_xenbus_watch(h, &be->watch);
	if (er == 0) {
		be->watch.node = NULL;
		warn("adding frontend watch on %s", be->frontpath);
		goto free_be;
	}

        list_add(&be->list, &belist);

        DPRINTF("[PROBE]: ADDED NEW DEVICE (%s)\n", bepath_im);

	backend_changed(h, &be->backend_watch, bepath);
	return;

 free_be:
	if (be && (be->backend_watch.node))
            unregister_xenbus_watch(h, &be->backend_watch);
        free(frontend);
        free(bepath);
	free(be);
	return;
}


int add_blockdevice_probe_watch(struct xs_handle *h, const char *domname)
{
    char *domid, *path;
    struct xenbus_watch *vbd_watch;
    int er;

    domid = get_dom_domid(h, domname);

    DPRINTF("%s: %s\n", domname, (domid != NULL) ? domid : "[ not found! ]");

    asprintf(&path, "/local/domain/%s/backend/vbd", domid);
    if (path == NULL) 
        return -ENOMEM;

    vbd_watch = (struct xenbus_watch *)malloc(sizeof(struct xenbus_watch));
    vbd_watch->node     = path;
    vbd_watch->callback = blkback_probe;
    er = register_xenbus_watch(h, vbd_watch);
    if (er == 0) {
        warn("Error adding vbd probe watch %s", path);
        return -EINVAL;
    }

    return 0;
}
