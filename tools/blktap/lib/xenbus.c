/*
 * xenbus.c
 * 
 * xenbus interface to the blocktap.
 * 
 * this handles the top-half of integration with block devices through the
 * store -- the tap driver negotiates the device channel etc, while the
 * userland tap client needs to sort out the disk parameters etc.
 * 
 * (c) 2005 Andrew Warfield and Julian Chesterfield
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <printf.h>
#include <string.h>
#include <err.h>
#include <stdarg.h>
#include <errno.h>
#include <xs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/time.h>
#include "blktaplib.h"
#include "list.h"
#include "xs_api.h"

#if 0
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

struct backend_info
{
	/* our communications channel */
	blkif_t *blkif;
	
	long int frontend_id;
	long int pdev;
	long int readonly;
	
	char *backpath;
	char *frontpath;
	
	struct list_head list;
};

static LIST_HEAD(belist);

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

static int get_be_id(const char *str)
{
	int len,end;
	const char *ptr;
	char *tptr, num[10];
	
	len = strsep_len(str, '/', 6);
	end = strlen(str);
	if( (len < 0) || (end < 0) ) return -1;
	
	ptr = str + len + 1;
	strncpy(num, ptr, end - len);
	tptr = num + (end - (len + 1));
	*tptr = '\0';

	return atoi(num);
}

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
	return (be_lookup_be(bepath) != NULL);
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
	/* Unhook from be list. */
	list_del(&be->list);

	/* Free everything else. */
	if (be->blkif) {
		DPRINTF("Freeing blkif dev [%d]\n",be->blkif->devnum);
		free_blkif(be->blkif);
	}
	if (be->frontpath)
		free(be->frontpath);
	if (be->backpath)
		free(be->backpath);
	free(be);
	return 0;
}

static void ueblktap_setup(struct xs_handle *h, char *bepath)
{
	struct backend_info *be;
	char *path = NULL, *p,*dev;
	int len, er, deverr;
	long int pdev = 0, handle;
	blkif_info_t *blk;
	
	be = be_lookup_be(bepath);
	if (be == NULL)
	{
		DPRINTF("ERROR: backend changed called for nonexistent "
			"backend! (%s)\n", bepath);
		goto fail;
	}

	deverr = xs_gather(h, bepath, "physical-device", "%li", &pdev, NULL);
	if (!deverr) {
		DPRINTF("pdev set to %ld\n",pdev);
		if (be->pdev && be->pdev != pdev) {
			DPRINTF("changing physical-device not supported");
			goto fail;
		}
		be->pdev = pdev;
	}

	/* Check to see if device is to be opened read-only. */
	deverr = xs_gather(h, bepath, "mode", NULL, &path, NULL);
	if (deverr) {
		DPRINTF("ERROR: could not find read/write mode\n");
		goto fail;
	} else if (path[0] == 'r')
		be->readonly = 1;

	if (be->blkif == NULL) {
		/* Front end dir is a number, which is used as the handle. */
		p = strrchr(be->frontpath, '/') + 1;
		handle = strtoul(p, NULL, 0);

		be->blkif = alloc_blkif(be->frontend_id);
		if (be->blkif == NULL)
			goto fail;

		be->blkif->be_id = get_be_id(bepath);
		
		/* Insert device specific info, */
		blk = malloc(sizeof(blkif_info_t));
		if (!blk) {
			DPRINTF("Out of memory - blkif_info_t\n");
			goto fail;
		}
		er = xs_gather(h, bepath, "params", NULL, &blk->params, NULL);
		if (er)
			goto fail;
		be->blkif->info = blk;
		
		if (deverr) {
			/*Dev number was not available, try to set manually*/
			pdev = convert_dev_name_to_num(blk->params);
			be->pdev = pdev;
		}

		er = blkif_init(be->blkif, handle, be->pdev, be->readonly);
		if (er != 0) {
			DPRINTF("Unable to open device %s\n",blk->params);
			goto fail;
		}

		DPRINTF("[BECHG]: ADDED A NEW BLKIF (%s)\n", bepath);
	}

	/* Supply the information about the device to xenstore */
	er = xs_printf(h, be->backpath, "sectors", "%llu",
			be->blkif->ops->get_size(be->blkif));

	if (er == 0) {
		DPRINTF("ERROR: Failed writing sectors");
		goto fail;
	}

	er = xs_printf(h, be->backpath, "sector-size", "%lu",
			be->blkif->ops->get_secsize(be->blkif));

	if (er == 0) {
		DPRINTF("ERROR: Failed writing sector-size");
		goto fail;
	}

	er = xs_printf(h, be->backpath, "info", "%u",
			be->blkif->ops->get_info(be->blkif));

	if (er == 0) {
		DPRINTF("ERROR: Failed writing info");
		goto fail;
	}

	be->blkif->state = CONNECTED;
	DPRINTF("[SETUP] Complete\n\n");
	goto close;
	
fail:
	if ( (be != NULL) && (be->blkif != NULL) ) 
		backend_remove(h, be);
close:
	if (path)
		free(path);
	return;
}

/**
 * Xenstore watch callback entry point. This code replaces the hotplug scripts,
 * and as soon as the xenstore backend driver entries are created, this script
 * gets called.
 */
static void ueblktap_probe(struct xs_handle *h, struct xenbus_watch *w, 
			   const char *bepath_im)
{
	struct backend_info *be = NULL;
	char *frontend = NULL, *bepath = NULL, *p;
	int er, len;
	blkif_t *blkif;
	
	
	bepath = strdup(bepath_im);
	
	if (!bepath) {
		DPRINTF("No path\n");
		return;
	}
	
	/*
	 *asserts that xenstore structure is always 7 levels deep
	 *e.g. /local/domain/0/backend/vbd/1/2049
	 */
	len = strsep_len(bepath, '/', 7);
	if (len < 0) 
		goto free_be;
	bepath[len] = '\0';
	
	be = malloc(sizeof(*be));
	if (!be) {
		DPRINTF("ERROR: allocating backend structure\n");
		goto free_be;
	}
	memset(be, 0, sizeof(*be));
	frontend = NULL;

	er = xs_gather(h, bepath,
		       "frontend-id", "%li", &be->frontend_id,
		       "frontend", NULL, &frontend,
		       NULL);

	if (er) {
		/*
		 *Unable to find frontend entries, 
		 *bus-id is no longer valid
		 */
		DPRINTF("ERROR: Frontend-id check failed, removing backend: "
			"[%s]\n",bepath);

		/**
		 * BE info should already exist, 
		 * free new mem and find old entry
		 */
		free(be);
		be = be_lookup_be(bepath);
		if ( (be != NULL) && (be->blkif != NULL) ) 
			backend_remove(h, be);
		else goto free_be;
		if (bepath)
			free(bepath);
		return;
	}
	
	/* Are we already tracking this device? */
	if (be_exists_be(bepath))
		goto free_be;
	
	be->backpath = bepath;
	be->frontpath = frontend;
	
	list_add(&be->list, &belist);
	
	DPRINTF("[PROBE]\tADDED NEW DEVICE (%s)\n", bepath);
	DPRINTF("\tFRONTEND (%s),(%ld)\n", frontend,be->frontend_id);
	
	ueblktap_setup(h, bepath);	
	return;
	
 free_be:
	if (frontend)
		free(frontend);
	if (bepath)
		free(bepath);
	if (be) 
		free(be);
}

/**
 *We set a general watch on the backend vbd directory
 *ueblktap_probe is called for every update
 *Our job is to monitor for new entries. As they 
 *are created, we initalise the state and attach a disk.
 */

int add_blockdevice_probe_watch(struct xs_handle *h, const char *domid)
{
	char *path;
	struct xenbus_watch *vbd_watch;
	
	asprintf(&path, "/local/domain/%s/backend/tap", domid);
	if (path == NULL) 
		return -ENOMEM;
	
	vbd_watch = (struct xenbus_watch *)malloc(sizeof(struct xenbus_watch));
	if (!vbd_watch) {
		DPRINTF("ERROR: unable to malloc vbd_watch [%s]\n", path);
		return -EINVAL;
	}	
	vbd_watch->node     = path;
	vbd_watch->callback = ueblktap_probe;
	if (register_xenbus_watch(h, vbd_watch) != 0) {
		DPRINTF("ERROR: adding vbd probe watch %s\n", path);
		return -EINVAL;
	}
	return 0;
}

/* Asynch callback to check for /local/domain/<DOMID>/name */
void check_dom(struct xs_handle *h, struct xenbus_watch *w, 
	       const char *bepath_im)
{
	char *domid;

	domid = get_dom_domid(h);
	if (domid == NULL)
		return;

	add_blockdevice_probe_watch(h, domid);
	free(domid);
	unregister_xenbus_watch(h, w);
}

/* We must wait for xend to register /local/domain/<DOMID> */
int watch_for_domid(struct xs_handle *h)
{
	struct xenbus_watch *domid_watch;
	char *path = NULL;

	asprintf(&path, "/local/domain");
	if (path == NULL) 
		return -ENOMEM;

	domid_watch = malloc(sizeof(struct xenbus_watch));
	if (domid_watch == NULL) {
		DPRINTF("ERROR: unable to malloc domid_watch [%s]\n", path);
		return -EINVAL;
	}	

	domid_watch->node     = path;
	domid_watch->callback = check_dom;

	if (register_xenbus_watch(h, domid_watch) != 0) {
		DPRINTF("ERROR: adding vbd probe watch %s\n", path);
		return -EINVAL;
	}

	DPRINTF("Set async watch for /local/domain\n");

	return 0;
}

int setup_probe_watch(struct xs_handle *h)
{
	char *domid;
	int ret;
	
	domid = get_dom_domid(h);
	if (domid == NULL)
		return watch_for_domid(h);

	ret = add_blockdevice_probe_watch(h, domid);
	free(domid);
	return ret;
}
