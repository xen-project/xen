/*
 * tools/blktap_user/blkif.c
 * 
 * The blkif interface for blktap.  A blkif describes an in-use virtual disk.
 * (c) 2005 Andrew Warfield and Julian Chesterfield
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
#include <errno.h>
#include <string.h>
#include <err.h>
#include <unistd.h>

#include "blktaplib.h"

#if 0
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

#define BLKIF_HASHSZ 1024
#define BLKIF_HASH(_d,_h) (((int)(_d)^(int)(_h))&(BLKIF_HASHSZ-1))

static blkif_t      *blkif_hash[BLKIF_HASHSZ];

blkif_t *blkif_find_by_handle(domid_t domid, unsigned int handle)
{
	blkif_t *blkif = blkif_hash[BLKIF_HASH(domid, handle)];
	while ( (blkif != NULL) && 
		((blkif->domid != domid) || (blkif->handle != handle)) )
		blkif = blkif->hash_next;
	return blkif;
}

blkif_t *alloc_blkif(domid_t domid)
{
	blkif_t *blkif;
	DPRINTF("Alloc_blkif called [%d]\n",domid);
	blkif = (blkif_t *)malloc(sizeof(blkif_t));
	if (!blkif)
		return NULL;
	memset(blkif, 0, sizeof(*blkif));
	blkif->domid = domid;
	blkif->devnum = -1;
	return blkif;
}

/*Controller callbacks*/
static int (*new_devmap_hook)(blkif_t *blkif) = NULL;
void register_new_devmap_hook(int (*fn)(blkif_t *blkif))
{
	new_devmap_hook = fn;
}

static int (*new_unmap_hook)(blkif_t *blkif) = NULL;
void register_new_unmap_hook(int (*fn)(blkif_t *blkif))
{
	new_unmap_hook = fn;
}

static int (*new_blkif_hook)(blkif_t *blkif) = NULL;
void register_new_blkif_hook(int (*fn)(blkif_t *blkif))
{
	new_blkif_hook = fn;
}

int blkif_init(blkif_t *blkif, long int handle, long int pdev, 
               long int readonly)
{
	domid_t domid;
	blkif_t **pblkif;
	int devnum;
	
	if (blkif == NULL)
		return -EINVAL;
	
	domid = blkif->domid;
	blkif->handle   = handle;
	blkif->pdev     = pdev;
	blkif->readonly = readonly;
	
	/*
	 * Call out to the new_blkif_hook. 
	 * The tap application should define this,
	 * and it should return having set blkif->ops
	 * 
	 */
	if (new_blkif_hook == NULL)
	{
		DPRINTF("Probe detected a new blkif, but no new_blkif_hook!");
		return -1;
	}
	if (new_blkif_hook(blkif)!=0) {
		DPRINTF("BLKIF: Image open failed\n");
		return -1;
	}
	
	/* Now wire it in. */
	pblkif = &blkif_hash[BLKIF_HASH(domid, handle)];
	DPRINTF("Created hash entry: %d [%d,%ld]\n", 
		BLKIF_HASH(domid, handle), domid, handle);
	
	while ( *pblkif != NULL )
	{
		if ( ((*pblkif)->domid == domid) && 
		     ((*pblkif)->handle == handle) )
		{
			DPRINTF("Could not create blkif: already exists\n");
			return -1;
		}
		pblkif = &(*pblkif)->hash_next;
	}
	blkif->hash_next = NULL;
	*pblkif = blkif;
	
	if (new_devmap_hook == NULL)
	{
		DPRINTF("Probe setting up new blkif but no devmap hook!");
		return -1;
	}
	
	devnum = new_devmap_hook(blkif);
	if (devnum == -1)
		return -1;
	blkif->devnum = devnum;
	
	return 0;
}

void free_blkif(blkif_t *blkif)
{
	blkif_t **pblkif, *curs;
	image_t *image;
	
	pblkif = &blkif_hash[BLKIF_HASH(blkif->domid, blkif->handle)];
	while ( (curs = *pblkif) != NULL )
	{
		if ( blkif == curs )
		{
			*pblkif = curs->hash_next;
		}
		pblkif = &curs->hash_next;
	}
	if (blkif != NULL) {
		if ((image=(image_t *)blkif->prv)!=NULL) {
			free(blkif->prv);
		}
		if (blkif->info!=NULL) {
			free(blkif->info);
		}
		if (new_unmap_hook != NULL) new_unmap_hook(blkif);
		free(blkif);
	}
}

void __init_blkif(void)
{    
	memset(blkif_hash, 0, sizeof(blkif_hash));
}
