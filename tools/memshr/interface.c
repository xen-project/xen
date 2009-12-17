/******************************************************************************
 *
 * Copyright (c) 2009 Citrix (R&D) Inc. (Grzegorz Milos)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <string.h>

#include "memshr-priv.h"
#include "shm.h"

typedef struct {
    int     enabled;
    domid_t domid;
} memshr_vbd_info_t;

memshr_vbd_info_t vbd_info = {0, DOMID_INVALID};

typedef struct {
    struct shared_memshr_info *shared_info;
    struct fgprtshr_hash      *fgprts;
    struct blockshr_hash      *blks;
} private_memshr_info_t;

private_memshr_info_t memshr;

#define SHARED_INFO  (memshr.shared_info)

void memshr_set_domid(int domid)
{
    vbd_info.domid = domid;
}

void memshr_daemon_initialize(void)
{
    void *shm_base_addr;
    struct fgprtshr_hash *h;

    memset(&memshr, 0, sizeof(private_memshr_info_t));

    if((SHARED_INFO = shm_shared_info_open(1)) == NULL)
    {
        DPRINTF("Failed to init shared info.\n");
        return;
    }

    if((memshr.fgprts = shm_fgprtshr_hash_open(1)) == NULL) 
    {
        DPRINTF("Failed to init fgprtshr hash.\n");
        return;
    }
    memshr.shared_info->fgprtshr_hash_inited = 1;

    if((memshr.blks = shm_blockshr_hash_open(1)) == NULL) 
    {
        DPRINTF("Failed to init blockshr hash.\n");
        return;
    }
    memshr.shared_info->blockshr_hash_inited = 1;
}


void memshr_vbd_initialize(void)
{
    memset(&memshr, 0, sizeof(private_memshr_info_t));

    if((SHARED_INFO = shm_shared_info_open(0)) == NULL)
    {
        DPRINTF("Failed to open shared info.\n");
        return;
    }

    if(!SHARED_INFO->fgprtshr_hash_inited)
    {
        DPRINTF("fgprtshr hash not inited.\n");
        return;
    }

    if((memshr.fgprts = shm_fgprtshr_hash_open(0)) == NULL)
    {
        DPRINTF("Failed to open fgprtshr_hash.\n");
        return;
    }

    if((memshr.blks = shm_blockshr_hash_open(0)) == NULL)
    {
        DPRINTF("Failed to open blockshr_hash.\n");
        return;
    }

    if(vbd_info.domid == DOMID_INVALID)
        return;

    vbd_info.enabled = 1;
}

