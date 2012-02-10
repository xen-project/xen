/******************************************************************************
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Grzegorz Milos)
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
#include <inttypes.h>

#include "memshr.h"
#include "memshr-priv.h"
#include "bidir-hash.h"
#include "shm.h"
#include "bidir-daemon.h"

typedef struct {
    int     enabled;
    domid_t domid;
    xc_interface *xc_handle;
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
    
    bidir_daemon_initialize(memshr.blks);
}


void memshr_vbd_initialize(void)
{
    xc_interface *xc_handle;

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

    if((xc_handle = xc_interface_open(0,0,0)) == 0)
    {
        DPRINTF("Failed to open XC interface.\n");
        return;
    }

    vbd_info.xc_handle = xc_handle;
    vbd_info.enabled = 1;
}

uint16_t memshr_vbd_image_get(const char* file)
{
    uint16_t id;

    if(pthread_mutex_lock(&SHARED_INFO->lock)) goto error_out;
    id = shm_vbd_image_get(file, SHARED_INFO->vbd_images);
    if(pthread_mutex_unlock(&SHARED_INFO->lock)) goto error_out;

    return id;
error_out:
    return 0;    
}

void memshr_vbd_image_put(uint16_t memshr_id)
{
    if(pthread_mutex_lock(&SHARED_INFO->lock)) return;
    shm_vbd_image_put(memshr_id, SHARED_INFO->vbd_images);
    if(pthread_mutex_unlock(&SHARED_INFO->lock)) return;
}
    
int memshr_vbd_issue_ro_request(char *buf,
                                grant_ref_t gref,
                                uint16_t file_id,
                                uint64_t sec, 
                                int secs,
                                share_tuple_t *hnd)
{
    vbdblk_t blk;
    share_tuple_t source_st, client_st;
    uint64_t c_hnd;
    int ret;

    *hnd = (share_tuple_t){ 0, 0, 0 };
    if(!vbd_info.enabled) 
        return -1;

    if(secs != 8)
        return -2;

    /* Nominate the granted page for sharing */
    ret = xc_memshr_nominate_gref(vbd_info.xc_handle,
                                  vbd_info.domid,
                                  gref,
                                  &c_hnd);
    /* If page couldn't be made sharable, we cannot do anything about it */
    if(ret != 0)
        return -3;

    client_st = (share_tuple_t){ vbd_info.domid, gref, c_hnd };
    *hnd = client_st;

    /* Check if we've read matching disk block previously */
    blk.sec     = sec;
    blk.disk_id = file_id;
    if(blockshr_block_lookup(memshr.blks, blk, &source_st) > 0)
    {
        ret = xc_memshr_share_grefs(vbd_info.xc_handle, source_st.domain, source_st.frame, 
                                    source_st.handle, vbd_info.domid, gref, c_hnd);
        if(!ret) return 0;
        /* Handles failed to be shared => at least one of them must be invalid,
           remove the relevant ones from the map */
        switch(ret)
        {
            case XENMEM_SHARING_OP_S_HANDLE_INVALID:
                ret = blockshr_shrhnd_remove(memshr.blks, source_st, NULL);
                if(ret) DPRINTF("Could not rm invl s_hnd: %u %"PRId64" %"PRId64"\n", 
                                    source_st.domain, source_st.frame, source_st.handle);
                break;
            case XENMEM_SHARING_OP_C_HANDLE_INVALID:
                ret = blockshr_shrhnd_remove(memshr.blks, client_st, NULL);
                if(ret) DPRINTF("Could not rm invl c_hnd: %u %"PRId64" %"PRId64"\n", 
                                    client_st.domain, client_st.frame, client_st.handle);
                break;
            default:
                break;
        }
        return -5;
    }

    return -4;
}

void memshr_vbd_complete_ro_request(share_tuple_t hnd,
                                    uint16_t file_id, 
                                    uint64_t sec, 
                                    int secs)
{
    vbdblk_t blk;
    
    if(!vbd_info.enabled) 
        return;

    if(secs != 8)
        return;

    blk.sec     = sec;
    blk.disk_id = file_id;
    if(blockshr_insert(memshr.blks, blk, hnd) < 0)
        DPRINTF("Could not insert block hint into hash.\n");
}
