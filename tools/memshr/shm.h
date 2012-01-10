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
#ifndef __SHM_H__
#define __SHM_H__

#include <pthread.h>
#include <unistd.h>

#define MAX_NAME_LEN  1000

typedef struct vbd_image_info {
    char     file[MAX_NAME_LEN];
    int      ref_cnt;
    uint16_t next;
    uint16_t prev;
} vbd_image_info_t;

#define MAX_NR_VBD_IMAGES   4096
 
typedef struct shared_memshr_info {
    unsigned long    magic;
    pthread_mutex_t  lock;
    int              fgprtshr_hash_inited;
    int              blockshr_hash_inited;
    vbd_image_info_t vbd_images[MAX_NR_VBD_IMAGES];
} shared_memshr_info_t;

shared_memshr_info_t * shm_shared_info_open(int unlink);
struct fgprtshr_hash * shm_fgprtshr_hash_open(int unlink);
struct blockshr_hash * shm_blockshr_hash_open(int unlink);
uint16_t shm_vbd_image_get(const char* file, vbd_image_info_t *vbd_imgs);
void     shm_vbd_image_put(uint16_t memshr_id, vbd_image_info_t *vbd_imgs);

#endif /* __SHM_H__ */
