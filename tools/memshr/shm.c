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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "memshr-priv.h"
#include "bidir-hash.h"
#include "shm.h"

#define MEMSHR_INFO_SHM_FILE  "/memshr-info"
#define MEMSHR_INFO_MAGIC     0x15263748 

#define FGPRT_HASH_SHM_FILE "/blktap-fgprts"
#define FGPRT_HASH_PAGES    10000

#define BLOCK_HASH_SHM_FILE "/blktap-blks"
#define BLOCK_HASH_PAGES    10000

typedef struct shm_area {
    void*  base_addr;
    size_t size;
    int    fd;
} shm_area_t;

typedef struct {
    struct shm_area shared_info_area;
    struct shm_area fgprts_area;
    struct shm_area blocks_area;
} private_shm_info_t;

private_shm_info_t shm_info;



static int shm_area_open(const char *file, size_t size, int unlink, shm_area_t *shma)
{ 
    /* TODO: If blktapctrl can be restarted while system is running, this needs
     * to be cleverer */
    if(unlink) shm_unlink(file);

    shma->size = size;
    shma->fd = shm_open(file,
                        (O_CREAT | O_RDWR),
                        (S_IREAD | S_IWRITE));

    if(shma->fd < 0) return -1;

    if(ftruncate(shma->fd, size) < 0) return -2;

    shma->base_addr = mmap(NULL, 
                      size,
                      PROT_READ | PROT_WRITE, 
                      MAP_SHARED,
                      shma->fd,
                      0);
    
    if(shma->base_addr == MAP_FAILED) return -2;

    return 0;
}

static void shm_area_close(shm_area_t *shma)
{
    munmap(shma->base_addr, shma->size);
    close(shma->fd);
}


shared_memshr_info_t * shm_shared_info_open(int unlink)
{
    shared_memshr_info_t *shared_info;
    pthread_mutexattr_t  lock_attr;
    int nr_pages, i;

    nr_pages = (sizeof(shared_memshr_info_t) >> XC_PAGE_SHIFT) + 1;
    if(shm_area_open(MEMSHR_INFO_SHM_FILE, 
                     nr_pages * XC_PAGE_SIZE,
                     unlink, 
                     &(shm_info.shared_info_area)) < 0)
    {
        DPRINTF("Failed to open shma for shared info.\n");
        return NULL;
    }
    shared_info = (shared_memshr_info_t *)
                             shm_info.shared_info_area.base_addr;
    if(unlink)
    {
        memset(shared_info, 0, sizeof(shared_memshr_info_t));
        if(pthread_mutexattr_init(&lock_attr) ||
           pthread_mutexattr_setpshared(&lock_attr, PTHREAD_PROCESS_SHARED) ||
           pthread_mutex_init(&shared_info->lock, &lock_attr) ||
           pthread_mutexattr_destroy(&lock_attr))
        {
            DPRINTF("Failed to init shared info lock.\n");
            return NULL;
        }
        strcpy(shared_info->vbd_images[0].file, "list-head");
        for(i=1; i<MAX_NR_VBD_IMAGES; i++)
        {
            shared_info->vbd_images[i].next = i; 
            shared_info->vbd_images[i].prev = i; 
        }
        shared_info->magic = MEMSHR_INFO_MAGIC;
    } 
    else
    if(shared_info->magic != MEMSHR_INFO_MAGIC)
    {
        DPRINTF("Incorrect magic in shared info.\n");
        return NULL;
    }
    
    return shared_info;
}


struct fgprtshr_hash * shm_fgprtshr_hash_open(int unlink)
{
    struct fgprtshr_hash *h;
    if(shm_area_open(FGPRT_HASH_SHM_FILE, 
                     FGPRT_HASH_PAGES * XC_PAGE_SIZE,
                     unlink, 
                     &(shm_info.fgprts_area)) < 0)
    {
        DPRINTF("Failed to init shma for fgprtshr_hash.\n");
        return NULL;
    }

    if(unlink)
    {
        h = fgprtshr_shm_hash_init(
                     (unsigned long) shm_info.fgprts_area.base_addr, 
                     FGPRT_HASH_PAGES * XC_PAGE_SIZE);
    } else
    {
        h = fgprtshr_shm_hash_get(
                     (unsigned long) shm_info.fgprts_area.base_addr); 
    }
        
    return h;
} 

struct blockshr_hash * shm_blockshr_hash_open(int unlink)
{
    struct blockshr_hash *h;
    if(shm_area_open(BLOCK_HASH_SHM_FILE, 
                     BLOCK_HASH_PAGES * XC_PAGE_SIZE,
                     unlink, 
                     &(shm_info.blocks_area)) < 0)
    {
        DPRINTF("Failed to init shma for blockshr_hash.\n");
        return NULL;
    }

    if(unlink)
    {
        h = blockshr_shm_hash_init(
                     (unsigned long) shm_info.blocks_area.base_addr, 
                     BLOCK_HASH_PAGES * XC_PAGE_SIZE);
    } else
    {
        h = blockshr_shm_hash_get(
                     (unsigned long) shm_info.blocks_area.base_addr); 
    }
        
    return h;
} 

uint16_t shm_vbd_image_get(const char* file, vbd_image_info_t *vbd_imgs)
{
    vbd_image_info_t *img, *next_img;
    int i, img_id;

    /* Try to find the file in the existing list first */ 
    img = vbd_imgs;
    while(img->next != 0)
    {
        img = vbd_imgs + img->next;
        if(strncmp(img->file, file, MAX_NAME_LEN) == 0)
        {
            img->ref_cnt++;
            return (uint16_t)(img - vbd_imgs); 
        }
    }
    
    /* Couldn't find an existing entry. We need to add one. Find empty slot */ 
    for(i=1; i<MAX_NR_VBD_IMAGES; i++)
    {
        img = vbd_imgs + i;
        if((img->next == i) && (img->prev == i))
            break;
    }
    /* No entries left! */
    if(i == MAX_NR_VBD_IMAGES)
    {
        DPRINTF("No space in vbds table.\n");
        return 0;
    }
    if(strlen(file) > MAX_NAME_LEN - 1)
    {
        DPRINTF("Filename: %s too long (>%d).\n", file, MAX_NAME_LEN - 1);
        return 0; 
    }
    /* Init the entry */
    img_id = (img - vbd_imgs);
    next_img = vbd_imgs + vbd_imgs[0].next;
    strcpy(img->file, file);
    img->ref_cnt = 1;
    img->next = vbd_imgs[0].next;
    img->prev = 0;
    next_img->prev = img_id;
    vbd_imgs[0].next = img_id;

    return img_id;
}


void shm_vbd_image_put(uint16_t memshr_id, vbd_image_info_t *vbd_imgs)
{
    vbd_image_info_t *img, *next_img, *prev_img;
    
    img = vbd_imgs + memshr_id;
    if(img->ref_cnt == 0)
    {
        DPRINTF("Incorrect image put.\n");
        return;
    }

    img->ref_cnt--; 

    /* Remove from list if ref_cnt is zero */
    if(img->ref_cnt == 0)
    {
        next_img = vbd_imgs + img->next;
        prev_img = vbd_imgs + img->prev;
        prev_img->next = img->next;
        next_img->prev = img->prev;
        img->next = img->prev = (img - vbd_imgs);
        memset(img->file, 0, MAX_NAME_LEN);
    }
}

