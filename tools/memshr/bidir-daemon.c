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
#include <pthread.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>

#include "bidir-hash.h"
#include "memshr-priv.h"

static struct blockshr_hash *blks_hash;

/* Callback in the iterator, remember this value, and leave */
int find_one(vbdblk_t k, share_tuple_t v, void *priv)
{
    share_tuple_t *rv = (share_tuple_t *) priv;
    *rv = v;
    /* Break out of iterator loop */
    return 1;
}

void* bidir_daemon(void *unused)
{
    uint32_t nr_ent, max_nr_ent, tab_size, max_load, min_load;

    while(1)
    {
        blockshr_hash_sizes( blks_hash, 
                            &nr_ent, 
                            &max_nr_ent,
                            &tab_size, 
                            &max_load, 
                            &min_load);
        /* Remove some hints as soon as we get to 90% capacity */ 
        if(10 * nr_ent > 9 * max_nr_ent)
        {
            share_tuple_t next_remove;
            int to_remove;
            int ret;

            to_remove = 0.1 * max_nr_ent; 
            while(to_remove > 0) 
            {
                /* We use the iterator to get one entry */
                next_remove.handle = 0;
                ret = blockshr_hash_iterator(blks_hash, find_one, &next_remove);

                if ( !ret )
                    if ( next_remove.handle == 0 )
                        ret = -ESRCH;

                if ( !ret )
                    ret = blockshr_shrhnd_remove(blks_hash, next_remove, NULL);

                if(ret <= 0)
                {
                    /* We failed to remove an entry, because of a serious hash
                     * table error */
                    DPRINTF("Could not remove handle %"PRId64", error: %d\n",
                            next_remove.handle, ret);
                    /* Force to exit the loop early */
                    to_remove = 0;
                } else 
                if(ret > 0)
                {
                    /* Managed to remove the entry. Note next_remove not
                     * incremented, in case there are duplicates */
                    to_remove--;
                }
            }
        }

        sleep(1);
    }
}

void bidir_daemon_launch(void)
{
    pthread_t thread; 

    pthread_create(&thread, NULL, bidir_daemon, NULL);
}

void bidir_daemon_initialize(struct blockshr_hash *blks)
{
    blks_hash = blks; 
    bidir_daemon_launch();
}
