/*
 * Copyright (C) 2003 - 2004 Mike Wray <mike.wray@hp.com>.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or  (at your option) any later version. This library is 
 * distributed in the  hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "select.h"

/** Zero all the file descriptor sets.
 *
 * @param set select set
 * @param fd file descriptor
 * @return 0 on success, -1 otherwise
 */
void SelectSet_zero(SelectSet *set){
    set->n = 0;
    FD_ZERO(&set->rd);
    FD_ZERO(&set->wr);
    FD_ZERO(&set->er);
}

/** Add a file descriptor to the write set.
 *
 * @param set select set
 * @param fd file descriptor
 * @return 0 on success, -1 otherwise
 */
void SelectSet_add_read(SelectSet *set, int fd){
    FD_SET(fd, &set->rd);
    if(fd > set->n) set->n = fd;
}

/** Add a file descriptor to the write set.
 *
 * @param set select set
 * @param fd file descriptor
 * @return 0 on success, -1 otherwise
 */
void SelectSet_add_write(SelectSet *set, int fd){
    FD_SET(fd, &set->wr);
    if(fd > set->n) set->n = fd;
}

/** Select on file descriptors.
 *
 * @param set select set
 * @param timeout timeout (may be NULL for no timeout)
 * @return 0 on success, -1 otherwise
 */
int SelectSet_select(SelectSet *set, struct timeval *timeout){
    return select(set->n+1, &set->rd, &set->wr, &set->er, timeout);
}
