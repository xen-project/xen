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
