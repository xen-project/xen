/* ublkback.c
 *
 * libaio-based userlevel backend.
 */

#include "blktaplib.h"
#include "ublkbacklib.h"


int main(int argc, char *argv[])
{
    ublkback_init();
    
    register_new_blkif_hook(ublkback_new_blkif);
    blktap_listen();
    
    return 0;
}
