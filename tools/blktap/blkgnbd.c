/* blkgnbd.c
 *
 * gnbd-backed disk.
 */

#include "blktaplib.h"
#include "blkgnbdlib.h"


int main(int argc, char *argv[])
{
    gnbd_init();
    
    blktap_register_ctrl_hook("gnbd_control", gnbd_control);
    blktap_register_request_hook("gnbd_request", gnbd_request);
    blktap_listen();
    
    return 0;
}
