/* blkcowgnbd.c
 *
 * gnbd-backed cow.
 */

#include "blktaplib.h"
#include "blkcowlib.h"
#include "blkgnbdlib.h"


int main(int argc, char *argv[])
{
    cow_init();
    gnbd_init();
    
    blktap_register_ctrl_hook("cow_control", cow_control);
    blktap_register_ctrl_hook("gnbd_control", gnbd_control);
    blktap_register_request_hook("cow_request", cow_request);
    blktap_register_request_hook("gnbd_request", gnbd_request);
    blktap_register_response_hook("cow_response", cow_response);
    blktap_listen();
    
    return 0;
}
