/* blkcowimg.c
 *
 * file-backed cow.
 */

#include "blktaplib.h"
#include "blkcowlib.h"
#include "blkimglib.h"


int main(int argc, char *argv[])
{
    cow_init();
    image_init();
    
    blktap_register_ctrl_hook("cow_control", cow_control);
    blktap_register_ctrl_hook("image_control", image_control);
    blktap_register_request_hook("cow_request", cow_request);
    blktap_register_request_hook("image_request", image_request);
    blktap_register_response_hook("cow_response", cow_response);
    blktap_listen();
    
    return 0;
}
