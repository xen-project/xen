/* blkimg.c
 *
 * file-backed disk.
 */

#include "blktaplib.h"
#include "blkimglib.h"


int main(int argc, char *argv[])
{
    image_init();
    
    blktap_register_ctrl_hook("image_control", image_control);
    blktap_register_request_hook("image_request", image_request);
    blktap_listen();
    
    return 0;
}
