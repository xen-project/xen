/* blkaio.c
 *
 * libaio-backed disk.
 */

#include "blktaplib.h"
#include "blkaiolib.h"


int main(int argc, char *argv[])
{
    aio_init();
    
    blktap_register_ctrl_hook("aio_control", aio_control);
    blktap_register_request_hook("aio_request", aio_request);
    blktap_listen();
    
    return 0;
}
