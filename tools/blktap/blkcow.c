/* blkcow.c
 *
 * copy on write a block device.  in a really inefficient way.
 * 
 * (c) 2004 Andrew Warfield.
 *
 * This uses whatever backend the tap is attached to as the read-only
 * underlay -- for the moment.
 *
 * Xend has been modified to use an amorfs:[fsid] disk tag.
 * This will show up as device type (maj:240,min:0) = 61440.
 *
 * The fsid is placed in the sec_start field of the disk extent,
 * the cow plugin uses this to identify a unique overlay.
 */

#include "blktaplib.h"
#include "blkcowlib.h"


int main(int argc, char *argv[])
{
    cow_init();
    
    blktap_register_ctrl_hook("cow_control", cow_control);
    blktap_register_request_hook("cow_request", cow_request);
    blktap_register_response_hook("cow_response", cow_response);
    blktap_listen();
    
    return 0;
}
