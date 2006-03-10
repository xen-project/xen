/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2005 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: xc_shadow.c
 *      Author: Rolf Neugebauer (rolf.neugebauer@intel.com)
 *        Date: Mar 2005
 * 
 * Description: 
 */


#include <xenctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

void usage(void)
{
    printf("xc_shadow: -[0|1|2]\n");
    printf("    set shadow mode\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    int xc_handle;
    int mode = 0;

    if ( argc > 1 )
    {
        char *p = argv[1];
        if (*p++ == '-') {
            if (*p == '1')
                mode = 1;
            else if (*p == '2')
                mode = 2;
            else if (*p == '0')
                mode = 0;
            else
                usage();
        } else
            usage();
    } 
    else
        usage();

    if ( (xc_handle = xc_interface_open()) == -1 )
    {
        fprintf(stderr, "Error opening xc interface: %d (%s)\n",
                errno, strerror(errno));
        return 1;
    }

    if ( xc_shadow_control(xc_handle,
                           0,
                           mode, 
                           NULL,
                           0,
                           NULL) < 0 )
    {    
        fprintf(stderr, "Error reseting performance counters: %d (%s)\n",
                errno, strerror(errno));
        return 1;
    }
    return 0;
}
