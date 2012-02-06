/*
 *
 *  Author:  Machon Gregory, <mbgrego@tycho.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <xenctrl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

static void usage (int argCnt, const char *args[])
{
    fprintf(stderr, "Usage: %s\n", args[0]);
    exit(1);
}

int main (int argCnt, const char *args[])
{
    int ret;
    xc_interface *xch = 0;

    if (argCnt != 1)
        usage(argCnt, args);

    xch = xc_interface_open(0,0,0);
    if ( !xch )
    {
        fprintf(stderr, "Unable to create interface to xenctrl: %s\n",
                strerror(errno));
        ret = -1;
        goto done;
    }

    ret = xc_flask_getenforce(xch);
    if ( ret < 0 )
    {
        errno = -ret;
        fprintf(stderr, "Unable to get enforcing mode: %s\n",
                strerror(errno));
        ret = -1;
        goto done;
    }
    else
    {
        if(ret) 
            printf("Enforcing\n");
        else
            printf("Permissive\n");
    }

done:
    if ( xch )
        xc_interface_close(xch);

    return ret;
}
