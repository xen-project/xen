/*
 *
 *  Authors:  Machon Gregory, <mbgrego@tycho.ncsc.mil>
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
    fprintf(stderr, "Usage: %s [ (Enforcing|1) | (Permissive|0) ]\n", args[0]);
    exit(1);
}

int main (int argCnt, const char *args[])
{
    int ret = 0;
    xc_interface *xch = 0;
    long mode = 0;
    char *end;

    if (argCnt != 2)
        usage(argCnt, args);

    xch = xc_interface_open(0,0,0);
    if ( !xch )
    {
        fprintf(stderr, "Unable to create interface to xenctrl: %s\n",
                strerror(errno));
        ret = -1;
        goto done;
    }

    if( strlen(args[1]) == 1 && (args[1][0] == '0' || args[1][0] == '1')){
        mode = strtol(args[1], &end, 10);
        ret = xc_flask_setenforce(xch, mode);
    } else {
        if( strcasecmp(args[1], "enforcing") == 0 ){
            ret = xc_flask_setenforce(xch, 1);
        } else if( strcasecmp(args[1], "permissive") == 0 ){
            ret = xc_flask_setenforce(xch, 0);
        } else {
            usage(argCnt, args);
        }
    }

    if ( ret < 0 )
    {
        errno = -ret;
        fprintf(stderr, "Unable to get enforcing mode: %s\n",
                strerror(errno));
        ret = -1;
        goto done;
    }

done:
    if ( xch )
        xc_interface_close(xch);

    return ret;
}
