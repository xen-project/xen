/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2009 - Juergen Gross - Fujitsu Technology Solutions
 ****************************************************************************
 *
 *        File: xenlockprof.c
 *      Author: Juergen Gross (juergen.gross@ts.fujitsu.com)
 *        Date: Oct 2009
 * 
 * Description: 
 */

#include <xenctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>

int main(int argc, char *argv[])
{
    xc_interface      *xc_handle;
    uint32_t           i, j, n;
    uint64_t           time;
    double             l, b, sl, sb;
    char               name[60];
    DECLARE_HYPERCALL_BUFFER(xc_lockprof_data_t, data);

    if ( (argc > 2) || ((argc == 2) && (strcmp(argv[1], "-r") != 0)) )
    {
        printf("%s: [-r]\n", argv[0]);
        printf("no args: print lock profile data\n");
        printf("    -r : reset profile data\n");
        return 1;
    }

    if ( (xc_handle = xc_interface_open(0,0,0)) == 0 )
    {
        fprintf(stderr, "Error opening xc interface: %d (%s)\n",
                errno, strerror(errno));
        return 1;
    }

    if ( argc > 1 )
    {
        if ( xc_lockprof_reset(xc_handle) != 0 )
        {
            fprintf(stderr, "Error reseting profile data: %d (%s)\n",
                    errno, strerror(errno));
            return 1;
        }
        return 0;
    }

    n = 0;
    if ( xc_lockprof_query_number(xc_handle, &n) != 0 )
    {
        fprintf(stderr, "Error getting number of profile records: %d (%s)\n",
                errno, strerror(errno));
        return 1;
    }

    n += 32;    /* just to be sure */
    data = xc_hypercall_buffer_alloc(xc_handle, data, sizeof(*data) * n);
    if ( data == NULL )
    {
        fprintf(stderr, "Could not allocate buffers: %d (%s)\n",
                errno, strerror(errno));
        return 1;
    }

    i = n;
    if ( xc_lockprof_query(xc_handle, &i, &time, HYPERCALL_BUFFER(data)) != 0 )
    {
        fprintf(stderr, "Error getting profile records: %d (%s)\n",
                errno, strerror(errno));
        return 1;
    }

    if ( i > n )
    {
        printf("data incomplete, %d records are missing!\n\n", i - n);
        i = n;
    }

    sl = 0;
    sb = 0;
    for ( j = 0; j < i; j++ )
    {
        switch ( data[j].type )
        {
        case LOCKPROF_TYPE_GLOBAL:
            sprintf(name, "global lock %s", data[j].name);
            break;
        case LOCKPROF_TYPE_PERDOM:
            sprintf(name, "domain %d lock %s", data[j].idx, data[j].name);
            break;
        default:
            sprintf(name, "unknown type(%d) %d lock %s", data[j].type,
                    data[j].idx, data[j].name);
            break;
        }
        l = (double)(data[j].lock_time) / 1E+09;
        b = (double)(data[j].block_time) / 1E+09;
        sl += l;
        sb += b;
        printf("%-50s: lock:%12"PRId64"(%20.9fs), "
               "block:%12"PRId64"(%20.9fs)\n",
               name, data[j].lock_cnt, l, data[j].block_cnt, b);
    }
    l = (double)time / 1E+09;
    printf("total profiling time: %20.9fs\n", l);
    printf("total locked time:    %20.9fs\n", sl);
    printf("total blocked time:   %20.9fs\n", sb);

    xc_hypercall_buffer_free(xc_handle, data);

    return 0;
}
