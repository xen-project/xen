/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2004 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: xenperf.c
 *      Author: Rolf Neugebauer (rolf.neugebauer@intel.com)
 *        Date: Nov 2004
 * 
 * Description: 
 */


#include <xc.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[])
{
    int              i, j, xc_handle;
    xc_perfc_desc_t *pcd;
    unsigned int     num, sum, reset = 0;

    if ( argc > 1 )
    {
        char *p = argv[1];
        if ( (*p++ == '-')  && (*p == 'r') )
            reset = 1;
        else
        {
            printf("%s: [-r]\n", argv[0]);
            printf("no args: print xen performance counters\n");
            printf("    -r : reset xen performance counters\n");
            return 0;
        }
    }   

    if ( (xc_handle = xc_interface_open()) == -1 )
    {
        fprintf(stderr, "Error opening xc interface: %d (%s)\n",
                errno, strerror(errno));
        return 1;
    }
    
    if ( reset )
    {
        if ( xc_perfc_control(xc_handle, DOM0_PERFCCONTROL_OP_RESET,
                              NULL) < 0 )
        {
            fprintf(stderr, "Error reseting performance counters: %d (%s)\n",
                    errno, strerror(errno));
            return 1;
        }

        return 0;
    }


    if ( (num = xc_perfc_control(xc_handle, DOM0_PERFCCONTROL_OP_QUERY,
                                 NULL)) < 0 )
    {
        fprintf(stderr, "Error getting number of perf counters: %d (%s)\n",
                errno, strerror(errno));
        return 1;
    }

    pcd = malloc(sizeof(*pcd) * num);

    if ( mlock(pcd, sizeof(*pcd) * num) != 0 )
    {
        fprintf(stderr, "Could not mlock descriptor buffer: %d (%s)\n",
                errno, strerror(errno));
        exit(-1);
    }

    if ( xc_perfc_control(xc_handle, DOM0_PERFCCONTROL_OP_QUERY, pcd) <= 0 )
    {
        fprintf(stderr, "Error getting perf counter description: %d (%s)\n",
                errno, strerror(errno));
        return 1;
    }

    munlock(pcd, sizeof(*pcd) * num);

    for ( i = 0; i < num; i++ )
    {
        printf ("%-35s ", pcd[i].name);
        
        sum = 0;
        for ( j = 0; j < pcd[i].nr_vals; j++ )
            sum += pcd[i].vals[j];
        printf ("T=%10u ", (unsigned int)sum);

        for ( j = 0; j < pcd[i].nr_vals; j++ )
            printf(" %10u", (unsigned int)pcd[i].vals[j]);

        printf("\n");
    }

    return 0;
}
