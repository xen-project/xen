/*
 * xenpm.c: list the power information of the available processors
 * Copyright (c) 2008, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>

#include <xenctrl.h>
#include <inttypes.h>

int main(int argc, char **argv)
{
    int xc_fd;
    int i, j, ret = 0;
    int cinfo = 0, pinfo = 0;
    int ch;
    xc_physinfo_t physinfo = { 0 };

    while ( (ch = getopt(argc, argv, "cp")) != -1 )
    {
        switch ( ch )
        {
        case 'c':
            cinfo = 1;
            break;
        case 'p':
            pinfo = 1;
            break;
        default:
            fprintf(stderr, "%s [-p] [-c]\n", argv[0]);
            return -1;
        }
    }

    if ( !cinfo && !pinfo )
    {
        cinfo = 1;
        pinfo = 1;
    }

    xc_fd = xc_interface_open();
    if ( xc_fd < 0 )
    {
        fprintf(stderr, "failed to get the handler\n");
        return xc_fd;
    }

    ret = xc_physinfo(xc_fd, &physinfo);
    if ( ret )
    {
        fprintf(stderr, "failed to get the processor information\n");
        xc_interface_close(xc_fd);
        return ret;
    }

    /* print out the C state information */
    if ( cinfo )
    {
        int max_cx_num = 0;
        struct xc_cx_stat cxstatinfo, *cxstat = &cxstatinfo;

        for ( i = 0; i < physinfo.nr_cpus; i++ )
        {
            ret = xc_pm_get_max_cx(xc_fd, i, &max_cx_num);
            if ( ret )
            {
                if ( errno == ENODEV )
                {
                    fprintf(stderr, "Xen cpuidle is not enabled!\n");
                    break;
                }
                else
                {
                    fprintf(stderr, "[CPU%d] failed to get max C-state\n", i);
                    continue;
                }
            }

            cxstat->triggers = malloc(max_cx_num * sizeof(uint64_t));
            if ( !cxstat->triggers )
            {
                fprintf(stderr, "failed to malloc for C-states triggers\n");
                break;
            }
            cxstat->residencies = malloc(max_cx_num * sizeof(uint64_t));
            if ( !cxstat->residencies )
            {
                fprintf(stderr, "failed to malloc for C-states residencies\n");
                free(cxstat->triggers);
                break;
            }

            ret = xc_pm_get_cxstat(xc_fd, i, cxstat);
            if( ret )
            {
                fprintf(stderr, "[CPU%d] failed to get C-states statistics "
                        "information\n", i);
                free(cxstat->triggers);
                free(cxstat->residencies);
                continue;
            }

            printf("cpu id               : %d\n", i);
            printf("total C-states       : %d\n", cxstat->nr);
            printf("idle time(ms)        : %"PRIu64"\n",
                   cxstat->idle_time/1000000UL);
            for ( j = 0; j < cxstat->nr; j++ )
            {
                printf("C%d                   : transition [%020"PRIu64"]\n",
                       j, cxstat->triggers[j]);
                printf("                       residency  [%020"PRIu64" ms]\n",
                       cxstat->residencies[j]*1000000UL/3579/1000000UL);
            }

            free(cxstat->triggers);
            free(cxstat->residencies);

            printf("\n");
        }
    }

    /* print out P state information */
    if ( pinfo )
    {
        int max_px_num = 0;
        struct xc_px_stat pxstatinfo, *pxstat = &pxstatinfo;

        for ( i = 0; i < physinfo.nr_cpus; i++ )
        {
            ret = xc_pm_get_max_px(xc_fd, i, &max_px_num);
            if ( ret )
            {
                if ( errno == ENODEV )
                {
                    printf("Xen cpufreq is not enabled!\n");
                    break;
                }
                else
                {
                    fprintf(stderr, "[CPU%d] failed to get max P-state\n", i);
                    continue;
                }
            }

            pxstat->trans_pt = malloc(max_px_num * max_px_num *
                                      sizeof(uint64_t));
            if ( !pxstat->trans_pt )
            {
                fprintf(stderr, "failed to malloc for P-states "
                        "transition table\n");
                break;
            }
            pxstat->pt = malloc(max_px_num * sizeof(struct xc_px_val));
            if ( !pxstat->pt )
            {
                fprintf(stderr, "failed to malloc for P-states table\n");
                free(pxstat->pt);
                break;
            }

            ret = xc_pm_get_pxstat(xc_fd, i, pxstat);
            if( ret )
            {
                fprintf(stderr, "[CPU%d] failed to get P-states "
                        "statistics information\n", i);
                free(pxstat->trans_pt);
                free(pxstat->pt);
                continue;
            }

            printf("cpu id               : %d\n", i);
            printf("total P-states       : %d\n", pxstat->total);
            printf("usable P-states      : %d\n", pxstat->usable);
            printf("current frequency    : %"PRIu64" MHz\n",
                   pxstat->pt[pxstat->cur].freq);
            for ( j = 0; j < pxstat->total; j++ )
            {
                if ( pxstat->cur == j )
                    printf("*P%d", j);
                else
                    printf("P%d ", j);
                printf("                  : freq       [%04"PRIu64" MHz]\n",
                       pxstat->pt[j].freq);
                printf("                       transition [%020"PRIu64"]\n",
                       pxstat->pt[j].count);
                printf("                       residency  [%020"PRIu64" ms]\n",
                       pxstat->pt[j].residency/1000000UL);
            }

            free(pxstat->trans_pt);
            free(pxstat->pt);

            printf("\n");
        }
    }

    xc_interface_close(xc_fd);
    return ret;
}

