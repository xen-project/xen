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

#include <xenctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

#define X(name) [__HYPERVISOR_##name] = #name
const char *hypercall_name_table[64] =
{
    X(set_trap_table),
    X(mmu_update),
    X(set_gdt),
    X(stack_switch),
    X(set_callbacks),
    X(fpu_taskswitch),
    X(sched_op_compat),
    X(platform_op),
    X(set_debugreg),
    X(get_debugreg),
    X(update_descriptor),
    X(memory_op),
    X(multicall),
    X(update_va_mapping),
    X(set_timer_op),
    X(event_channel_op_compat),
    X(xen_version),
    X(console_io),
    X(physdev_op_compat),
    X(grant_table_op),
    X(vm_assist),
    X(update_va_mapping_otherdomain),
    X(iret),
    X(vcpu_op),
    X(set_segment_base),
    X(mmuext_op),
    X(xsm_op),
    X(nmi_op),
    X(sched_op),
    X(callback_op),
    X(xenoprof_op),
    X(event_channel_op),
    X(physdev_op),
    X(hvm_op),
    X(sysctl),
    X(domctl),
    X(kexec_op),
    X(arch_0),
    X(arch_1),
    X(arch_2),
    X(arch_3),
    X(arch_4),
    X(arch_5),
    X(arch_6),
    X(arch_7),
};
#undef X

int main(int argc, char *argv[])
{
    int              i, j;
    xc_interface    *xc_handle;
    DECLARE_HYPERCALL_BUFFER(xc_perfc_desc_t, pcd);
    DECLARE_HYPERCALL_BUFFER(xc_perfc_val_t, pcv);
    xc_perfc_val_t  *val;
    int num_desc, num_val;
    unsigned int    sum, reset = 0, full = 0, pretty = 0;
    char hypercall_name[36];

    if ( argc > 1 )
    {
        char *p = argv[1];
        if ( p[0] == '-' )
        {
            switch ( p[1] )
            {
            case 'f':
                full = 1;
                break;
            case 'p':
                full = 1;
                pretty = 1;
                break;
            case 'r':
                reset = 1;
                break;
            default:
                goto error;
            }
        }
        else
        {
        error:
            printf("%s: [-r]\n", argv[0]);
            printf("no args: print digested counters\n");
            printf("    -f : print full arrays/histograms\n");
            printf("    -p : print full arrays/histograms in pretty format\n");
            printf("    -r : reset counters\n");
            return 0;
        }
    }   

    if ( (xc_handle = xc_interface_open(0,0,0)) == 0 )
    {
        fprintf(stderr, "Error opening xc interface: %d (%s)\n",
                errno, strerror(errno));
        return 1;
    }
    
    if ( reset )
    {
        if ( xc_perfc_reset(xc_handle) != 0 )
        {
            fprintf(stderr, "Error reseting performance counters: %d (%s)\n",
                    errno, strerror(errno));
            return 1;
        }

        return 0;
    }

    if ( xc_perfc_query_number(xc_handle, &num_desc, &num_val) != 0 )
    {
        fprintf(stderr, "Error getting number of perf counters: %d (%s)\n",
                errno, strerror(errno));
        return 1;
    }

    pcd = xc_hypercall_buffer_alloc(xc_handle, pcd, sizeof(*pcd) * num_desc);
    pcv = xc_hypercall_buffer_alloc(xc_handle, pcv, sizeof(*pcv) * num_val);

    if ( pcd == NULL || pcv == NULL)
    {
        fprintf(stderr, "Could not allocate buffers: %d (%s)\n",
                errno, strerror(errno));
        exit(-1);
    }

    if ( xc_perfc_query(xc_handle, HYPERCALL_BUFFER(pcd), HYPERCALL_BUFFER(pcv)) != 0 )
    {
        fprintf(stderr, "Error getting perf counter: %d (%s)\n",
                errno, strerror(errno));
        return 1;
    }

    val = pcv;
    for ( i = 0; i < num_desc; i++ )
    {
        printf ("%-35s ", pcd[i].name);
        
        sum = 0;
        for ( j = 0; j < pcd[i].nr_vals; j++ )
            sum += val[j];
        printf ("T=%10u ", (unsigned int)sum);

        if ( full || (pcd[i].nr_vals <= 4) )
        {
            if ( pretty && (strcmp(pcd[i].name, "hypercalls") == 0) )
            {
                printf("\n");
                for( j = 0; j < pcd[i].nr_vals; j++ )
                {
                    if ( val[j] == 0 )
                        continue;
                    if ( (j < 64) && hypercall_name_table[j] )
                        strncpy(hypercall_name, hypercall_name_table[j],
                                sizeof(hypercall_name));
                    else
                        snprintf(hypercall_name, sizeof(hypercall_name), "[%d]", j);
                    hypercall_name[sizeof(hypercall_name)-1]='\0';
                    printf("%-35s ", hypercall_name);
                    printf("%12u\n", (unsigned int)val[j]);
                }
            }
            else
            {
                for ( j = 0; j < pcd[i].nr_vals; j++ )
                    printf(" %10u", (unsigned int)val[j]);
                printf("\n");
            }
        }
        else
        {
            printf("\n");
        }

        val += pcd[i].nr_vals;
    }

    xc_hypercall_buffer_free(xc_handle, pcd);
    xc_hypercall_buffer_free(xc_handle, pcv);
    return 0;
}
