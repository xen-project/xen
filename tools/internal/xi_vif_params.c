
#include "dom0_defs.h"
#include "mem_defs.h"

static char *argv0 = "internal_domain_vif_params";

int main(int argc, char **argv)
{
    network_op_t  netop;
    int           domain, vif;
    unsigned long credit_bytes, credit_usec;
    
    if ( argv[0] != NULL ) 
        argv0 = argv[0];

    if ( (argc != 3) && (argc != 5) ) 
    {
        fprintf(stderr, "Usage: %s <domain-id> <vif-id> "
                "[<credit-bytes> <credit-usec>]\n", argv0);
        fprintf(stderr, "Specify <credit usec> == 0 to disable scheduling\n");
        return 1;
    }

    domain = atol(argv[1]);
    vif    = atol(argv[2]);

    if ( argc == 5 )
    {
        credit_bytes = atol(argv[3]);
        credit_usec  = atol(argv[4]);

        netop.cmd = NETWORK_OP_VIFSETPARAMS;
        netop.u.vif_setparams.domain       = domain;
        netop.u.vif_setparams.vif          = vif;
        netop.u.vif_setparams.credit_bytes = credit_bytes;
        netop.u.vif_setparams.credit_usec  = credit_usec;
        if ( do_network_op(&netop) < 0 )
            return 1;

        if ( credit_usec != 0 )
        {
            printf("Set scheduling to %lu bytes every"
                   " %lu usecs (%2.2f Mbps)\n",
                   credit_bytes, credit_usec,
                   ((float)credit_bytes/(1024.0*1024.0/8.0)) /
                   ((float)credit_usec/1000000.0));
        }
        else
        {
            printf("Disabled rate limiting for vif\n");
        }
    }
    else
    {
        netop.cmd = NETWORK_OP_VIFGETINFO;
        netop.u.vif_getinfo.domain = domain;
        netop.u.vif_getinfo.vif    = vif;
        if ( do_network_op(&netop) < 0 )
            return 1;
        
        printf("%lld bytes transmitted\n"
               "%lld packets transmitted\n"
               "%lld bytes received\n"
               "%lld packets received\n",
               netop.u.vif_getinfo.total_bytes_sent,
               netop.u.vif_getinfo.total_packets_sent,
               netop.u.vif_getinfo.total_bytes_received,
               netop.u.vif_getinfo.total_packets_received);

        if ( netop.u.vif_getinfo.credit_usec != 0 )
        {
            printf("Scheduling: %lu bytes every %lu usecs (%2.2f Mbps)\n",
               netop.u.vif_getinfo.credit_bytes,
                   netop.u.vif_getinfo.credit_usec,
               ((float)netop.u.vif_getinfo.credit_bytes/(1024.0*1024.0/8.0)) /
               ((float)netop.u.vif_getinfo.credit_usec/1000000.0));
        }
        else
        {
            printf("Scheduling: no rate limit\n");
        }
    }

    return 0;
}
