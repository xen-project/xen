
#include "dom0_defs.h"
#include "mem_defs.h"

static char *argv0 = "internal_domain_usage";

int main(int argc, char **argv)
{
    dom0_op_t    op;
    network_op_t netop;
    int          i, domain, vifs[32];

    if ( argv[0] != NULL ) 
        argv0 = argv[0];

    if ( argc != 2 ) 
    {
        fprintf(stderr, "Usage: %s <domain-id>\n", argv0);
        return 1;
    }

    domain = atol(argv[1]);

    op.cmd                 = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = domain;
    if ( do_dom0_op(&op) < 0 )
        return 1;

    printf("cpu%d: %lld\n", 
           op.u.getdomaininfo.processor,
           op.u.getdomaininfo.cpu_time);

    if ( mlock(vifs, sizeof(vifs)) != 0 )
    {
        PERROR("Could not lock memory for network query buffer");
        return 1;
    }

    netop.cmd = NETWORK_OP_VIFQUERY;
    netop.u.vif_query.domain = domain;
    netop.u.vif_query.buf    = vifs;
    if ( do_network_op(&netop) < 0 )
        return 1;

    for ( i = 1; i <= vifs[0]; i++ )
    {
        netop.cmd = NETWORK_OP_VIFGETINFO;
        netop.u.vif_getinfo.domain = domain;
        netop.u.vif_getinfo.vif    = vifs[i];
        if ( do_network_op(&netop) < 0 )
            return 1;

        printf("vif%d: sent %lld bytes (%lld packets) "
               "received %lld bytes (%lld packets)\n",
               vifs[i],
               netop.u.vif_getinfo.total_bytes_sent,
               netop.u.vif_getinfo.total_packets_sent,
               netop.u.vif_getinfo.total_bytes_received,
               netop.u.vif_getinfo.total_packets_received);
    }

    return 0;
}
