/******************************************************************************
 * libxc_vif.c
 * 
 * API for manipulating and accessing per-network-interface parameters.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include "libxc_private.h"

int xc_vif_scheduler_set(unsigned int domid, 
                         unsigned int vifid, 
                         xc_vif_sched_params_t *params)
{
    network_op_t  netop;
    netop.cmd = NETWORK_OP_VIFSETPARAMS;
    netop.u.vif_setparams.domain       = domid;
    netop.u.vif_setparams.vif          = vifid;
    netop.u.vif_setparams.credit_bytes = params->credit_bytes;
    netop.u.vif_setparams.credit_usec  = params->credit_usec;
    return do_network_op(&netop);
}


int xc_vif_scheduler_get(unsigned int domid, 
                         unsigned int vifid, 
                         xc_vif_sched_params_t *params)
{
    network_op_t  netop;
    int rc;

    netop.cmd = NETWORK_OP_VIFGETINFO;
    netop.u.vif_getinfo.domain = domid;
    netop.u.vif_getinfo.vif    = vifid;

    if ( (rc = do_network_op(&netop)) >= 0 )
    {
        params->credit_bytes = netop.u.vif_getinfo.credit_bytes;
        params->credit_usec  = netop.u.vif_getinfo.credit_usec;
    }

    return rc;
}


int xc_vif_stats_get(unsigned int domid, 
                     unsigned int vifid, 
                     xc_vif_stats_t *stats)
{
    network_op_t  netop;
    int rc;

    netop.cmd = NETWORK_OP_VIFGETINFO;
    netop.u.vif_getinfo.domain = domid;
    netop.u.vif_getinfo.vif    = vifid;

    if ( (rc = do_network_op(&netop)) >= 0 )
    {
        stats->tx_bytes = netop.u.vif_getinfo.total_bytes_sent;
        stats->tx_pkts  = netop.u.vif_getinfo.total_packets_sent;
        stats->rx_bytes = netop.u.vif_getinfo.total_bytes_received;
        stats->rx_pkts  = netop.u.vif_getinfo.total_packets_received;
    }

    return rc;
}
