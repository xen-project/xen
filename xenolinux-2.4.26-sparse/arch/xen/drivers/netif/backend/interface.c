/******************************************************************************
 * arch/xen/drivers/netif/backend/interface.c
 * 
 * Network-device interface management.
 * 
 * Copyright (c) 2004, Keir Fraser
 */

#include "common.h"

#define NETIF_HASHSZ 1024
#define NETIF_HASH(_d,_h) \
    (((int)(_d)^(int)((_d)>>32)^(int)(_h))&(NETIF_HASHSZ-1))

static kmem_cache_t *netif_cachep;
static netif_t      *netif_hash[NETIF_HASHSZ];

netif_t *netif_find_by_handle(domid_t domid, unsigned int handle)
{
    netif_t *netif = netif_hash[NETIF_HASH(domid, handle)];
    while ( (netif != NULL) && 
            ((netif->domid != domid) || (netif->handle != handle)) )
        netif = netif->hash_next;
    return netif;
}

void __netif_disconnect_complete(netif_t *netif)
{
    ctrl_msg_t            cmsg;
    netif_be_disconnect_t disc;

    /*
     * These can't be done in __netif_disconnect() because at that point there
     * may be outstanding requests at the disc whose asynchronous responses
     * must still be notified to the remote driver.
     */
    unbind_evtchn_from_irq(netif->evtchn);
    vfree(netif->net_ring_base);

    /* Construct the deferred response message. */
    cmsg.type         = CMSG_NETIF_BE;
    cmsg.subtype      = CMSG_NETIF_BE_DISCONNECT;
    cmsg.id           = netif->disconnect_rspid;
    cmsg.length       = sizeof(netif_be_disconnect_t);
    disc.domid        = netif->domid;
    disc.netif_handle = netif->handle;
    disc.status       = NETIF_BE_STATUS_OKAY;
    memcpy(cmsg.msg, &disc, sizeof(disc));

    /*
     * Make sure message is constructed /before/ status change, because
     * after the status change the 'netif' structure could be deallocated at
     * any time. Also make sure we send the response /after/ status change,
     * as otherwise a subsequent CONNECT request could spuriously fail if
     * another CPU doesn't see the status change yet.
     */
    mb();
    if ( netif->status != DISCONNECTING )
        BUG();
    netif->status = DISCONNECTED;
    mb();

    /* Send the successful response. */
    ctrl_if_send_response(&cmsg);
}

void netif_create(netif_be_create_t *create)
{
    domid_t       domid  = create->domid;
    unsigned int  handle = create->netif_handle;
    netif_t     **pnetif, *netif;

    if ( (netif = kmem_cache_alloc(netif_cachep, GFP_ATOMIC)) == NULL )
    {
        DPRINTK("Could not create netif: out of memory\n");
        create->status = NETIF_BE_STATUS_OUT_OF_MEMORY;
        return;
    }

    memset(netif, 0, sizeof(*netif));
    netif->domid  = domid;
    netif->handle = handle;
    netif->status = DISCONNECTED;
    spin_lock_init(&netif->vbd_lock);
    spin_lock_init(&netif->net_ring_lock);
    atomic_set(&netif->refcnt, 0);

    pnetif = &netif_hash[NETIF_HASH(domid, handle)];
    while ( *pnetif != NULL )
    {
        if ( ((*pnetif)->domid == domid) && ((*pnetif)->handle == handle) )
        {
            DPRINTK("Could not create netif: already exists\n");
            create->status = NETIF_BE_STATUS_INTERFACE_EXISTS;
            kmem_cache_free(netif_cachep, netif);
            return;
        }
        pnetif = &(*pnetif)->hash_next;
    }

    netif->hash_next = *pnetif;
    *pnetif = netif;

    DPRINTK("Successfully created netif\n");
    create->status = NETIF_BE_STATUS_OKAY;
}

void netif_destroy(netif_be_destroy_t *destroy)
{
    domid_t       domid  = destroy->domid;
    unsigned int  handle = destroy->netif_handle;
    netif_t     **pnetif, *netif;

    pnetif = &netif_hash[NETIF_HASH(domid, handle)];
    while ( (netif = *pnetif) != NULL )
    {
        if ( (netif->domid == domid) && (netif->handle == handle) )
        {
            if ( netif->status != DISCONNECTED )
                goto still_connected;
            goto destroy;
        }
        pnetif = &netif->hash_next;
    }

    destroy->status = NETIF_BE_STATUS_INTERFACE_NOT_FOUND;
    return;

 still_connected:
    destroy->status = NETIF_BE_STATUS_INTERFACE_CONNECTED;
    return;

 destroy:
    *pnetif = netif->hash_next;
    destroy_all_vbds(netif);
    kmem_cache_free(netif_cachep, netif);
    destroy->status = NETIF_BE_STATUS_OKAY;
}

void netif_connect(netif_be_connect_t *connect)
{
    domid_t       domid  = connect->domid;
    unsigned int  handle = connect->netif_handle;
    unsigned int  evtchn = connect->evtchn;
    unsigned long shmem_frame = connect->shmem_frame;
    struct vm_struct *vma;
    pgprot_t      prot;
    int           error;
    netif_t      *netif;

    netif = netif_find_by_handle(domid, handle);
    if ( unlikely(netif == NULL) )
    {
        DPRINTK("netif_connect attempted for non-existent netif (%llu,%u)\n", 
                connect->domid, connect->netif_handle); 
        connect->status = NETIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

    if ( (vma = get_vm_area(PAGE_SIZE, VM_IOREMAP)) == NULL )
    {
        connect->status = NETIF_BE_STATUS_OUT_OF_MEMORY;
        return;
    }

    prot = __pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED);
    error = direct_remap_area_pages(&init_mm, VMALLOC_VMADDR(vma->addr),
                                    shmem_frame<<PAGE_SHIFT, PAGE_SIZE,
                                    prot, domid);
    if ( error != 0 )
    {
        if ( error == -ENOMEM )
            connect->status = NETIF_BE_STATUS_OUT_OF_MEMORY;
        else if ( error == -EFAULT )
            connect->status = NETIF_BE_STATUS_MAPPING_ERROR;
        else
            connect->status = NETIF_BE_STATUS_ERROR;
        vfree(vma->addr);
        return;
    }

    if ( netif->status != DISCONNECTED )
    {
        connect->status = NETIF_BE_STATUS_INTERFACE_CONNECTED;
        vfree(vma->addr);
        return;
    }

    netif->evtchn        = evtchn;
    netif->irq           = bind_evtchn_to_irq(evtchn);
    netif->shmem_frame   = shmem_frame;
    netif->net_ring_base = (netif_ring_t *)vma->addr;
    netif->status        = CONNECTED;
    netif_get(netif);

    request_irq(netif->irq, netif_be_int, 0, "netif-backend", netif);

    connect->status = NETIF_BE_STATUS_OKAY;
}

int netif_disconnect(netif_be_disconnect_t *disconnect, u8 rsp_id)
{
    domid_t       domid  = disconnect->domid;
    unsigned int  handle = disconnect->netif_handle;
    netif_t      *netif;

    netif = netif_find_by_handle(domid, handle);
    if ( unlikely(netif == NULL) )
    {
        DPRINTK("netif_disconnect attempted for non-existent netif"
                " (%llu,%u)\n", disconnect->domid, disconnect->netif_handle); 
        disconnect->status = NETIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return 1; /* Caller will send response error message. */
    }

    if ( netif->status == CONNECTED )
    {
        netif->status = DISCONNECTING;
        netif->disconnect_rspid = rsp_id;
        wmb(); /* Let other CPUs see the status change. */
        free_irq(netif->irq, NULL);
        netif_deschedule(netif);
        netif_put(netif);
    }

    return 0; /* Caller should not send response message. */
}

net_vif_t *create_net_vif(domid_t dom)
{
    unsigned int idx;
    net_vif_t *new_vif = NULL;
    net_ring_t *new_ring = NULL;
    struct task_struct *p = NULL;
    unsigned long flags, vmac_hash;
    unsigned char vmac_key[ETH_ALEN + 2 + MAX_DOMAIN_NAME];

    if ( (p = find_domain_by_id(dom)) == NULL )
        return NULL;
    
    write_lock_irqsave(&tasklist_lock, flags);

    for ( idx = 0; idx < MAX_DOMAIN_VIFS; idx++ )
        if ( p->net_vif_list[idx] == NULL )
            break;
    if ( idx == MAX_DOMAIN_VIFS )
        goto fail;

    if ( (new_vif = kmem_cache_alloc(net_vif_cache, GFP_KERNEL)) == NULL )
        goto fail;

    memset(new_vif, 0, sizeof(*new_vif));
    
    if ( sizeof(net_ring_t) > PAGE_SIZE )
        BUG();
    new_ring = (net_ring_t *)get_free_page(GFP_KERNEL);
    clear_page(new_ring);
    SHARE_PFN_WITH_DOMAIN(virt_to_page(new_ring), p);

    /*
     * Fill in the new vif struct. Note that, while the vif's refcnt is
     * non-zero, we hold a reference to the task structure.
     */
    atomic_set(&new_vif->refcnt, 1);
    new_vif->shared_rings = new_ring;
    new_vif->shared_idxs  = &p->shared_info->net_idx[idx];
    new_vif->domain       = p;
    new_vif->idx          = idx;
    new_vif->list.next    = NULL;
    spin_lock_init(&new_vif->rx_lock);
    spin_lock_init(&new_vif->tx_lock);

    new_vif->credit_bytes = new_vif->remaining_credit = ~0UL;
    new_vif->credit_usec  = 0UL;
    init_ac_timer(&new_vif->credit_timeout);

    if ( (p->domain == 0) && (idx == 0) )
    {
        /*
         * DOM0/VIF0 gets the real physical MAC address, so that users can
         * easily get a Xen-based machine up and running by using an existing
         * DHCP entry.
         */
        memcpy(new_vif->vmac, the_dev->dev_addr, ETH_ALEN);
    }
    else
    {
        /*
         * Most VIFs get a random MAC address with a "special" vendor id.
         * We try to get MAC addresses to be unique across multiple servers
         * by including the physical MAC address in the hash. The hash also
         * includes the vif index and the domain's name.
         * 
         * NB. The vendor is currently an "obsolete" one that used to belong
         * to DEC (AA-00-00). Using it is probably a bit rude :-)
         * 
         * NB2. The first bit of the first random octet is set to zero for
         * all dynamic MAC addresses. This may allow us to manually specify
         * MAC addresses for some VIFs with no fear of clashes.
         */
        memcpy(&vmac_key[0], the_dev->dev_addr, ETH_ALEN);
        *(__u16 *)(&vmac_key[ETH_ALEN]) = htons(idx);
        strcpy(&vmac_key[ETH_ALEN+2], p->name);
        vmac_hash = hash(vmac_key, ETH_ALEN + 2 + strlen(p->name));
        memcpy(new_vif->vmac, "\xaa\x00\x00", 3);
        new_vif->vmac[3] = (vmac_hash >> 16) & 0xef; /* First bit is zero. */
        new_vif->vmac[4] = (vmac_hash >>  8) & 0xff;
        new_vif->vmac[5] = (vmac_hash >>  0) & 0xff;
    }

    p->net_vif_list[idx] = new_vif;
    
    write_unlock_irqrestore(&tasklist_lock, flags);
    return new_vif;
    
 fail:
    write_unlock_irqrestore(&tasklist_lock, flags);
    if ( new_vif != NULL )
        kmem_cache_free(net_vif_cache, new_vif);
    if ( p != NULL )
        put_task_struct(p);
    return NULL;
}

void netif_interface_init(void)
{
    netif_cachep = kmem_cache_create("netif_cache", sizeof(netif_t), 
                                     0, 0, NULL, NULL);
    memset(netif_hash, 0, sizeof(netif_hash));
}
