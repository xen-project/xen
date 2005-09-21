 /*****************************************************************************
 * drivers/xen/tpmback/interface.c
 *
 * Vritual TPM interface management.
 *
 * Copyright (c) 2005, IBM Corporation
 *
 * Author: Stefan Berger, stefanb@us.ibm.com
 *
 * This code has been derived from drivers/xen/netback/interface.c
 * Copyright (c) 2004, Keir Fraser
 */

#include "common.h"
#include <asm-xen/balloon.h>
#include <asm-xen/driver_util.h>

#define VMALLOC_VMADDR(x) ((unsigned long)(x))

#define TPMIF_HASHSZ (2 << 5)
#define TPMIF_HASH(_d,_h) (((int)(_d)^(int)(_h))&(TPMIF_HASHSZ-1))

static kmem_cache_t *tpmif_cachep;
int num_frontends = 0;

LIST_HEAD(tpmif_list);

tpmif_t *
alloc_tpmif(domid_t domid, long int instance)
{
	struct page *page;
	tpmif_t *tpmif;

	tpmif = kmem_cache_alloc(tpmif_cachep, GFP_KERNEL);
	if (!tpmif)
		return ERR_PTR(-ENOMEM);

	memset(tpmif, 0, sizeof (*tpmif));
	tpmif->domid = domid;
	tpmif->status = DISCONNECTED;
	tpmif->tpm_instance = instance;
	atomic_set(&tpmif->refcnt, 1);

	page = balloon_alloc_empty_page_range(TPMIF_TX_RING_SIZE);
	BUG_ON(page == NULL);
	tpmif->mmap_vstart = (unsigned long)pfn_to_kaddr(page_to_pfn(page));

	list_add(&tpmif->tpmif_list, &tpmif_list);
	num_frontends++;

	return tpmif;
}

void
free_tpmif(tpmif_t * tpmif)
{
	num_frontends--;
	list_del(&tpmif->tpmif_list);
	kmem_cache_free(tpmif_cachep, tpmif);
}

tpmif_t *
tpmif_find(domid_t domid, long int instance)
{
	tpmif_t *tpmif;

	list_for_each_entry(tpmif, &tpmif_list, tpmif_list) {
		if (tpmif->tpm_instance == instance) {
			if (tpmif->domid == domid) {
				tpmif_get(tpmif);
				return tpmif;
			} else {
				return NULL;
			}
		}
	}

	return alloc_tpmif(domid, instance);
}

static int
map_frontend_page(tpmif_t * tpmif, unsigned long localaddr,
		  unsigned long shared_page)
{
	struct gnttab_map_grant_ref op = {
		.host_addr = localaddr,
		.flags = GNTMAP_host_map,
		.ref = shared_page,
		.dom = tpmif->domid,
	};

	BUG_ON(HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1));

	if (op.handle < 0) {
		DPRINTK(" Grant table operation failure !\n");
		return op.handle;
	}

	tpmif->shmem_ref = shared_page;
	tpmif->shmem_handle = op.handle;
	tpmif->shmem_vaddr = localaddr;
	return 0;
}

static void
unmap_frontend_page(tpmif_t * tpmif)
{
	struct gnttab_unmap_grant_ref op;

	op.host_addr = tpmif->shmem_vaddr;
	op.handle = tpmif->shmem_handle;
	op.dev_bus_addr = 0;

	BUG_ON(HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1));
}

int
tpmif_map(tpmif_t * tpmif, unsigned long shared_page, unsigned int evtchn)
{
	struct vm_struct *vma;
	evtchn_op_t op = {.cmd = EVTCHNOP_bind_interdomain };
	int err;

	BUG_ON(tpmif->remote_evtchn);

	if ((vma = prepare_vm_area(PAGE_SIZE)) == NULL)
		return -ENOMEM;

	err = map_frontend_page(tpmif, VMALLOC_VMADDR(vma->addr), shared_page);
	if (err) {
		vunmap(vma->addr);
		return err;
	}

	op.u.bind_interdomain.dom1 = DOMID_SELF;
	op.u.bind_interdomain.dom2 = tpmif->domid;
	op.u.bind_interdomain.port1 = 0;
	op.u.bind_interdomain.port2 = evtchn;
	err = HYPERVISOR_event_channel_op(&op);
	if (err) {
		unmap_frontend_page(tpmif);
		vunmap(vma->addr);
		return err;
	}

	tpmif->evtchn = op.u.bind_interdomain.port1;
	tpmif->remote_evtchn = evtchn;

	tpmif->tx = (tpmif_tx_interface_t *) vma->addr;

	bind_evtchn_to_irqhandler(tpmif->evtchn,
				  tpmif_be_int, 0, "tpmif-backend", tpmif);
	tpmif->status = CONNECTED;
	tpmif->shmem_ref = shared_page;
	tpmif->active = 1;

	return 0;
}

static void
__tpmif_disconnect_complete(void *arg)
{
	evtchn_op_t op = {.cmd = EVTCHNOP_close };
	tpmif_t *tpmif = (tpmif_t *) arg;

	op.u.close.port = tpmif->evtchn;
	op.u.close.dom = DOMID_SELF;
	HYPERVISOR_event_channel_op(&op);
	op.u.close.port = tpmif->remote_evtchn;
	op.u.close.dom = tpmif->domid;
	HYPERVISOR_event_channel_op(&op);

	if (tpmif->evtchn)
		unbind_evtchn_from_irqhandler(tpmif->evtchn, tpmif);

	if (tpmif->tx) {
		unmap_frontend_page(tpmif);
		vunmap(tpmif->tx);
	}

	free_tpmif(tpmif);
}

void
tpmif_disconnect_complete(tpmif_t * tpmif)
{
	INIT_WORK(&tpmif->work, __tpmif_disconnect_complete, (void *)tpmif);
	schedule_work(&tpmif->work);
}

void __init
tpmif_interface_init(void)
{
	tpmif_cachep = kmem_cache_create("tpmif_cache", sizeof (tpmif_t),
					 0, 0, NULL, NULL);
}
