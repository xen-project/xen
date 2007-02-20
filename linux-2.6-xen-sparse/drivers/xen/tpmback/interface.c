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
#include <xen/balloon.h>
#include <xen/gnttab.h>

static kmem_cache_t *tpmif_cachep;
int num_frontends = 0;

LIST_HEAD(tpmif_list);

static tpmif_t *alloc_tpmif(domid_t domid, struct backend_info *bi)
{
	tpmif_t *tpmif;

	tpmif = kmem_cache_alloc(tpmif_cachep, GFP_KERNEL);
	if (tpmif == NULL)
		goto out_of_memory;

	memset(tpmif, 0, sizeof (*tpmif));
	tpmif->domid = domid;
	tpmif->status = DISCONNECTED;
	tpmif->bi = bi;
	snprintf(tpmif->devname, sizeof(tpmif->devname), "tpmif%d", domid);
	atomic_set(&tpmif->refcnt, 1);

	tpmif->mmap_pages = alloc_empty_pages_and_pagevec(TPMIF_TX_RING_SIZE);
	if (tpmif->mmap_pages == NULL)
		goto out_of_memory;

	list_add(&tpmif->tpmif_list, &tpmif_list);
	num_frontends++;

	return tpmif;

 out_of_memory:
	if (tpmif != NULL)
		kmem_cache_free(tpmif_cachep, tpmif);
	printk("%s: out of memory\n", __FUNCTION__);
	return ERR_PTR(-ENOMEM);
}

static void free_tpmif(tpmif_t * tpmif)
{
	num_frontends--;
	list_del(&tpmif->tpmif_list);
	free_empty_pages_and_pagevec(tpmif->mmap_pages, TPMIF_TX_RING_SIZE);
	kmem_cache_free(tpmif_cachep, tpmif);
}

tpmif_t *tpmif_find(domid_t domid, struct backend_info *bi)
{
	tpmif_t *tpmif;

	list_for_each_entry(tpmif, &tpmif_list, tpmif_list) {
		if (tpmif->bi == bi) {
			if (tpmif->domid == domid) {
				tpmif_get(tpmif);
				return tpmif;
			} else {
				return ERR_PTR(-EEXIST);
			}
		}
	}

	return alloc_tpmif(domid, bi);
}

static int map_frontend_page(tpmif_t *tpmif, unsigned long shared_page)
{
	struct gnttab_map_grant_ref op;

	gnttab_set_map_op(&op, (unsigned long)tpmif->tx_area->addr,
			  GNTMAP_host_map, shared_page, tpmif->domid);

	if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1))
		BUG();

	if (op.status) {
		DPRINTK(" Grant table operation failure !\n");
		return op.status;
	}

	tpmif->shmem_ref = shared_page;
	tpmif->shmem_handle = op.handle;

	return 0;
}

static void unmap_frontend_page(tpmif_t *tpmif)
{
	struct gnttab_unmap_grant_ref op;

	gnttab_set_unmap_op(&op, (unsigned long)tpmif->tx_area->addr,
			    GNTMAP_host_map, tpmif->shmem_handle);

	if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1))
		BUG();
}

int tpmif_map(tpmif_t *tpmif, unsigned long shared_page, unsigned int evtchn)
{
	int err;

	if (tpmif->irq)
		return 0;

	if ((tpmif->tx_area = alloc_vm_area(PAGE_SIZE)) == NULL)
		return -ENOMEM;

	err = map_frontend_page(tpmif, shared_page);
	if (err) {
		free_vm_area(tpmif->tx_area);
		return err;
	}

	tpmif->tx = (tpmif_tx_interface_t *)tpmif->tx_area->addr;

	err = bind_interdomain_evtchn_to_irqhandler(
		tpmif->domid, evtchn, tpmif_be_int, 0, tpmif->devname, tpmif);
	if (err < 0) {
		unmap_frontend_page(tpmif);
		free_vm_area(tpmif->tx_area);
		return err;
	}
	tpmif->irq = err;

	tpmif->shmem_ref = shared_page;
	tpmif->active = 1;

	return 0;
}

void tpmif_disconnect_complete(tpmif_t *tpmif)
{
	if (tpmif->irq)
		unbind_from_irqhandler(tpmif->irq, tpmif);

	if (tpmif->tx) {
		unmap_frontend_page(tpmif);
		free_vm_area(tpmif->tx_area);
	}

	free_tpmif(tpmif);
}

void __init tpmif_interface_init(void)
{
	tpmif_cachep = kmem_cache_create("tpmif_cache", sizeof (tpmif_t),
					 0, 0, NULL, NULL);
}

void __exit tpmif_interface_exit(void)
{
	kmem_cache_destroy(tpmif_cachep);
}
