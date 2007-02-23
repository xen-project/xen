/******************************************************************************
 * drivers/xen/tpmback/common.h
 */

#ifndef __TPM__BACKEND__COMMON_H__
#define __TPM__BACKEND__COMMON_H__

#include <linux/version.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <xen/evtchn.h>
#include <xen/driver_util.h>
#include <xen/interface/grant_table.h>
#include <xen/interface/io/tpmif.h>
#include <asm/io.h>
#include <asm/pgalloc.h>

#define DPRINTK(_f, _a...)			\
	pr_debug("(file=%s, line=%d) " _f,	\
		 __FILE__ , __LINE__ , ## _a )

struct backend_info;

typedef struct tpmif_st {
	struct list_head tpmif_list;
	/* Unique identifier for this interface. */
	domid_t domid;
	unsigned int handle;

	/* Physical parameters of the comms window. */
	unsigned int irq;

	/* The shared rings and indexes. */
	tpmif_tx_interface_t *tx;
	struct vm_struct *tx_area;

	/* Miscellaneous private stuff. */
	enum { DISCONNECTED, DISCONNECTING, CONNECTED } status;
	int active;

	struct tpmif_st *hash_next;
	struct list_head list;	/* scheduling list */
	atomic_t refcnt;

	struct backend_info *bi;

	grant_handle_t shmem_handle;
	grant_ref_t shmem_ref;
	struct page **mmap_pages;

	char devname[20];
} tpmif_t;

void tpmif_disconnect_complete(tpmif_t * tpmif);
tpmif_t *tpmif_find(domid_t domid, struct backend_info *bi);
void tpmif_interface_init(void);
void tpmif_interface_exit(void);
void tpmif_schedule_work(tpmif_t * tpmif);
void tpmif_deschedule_work(tpmif_t * tpmif);
void tpmif_xenbus_init(void);
void tpmif_xenbus_exit(void);
int tpmif_map(tpmif_t *tpmif, unsigned long shared_page, unsigned int evtchn);
irqreturn_t tpmif_be_int(int irq, void *dev_id, struct pt_regs *regs);

long int tpmback_get_instance(struct backend_info *bi);

int vtpm_release_packets(tpmif_t * tpmif, int send_msgs);


#define tpmif_get(_b) (atomic_inc(&(_b)->refcnt))
#define tpmif_put(_b)					\
	do {						\
		if (atomic_dec_and_test(&(_b)->refcnt))	\
			tpmif_disconnect_complete(_b);	\
	} while (0)

extern int num_frontends;

static inline unsigned long idx_to_kaddr(tpmif_t *t, unsigned int idx)
{
	return (unsigned long)pfn_to_kaddr(page_to_pfn(t->mmap_pages[idx]));
}

#endif /* __TPMIF__BACKEND__COMMON_H__ */
