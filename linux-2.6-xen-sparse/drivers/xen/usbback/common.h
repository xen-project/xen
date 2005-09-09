
#ifndef __USBIF__BACKEND__COMMON_H__
#define __USBIF__BACKEND__COMMON_H__

#include <linux/config.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <asm/io.h>
#include <asm/setup.h>
#include <asm/pgalloc.h>
#include <asm-xen/hypervisor.h>

#include <asm-xen/xen-public/io/usbif.h>

#if 0
#define ASSERT(_p) \
    if ( !(_p) ) { printk("Assertion '%s' failed, line %d, file %s", #_p , \
    __LINE__, __FILE__); *(int*)0=0; }
#define DPRINTK(_f, _a...) printk(KERN_ALERT "(file=%s, line=%d) " _f, \
                           __FILE__ , __LINE__ , ## _a )
#else
#define ASSERT(_p) ((void)0)
#define DPRINTK(_f, _a...) ((void)0)
#endif

typedef struct usbif_priv_st usbif_priv_t;

struct usbif_priv_st {
    /* Unique identifier for this interface. */
    domid_t          domid;
    unsigned int     handle;
    /* Physical parameters of the comms window. */
    unsigned long    shmem_frame;
    unsigned int     evtchn;
    /* Comms Information */
    usbif_back_ring_t usb_ring;
    /* Private fields. */
    enum { DISCONNECTED, DISCONNECTING, CONNECTED } status;
    /*
     * DISCONNECT response is deferred until pending requests are ack'ed.
     * We therefore need to store the id from the original request.
     */
    u8                   disconnect_rspid;
    usbif_priv_t        *hash_next;
    struct list_head     usbif_list;
    spinlock_t           usb_ring_lock;
    atomic_t             refcnt;

    struct work_struct work;
};

void usbif_create(usbif_be_create_t *create);
void usbif_destroy(usbif_be_destroy_t *destroy);
void usbif_connect(usbif_be_connect_t *connect);
int  usbif_disconnect(usbif_be_disconnect_t *disconnect, u8 rsp_id);
void usbif_disconnect_complete(usbif_priv_t *up);

void usbif_release_port(usbif_be_release_port_t *msg);
int usbif_claim_port(usbif_be_claim_port_t *msg);
void usbif_release_ports(usbif_priv_t *up);

usbif_priv_t *usbif_find(domid_t domid);
#define usbif_get(_b) (atomic_inc(&(_b)->refcnt))
#define usbif_put(_b)                             \
    do {                                          \
        if ( atomic_dec_and_test(&(_b)->refcnt) ) \
            usbif_disconnect_complete(_b);        \
    } while (0)


void usbif_interface_init(void);
void usbif_ctrlif_init(void);

void usbif_deschedule(usbif_priv_t *up);
void remove_from_usbif_list(usbif_priv_t *up);

irqreturn_t usbif_be_int(int irq, void *dev_id, struct pt_regs *regs);

#endif /* __USBIF__BACKEND__COMMON_H__ */
