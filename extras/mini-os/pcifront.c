/* Minimal PCI driver for Mini-OS. 
 * Copyright (c) 2007-2008 Samuel Thibault.
 * Based on blkfront.c.
 */

#include <os.h>
#include <xenbus.h>
#include <events.h>
#include <errno.h>
#include <gnttab.h>
#include <xmalloc.h>
#include <wait.h>
#include <pcifront.h>

#define PCI_DEVFN(slot, func) ((((slot) & 0x1f) << 3) | ((func) & 0x07))

DECLARE_WAIT_QUEUE_HEAD(pcifront_queue);

struct pcifront_dev {
    domid_t dom;

    struct xen_pci_sharedinfo *info;
    grant_ref_t info_ref;
    evtchn_port_t evtchn;

    char *nodename;
    char *backend;

    xenbus_event_queue events;
};

void pcifront_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
    wake_up(&pcifront_queue);
}

static void free_pcifront(struct pcifront_dev *dev)
{
    mask_evtchn(dev->evtchn);

    free(dev->backend);

    gnttab_end_access(dev->info_ref);
    free_page(dev->info);

    unbind_evtchn(dev->evtchn);

    free(dev->nodename);
    free(dev);
}

struct pcifront_dev *init_pcifront(char *_nodename)
{
    xenbus_transaction_t xbt;
    char* err;
    char* message=NULL;
    int retry=0;
    char* msg;
    char* nodename = _nodename ? _nodename : "device/pci/0";

    struct pcifront_dev *dev;

    char path[strlen(nodename) + 1 + 10 + 1];

    printk("******************* PCIFRONT for %s **********\n\n\n", nodename);

    dev = malloc(sizeof(*dev));
    memset(dev, 0, sizeof(*dev));
    dev->nodename = strdup(nodename);

    snprintf(path, sizeof(path), "%s/backend-id", nodename);
    dev->dom = xenbus_read_integer(path); 
    evtchn_alloc_unbound(dev->dom, pcifront_handler, dev, &dev->evtchn);

    dev->info = (struct xen_pci_sharedinfo*) alloc_page();
    memset(dev->info,0,PAGE_SIZE);

    dev->info_ref = gnttab_grant_access(dev->dom,virt_to_mfn(dev->info),0);

    dev->events = NULL;

again:
    err = xenbus_transaction_start(&xbt);
    if (err) {
        printk("starting transaction\n");
    }

    err = xenbus_printf(xbt, nodename, "pci-op-ref","%u",
                dev->info_ref);
    if (err) {
        message = "writing pci-op-ref";
        goto abort_transaction;
    }
    err = xenbus_printf(xbt, nodename,
                "event-channel", "%u", dev->evtchn);
    if (err) {
        message = "writing event-channel";
        goto abort_transaction;
    }
    err = xenbus_printf(xbt, nodename,
                "magic", XEN_PCI_MAGIC);
    if (err) {
        message = "writing magic";
        goto abort_transaction;
    }

    err = xenbus_printf(xbt, nodename, "state", "%u",
            3); /* initialised */


    err = xenbus_transaction_end(xbt, 0, &retry);
    if (retry) {
            goto again;
        printk("completing transaction\n");
    }

    goto done;

abort_transaction:
    xenbus_transaction_end(xbt, 1, &retry);
    goto error;

done:

    snprintf(path, sizeof(path), "%s/backend", nodename);
    msg = xenbus_read(XBT_NIL, path, &dev->backend);
    if (msg) {
        printk("Error %s when reading the backend path %s\n", msg, path);
        goto error;
    }

    printk("backend at %s\n", dev->backend);

    {
        char path[strlen(dev->backend) + 1 + 5 + 1];
        snprintf(path, sizeof(path), "%s/state", dev->backend);

        xenbus_watch_path_token(XBT_NIL, path, path, &dev->events);

        xenbus_wait_for_value(path, "4", &dev->events);

        xenbus_printf(xbt, nodename, "state", "%u", 4); /* connected */
    }
    unmask_evtchn(dev->evtchn);

    printk("**************************\n");

    return dev;

error:
    free_pcifront(dev);
    return NULL;
}

void pcifront_scan(struct pcifront_dev *dev, void (*func)(unsigned int domain, unsigned int bus, unsigned slot, unsigned int fun))
{
    char path[strlen(dev->backend) + 1 + 5 + 10 + 1];
    int i, n;
    char *s, *msg;
    unsigned int domain, bus, slot, fun;

    snprintf(path, sizeof(path), "%s/num_devs", dev->backend);
    n = xenbus_read_integer(path);

    for (i = 0; i < n; i++) {
        snprintf(path, sizeof(path), "%s/vdev-%d", dev->backend, i);
        msg = xenbus_read(XBT_NIL, path, &s);
        if (msg) {
            printk("Error %s when reading the PCI root name at %s\n", path);
            continue;
        }

        if (sscanf(s, "%x:%x:%x.%x", &domain, &bus, &slot, &fun) != 4) {
            printk("\"%s\" does not look like a PCI device address\n", s);
            free(s);
            continue;
        }
        free(s);

        func(domain, bus, slot, fun);
    }
}

void shutdown_pcifront(struct pcifront_dev *dev)
{
    char* err;
    char *nodename = dev->nodename;

    char path[strlen(dev->backend) + 1 + 5 + 1];

    printk("close pci: backend at %s\n",dev->backend);

    snprintf(path, sizeof(path), "%s/state", dev->backend);
    err = xenbus_printf(XBT_NIL, nodename, "state", "%u", 5); /* closing */
    xenbus_wait_for_value(path, "5", &dev->events);

    err = xenbus_printf(XBT_NIL, nodename, "state", "%u", 6);
    xenbus_wait_for_value(path, "6", &dev->events);

    err = xenbus_printf(XBT_NIL, nodename, "state", "%u", 1);
    xenbus_wait_for_value(path, "2", &dev->events);

    xenbus_unwatch_path(XBT_NIL, path);

    snprintf(path, sizeof(path), "%s/info-ref", nodename);
    xenbus_rm(XBT_NIL, path);
    snprintf(path, sizeof(path), "%s/event-channel", nodename);
    xenbus_rm(XBT_NIL, path);

    free_pcifront(dev);
}


void pcifront_op(struct pcifront_dev *dev, struct xen_pci_op *op)
{
    dev->info->op = *op;
    /* Make sure info is written before the flag */
    wmb();
    set_bit(_XEN_PCIF_active, &dev->info->flags);
    notify_remote_via_evtchn(dev->evtchn);

    wait_event(pcifront_queue, !test_bit(_XEN_PCIF_active, &dev->info->flags));

    /* Make sure flag is read before info */
    rmb();
    *op = dev->info->op;
}

int pcifront_conf_read(struct pcifront_dev *dev,
                       unsigned int dom,
                       unsigned int bus, unsigned int slot, unsigned long fun,
                       unsigned int off, unsigned int size, unsigned int *val)
{
    struct xen_pci_op op;

    memset(&op, 0, sizeof(op));

    op.cmd = XEN_PCI_OP_conf_read;
    op.domain = dom;
    op.bus = bus;
    op.devfn = PCI_DEVFN(slot, fun);
    op.offset = off;
    op.size = size;

    pcifront_op(dev, &op);

    if (op.err)
        return op.err;

    *val = op.value;

    return 0;
}

int pcifront_conf_write(struct pcifront_dev *dev,
                        unsigned int dom,
                        unsigned int bus, unsigned int slot, unsigned long fun,
                        unsigned int off, unsigned int size, unsigned int val)
{
    struct xen_pci_op op;

    memset(&op, 0, sizeof(op));

    op.cmd = XEN_PCI_OP_conf_write;
    op.domain = dom;
    op.bus = bus;
    op.devfn = PCI_DEVFN(slot, fun);
    op.offset = off;
    op.size = size;

    op.value = val;

    pcifront_op(dev, &op);

    return op.err;
}

int pcifront_enable_msi(struct pcifront_dev *dev,
                        unsigned int dom,
                        unsigned int bus, unsigned int slot, unsigned long fun)
{
    struct xen_pci_op op;

    memset(&op, 0, sizeof(op));

    op.cmd = XEN_PCI_OP_enable_msi;
    op.domain = dom;
    op.bus = bus;
    op.devfn = PCI_DEVFN(slot, fun);

    pcifront_op(dev, &op);
    
    if (op.err)
        return op.err;
    else
        return op.value;
}

int pcifront_disable_msi(struct pcifront_dev *dev,
                         unsigned int dom,
                         unsigned int bus, unsigned int slot, unsigned long fun)
{
    struct xen_pci_op op;

    memset(&op, 0, sizeof(op));

    op.cmd = XEN_PCI_OP_disable_msi;
    op.domain = dom;
    op.bus = bus;
    op.devfn = PCI_DEVFN(slot, fun);

    pcifront_op(dev, &op);
    
    return op.err;
}

int pcifront_enable_msix(struct pcifront_dev *dev,
                         unsigned int dom,
                         unsigned int bus, unsigned int slot, unsigned long fun,
                         struct xen_msix_entry *entries, int n)
{
    struct xen_pci_op op;

    if (n > SH_INFO_MAX_VEC)
        return XEN_PCI_ERR_op_failed;

    memset(&op, 0, sizeof(op));

    op.cmd = XEN_PCI_OP_enable_msix;
    op.domain = dom;
    op.bus = bus;
    op.devfn = PCI_DEVFN(slot, fun);
    op.value = n;

    memcpy(op.msix_entries, entries, n * sizeof(*entries));

    pcifront_op(dev, &op);
    
    if (op.err)
        return op.err;

    memcpy(entries, op.msix_entries, n * sizeof(*entries));

    return 0;
}


int pcifront_disable_msix(struct pcifront_dev *dev,
                          unsigned int dom,
                          unsigned int bus, unsigned int slot, unsigned long fun)
{
    struct xen_pci_op op;

    memset(&op, 0, sizeof(op));

    op.cmd = XEN_PCI_OP_disable_msix;
    op.domain = dom;
    op.bus = bus;
    op.devfn = PCI_DEVFN(slot, fun);

    pcifront_op(dev, &op);
    
    return op.err;
}
