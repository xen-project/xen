/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2004 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: phys_dev.c
 *      Author: Rolf Neugebauer (rolf.neugebauer@intel.com)
 *        Date: Feb 2004
 * 
 * Description: allows a domain to access devices on the PCI bus
 *
 * a guest os may be given access to particular devices on the PCI
 * bus. to allow the standard PCI device discovery to work it may
 * also have limited access to devices (bridges) in the PCI device
 * tree between the device and the PCI root device.
 *
 * for each domain a list of PCI devices is maintained, describing the
 * access mode for the domain. 
 *
 * guests can figure out the virtualised, or better, partioned PCI space
 * through normal pci config register access. Some of the accesses, in
 * particular write access are faked out. For example the sequence for
 * for detecting the IO regions, which require writes to determine the
 * size of teh region, is faked out by a very simple state machine, 
 * preventing direct writes to the PCI config registers by a guest.
 *
 * Interrupt handling is currently done in a very cheese fashion.
 * We take the default irq controller code and replace it with our own.
 * If an interrupt comes in it is acked using the PICs normal routine. Then
 * an event is send to the receiving domain which has to explicitly call
 * once it is finished dealing with the interrupt. Only then the PICs end
 * handler is called. very cheesy with all sorts of problems but it seems 
 * to work in normal cases. No shared interrupts are allowed.
 *
 * XXX this code is not SMP safe at the moment!
 */


#include <xen/config.h>
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/pci.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <asm/pci.h>
#include <hypervisor-ifs/hypervisor-if.h>
#include <hypervisor-ifs/physdev.h>

#if 1
#define DBG(_x...)
#else
#define DBG(_x...) printk(_x)
#endif

#define ACC_READ  1
#define ACC_WRITE 2

/* upper bounds for PCI  devices */
#define PCI_BUSMAX  255
#define PCI_DEVMAX   31
#define PCI_FUNCMAX   7
#define PCI_REGMAX  255

/* bit offsets into state */
#define ST_BASE_ADDRESS  0   /* bits 0-5: are for base address access */
#define ST_ROM_ADDRESS   6   /* bit 6: is for rom address access */    
#define ST_IRQ_DELIVERED 7   /* bit 7: waiting for end irq call */    

typedef struct _phys_dev_st
{
    int flags;                       /* flags for access etc */
    struct pci_dev *dev;             /* the device */
    struct list_head node;           /* link to the list */
    struct task_struct *owner;       /* 'owner of this device' */
    int state;                       /* state for various checks */

    hw_irq_controller *new_handler;  /* saved old handler */
    hw_irq_controller *orig_handler; /* saved old handler */

} phys_dev_t;


#define MAX_IRQS 32
/* an array of device descriptors index by IRQ number */
static phys_dev_t *irqs[MAX_IRQS];

/*
 * 
 * General functions
 * 
 */

/* find a device on the device list */
static phys_dev_t *find_pdev(struct task_struct *p, struct pci_dev *dev)
{
    phys_dev_t *t, *res = NULL;
    struct list_head *tmp;

    list_for_each(tmp, &p->pcidev_list)
    {
        t = list_entry(tmp,  phys_dev_t, node);
        if ( dev == t->dev )
        {
            res = t;
            break;
        }
    }
    return res;
}

/* add the device to the list of devices task p can access */
static void add_dev_to_task(struct task_struct *p, 
                            struct pci_dev *dev, int acc)
{
    
    phys_dev_t *pdev;
    
    if ( (pdev = find_pdev(p, dev)) )
    {
        /* device already on list, update access  */
        pdev->flags = acc;
        return;
    }

    /* add device */
    if ( !(pdev = kmalloc(sizeof(phys_dev_t), GFP_KERNEL)) )
    {
        printk("error allocating pdev structure\n");
        return;
    }
    
    pdev->dev = dev;
    pdev->flags = acc;
    pdev->state = 0;
    list_add(&pdev->node, &p->pcidev_list);

    if ( acc == ACC_WRITE )
        pdev->owner = p;

}

/*
 * physdev_pci_access_modify:
 * Allow/disallow access to a specific PCI device. Also allow read access to 
 * PCI devices from the device to the root of the device tree. If the given 
 * device is a bridge, then the domain should get access to all the devices 
 * attached to that bridge (XXX this is unimplemented!).
 */
int physdev_pci_access_modify(
    domid_t dom, int bus, int dev, int func, int enable)
{
    struct task_struct *p;
    struct pci_dev *pdev, *rdev, *tdev;
 
    if ( !IS_PRIV(current) )
        BUG();

    if ( (bus > PCI_BUSMAX) || (dev > PCI_DEVMAX) || (func > PCI_FUNCMAX) )
        return -EINVAL;

    if ( !enable )
    {
        DPRINTK("Disallowing access is not yet supported.\n");
        return -EINVAL;
    }

    DPRINTK("physdev_pci_access_modify: %02x:%02x:%02x\n", bus, dev, func);

    if ( (p = find_domain_by_id(dom)) == NULL ) 
        return -ESRCH;

    /* Make the domain privileged. */
    set_bit(PF_PRIVILEGED, &p->flags); 

    /* Grant write access to the specified device. */
    if ( (pdev = pci_find_slot(bus, PCI_DEVFN(dev, func))) == NULL )
    {
        DPRINTK("  dev does not exist\n");
        return -ENODEV;
    }
    add_dev_to_task(p, pdev, ACC_WRITE);
    DPRINTK("  add RW %02x:%02x:%02x\n", pdev->bus->number,
            PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));


    /* Grant read access to the root device. */
    if ( (rdev = pci_find_slot(0, PCI_DEVFN(0, 0))) == NULL )
    {
        DPRINTK("  bizarre -- no PCI root dev\n");
        return -ENODEV;
    }
    add_dev_to_task(p, rdev, ACC_READ);
    DPRINTK("  add R0 %02x:%02x:%02x\n", 0, 0, 0);

    /* Grant read access to all devices on the path to the root. */
    for ( tdev = pdev->bus->self; tdev != NULL; tdev = tdev->bus->self )
    {
        add_dev_to_task(p, tdev, ACC_READ);
        DPRINTK("  add RO %02x:%02x:%02x\n", tdev->bus->number,
                PCI_SLOT(tdev->devfn), PCI_FUNC(tdev->devfn));
    }

    if ( pdev->hdr_type == PCI_HEADER_TYPE_NORMAL )
        return 0;
    
    /* The  device is a bridge or cardbus. */
    printk("XXX can't give access to bridge devices yet\n");

    return 0;
}

/* check if a domain has general access to a device */
inline static int check_dev_acc (struct task_struct *p,
                                 int bus, int dev, int func,
                                 phys_dev_t **pdev) 
{
    struct pci_dev *target_dev;
    phys_dev_t     *target_pdev;
    unsigned int    target_devfn;

    *pdev = NULL;

    if ( !IS_PRIV(p) )
        return -EPERM; /* no pci acces permission */

    if ( bus > PCI_BUSMAX || dev > PCI_DEVMAX || func > PCI_FUNCMAX )
        return -EINVAL;

    DBG("a=%c b=%x d=%x f=%x ", (acc == ACC_READ) ? 'R' : 'W',
        mask, bus, dev, func);

    /* check target device */
    target_devfn = PCI_DEVFN(dev, func);
    target_dev   = pci_find_slot(bus, target_devfn);
    if ( !target_dev )
    {
        DBG("target does not exist\n");
        return -ENODEV;
    }

    /* check access */
    target_pdev = find_pdev(p, target_dev);
    if ( !target_pdev )
    {
        DBG("dom has no access to target\n");
        return -EPERM;
    }

    *pdev = target_pdev;
    return 0;
}

/*
 * 
 * PCI config space access
 * 
 */

/*
 * Base address registers contain the base address for IO regions.
 * The length can be determined by writing all 1s to the register and
 * reading the value again. The device will zero the lower unused bits.
 * 
 * to work out the length of the io region a device probe typically does:
 * 1) a = read_base_addr_reg()
 * 2) write_base_addr_reg(0xffffffff)
 * 3) b = read_base_addr_reg() // device zeros lower bits
 * 4) write_base_addr_reg(a) // restore original value
 * this function fakes out step 2-4. *no* writes are made to the device.
 * 
 * phys_dev_t contains a bit field (a bit for each base address register).
 * if the bit for a register is set the guest had writen all 1s to the 
 * register and subsequent read request need to fake out the b.
 * if the guest restores the original value (step 4 above) the bit is
 * cleared again. If the guest attempts to "restores" a wrong value an
 * error is flagged.
 */
static int do_base_address_access(phys_dev_t *pdev, int acc,
                                  int seg, int bus, int dev, int func, 
                                  int reg, int len, u32 *val)
{
    int idx, st_bit, ret = -EINVAL;
    u32 orig_val, sz;
    struct resource *res;

    idx    = (reg - PCI_BASE_ADDRESS_0)/4;
    st_bit = idx + ST_BASE_ADDRESS;
    res    = &(pdev->dev->resource[idx]);

    if ( acc == ACC_WRITE )
    {
        if ( *val == 0xffffffff || 
             ((res->flags & IORESOURCE_IO) && *val == 0xffff) )
        {
            /* set bit and return */
            set_bit(st_bit, &pdev->state);
            ret = 0;
        }
        else
        {
            /* assume guest wants to set the base address */
            clear_bit(st_bit, &pdev->state);

            /* check if guest tries to restore orig value */
            ret = pci_config_read(seg, bus, dev, func, reg, len, &orig_val);
            if ( *val != orig_val ) 
            {
                printk("caution: guest tried to change base address range.\n");
                ret = -EPERM;
            }
        }
        DBG("fixed pci write: %02x:%02x:%02x reg=0x%02x len=0x%02x"
            " val=0x%08x %lx\n", bus, dev, func, reg, len, *val,
            pdev->state);

    }

    else if ( acc == ACC_READ )
    {
        if ( !test_bit(st_bit, &pdev->state) )
        {
            /* just read and return */
            ret = pci_config_read(seg, bus, dev, func, reg, len, val);
        }
        else
        {
            /* fake value */
            ret = pci_config_read(seg, bus, dev, func, reg, len, &orig_val);

            sz  = res->end - res->start;

            if ( res->flags & IORESOURCE_MEM )
            {
                /* this is written out explicitly for clarity */
                *val = 0xffffffff;
                /* bit    0 = 0 */
                /* bit  21  = memory type */
                /* bit 3    = prefetchable */
                /* bit 4-31 width */
                sz   = sz >> 4; /* size in blocks of 16 byte */
                sz   = ~sz;     /* invert */
                *val = *val & (sz << 4); /* and in the size */
                /* use read values for low 4 bits */
                *val = *val | (orig_val & 0xf);
            }
            else if ( res->flags & IORESOURCE_IO )
            {
                *val = 0x0000ffff;
                /* bit 10 = 01 */
                /* bit 2-31 width */
                sz   = sz >> 2; /* size in dwords */
                sz   = ~sz & 0x0000ffff;
                *val = *val & (sz << 2);
                *val = *val | 0x1;
            }
            ret = 0;
        }
        DBG("fixed pci read : %02x:%02x:%02x reg=0x%02x len=0x%02x"
            " val=0x%08x %lx\n", bus, dev, func, reg, len, *val, pdev->state);
    }

    return ret;
}

/*
 * fake out read/write access to rom address register
 * pretty much the same as a above
 */
static int do_rom_address_access(phys_dev_t *pdev, int acc,
                                  int seg, int bus, int dev, int func, 
                                  int reg, int len, u32 *val)
{
    int st_bit, ret = -EINVAL;
    u32 orig_val, sz;
    struct resource *res;

    st_bit = ST_ROM_ADDRESS;
    res = &(pdev->dev->resource[PCI_ROM_RESOURCE]);

    if ( acc == ACC_WRITE )
    {
        if ( *val == 0xffffffff || *val == 0xfffffffe)
        {
            /* 0xffffffff would be unusual, but we check anyway */
            /* set bit and return */
            set_bit(st_bit, &pdev->state);
            ret = 0;
        }
        else
        {
            /* assume guest wants to set the base address */
            clear_bit(st_bit, &pdev->state);
            
            /* check if guest tries to restore orig value */
            ret = pci_config_read(seg, bus, dev, func, reg, len, &orig_val);
            if ( (*val != orig_val) ) 
            {
                if (*val != 0x00000000 )
                {
                    printk("caution: guest tried to change rom address.\n");
                    ret = -EPERM;
                }
                else
                {
                    printk ("guest disabled rom access for %02x:%02x:%02x\n",
                            bus, dev, func);
                    ret = 0;
                }
            }

        }
        DBG("fixed pci write: %02x:%02x:%02x reg=0x%02x len=0x%02x"
            " val=0x%08x %lx\n", bus, dev, func, reg, len, *val, pdev->state);
     
    }
    else if ( acc == ACC_READ )
    {
       if ( !test_bit(st_bit, &pdev->state) )
        {
            /* just read and return */
            ret = pci_config_read(seg, bus, dev, func, reg, len, val);
        }
        else
        {
            /* fake value */
            ret = pci_config_read(seg, bus, dev, func, reg, len, &orig_val);
            sz  = res->end - res->start;
            *val = 0xffffffff;
            /* leave bit 0 untouched */
            /* bit 1-10 reserved, harwired to 0 */
            sz = sz >> 11; /* size is in 2KB blocks */
            sz = ~sz;
            *val = *val & (sz << 11);
            *val = *val | (orig_val & 0x1);
        }

        DBG("fixed pci read : %02x:%02x:%02x reg=0x%02x len=0x%02x"
            " val=0x%08x %lx\n", bus, dev, func, reg, len, *val, pdev->state);
    }
    return ret;

}

/*
 * handle a domains pci config space read access if it has access to
 * the device.
 * For some registers for read-only devices (e.g. address base registers)
 * we need to maintain a state machine.
 */
static long pci_cfgreg_read(int seg, int bus, int dev, int func, int reg,
                            int len, u32 *val)
{
    int ret = 0;
    phys_dev_t *pdev;

    ret = check_dev_acc(current, bus, dev, func, &pdev);
    if ( ret != 0 )
        return ret;

    /* fake out read requests for some registers */
    switch (reg)
    {
    case PCI_BASE_ADDRESS_0:
    case PCI_BASE_ADDRESS_1:
    case PCI_BASE_ADDRESS_2:
    case PCI_BASE_ADDRESS_3:
    case PCI_BASE_ADDRESS_4:
    case PCI_BASE_ADDRESS_5:
        ret = do_base_address_access (pdev, ACC_READ, seg, bus, dev, 
                                      func, reg, len, val);
        return ret;
        break;
    case PCI_ROM_ADDRESS:
        ret = do_rom_address_access (pdev, ACC_READ, seg, bus, dev, 
                                      func, reg, len, val);
        return ret;
        break;        
    default:
        break;
    }

    ret = pci_config_read(seg, bus, dev, func, reg, len, val);

    DBG("pci read : %02x:%02x:%02x reg=0x%02x len=0x%02x val=0x%08x\n",
        bus, dev, func, reg, len, *val);
    return ret;
}

/*
 * handle a domains pci config space write accesses if it has access to
 * the device.
 * for some registers a state machine is maintained to fake out r/w access.
 * By default no write access is allowed but we may change that in the future.
 */
static long pci_cfgreg_write(int seg, int bus, int dev, int func, int reg,
                             int len, u32 val)
{
    int ret = 0;
    phys_dev_t *pdev;

    ret = check_dev_acc(current, bus, dev, func, &pdev);
    if ( ret != 0 )
        return ret;

    /* special treatment for some registers */
    switch (reg)
    {
    case PCI_BASE_ADDRESS_0:
    case PCI_BASE_ADDRESS_1:
    case PCI_BASE_ADDRESS_2:
    case PCI_BASE_ADDRESS_3:
    case PCI_BASE_ADDRESS_4:
    case PCI_BASE_ADDRESS_5:
        ret = do_base_address_access (pdev, ACC_WRITE, seg, bus, dev, 
                                      func, reg, len, &val);
        return ret;
        break;
    case PCI_ROM_ADDRESS:
        ret = do_rom_address_access (pdev, ACC_WRITE, seg, bus, dev, 
                                      func, reg, len, &val);
        return ret;
        break;        
#if 0
    case 0xe0: /* XXX some device drivers seem to write to this.... */
        printk("pci write hack allowed %02x:%02x:%02x: "
                   "reg=0x%02x len=0x%02x val=0x%08x\n",
                   bus, dev, func, reg, len, val);
        break;        
#endif
    default:
        //if ( pdev->flags != ACC_WRITE ) 
        /* XXX for debug we disallow all write access */
        {
            printk("pci write not allowed %02x:%02x:%02x: "
                   "reg=0x%02x len=0x%02x val=0x%08x\n",
                   bus, dev, func, reg, len, val);
            return -EPERM;
        }
        break;
    }

    ret = pci_config_write(seg, bus, dev, func, reg, len, val);

    DBG("pci write: %02x:%02x:%02x reg=0x%02x len=0x%02x val=0x%08x\n",
        bus, dev, func, reg, len, val);
    return ret;
}

/*
 * 
 * Interrupt handling
 * 
 */


/*
 * return the IRQ xen assigned to the device.
 * This may be different to what is in the PCI confic space!
 * XXX RN: I'm not sure we need this. we could just intercept PCI config
 * reads on PCI_INTERRUPT_LINE and return the correct value.
 */
static long pci_find_irq(int seg, int bus, int dev, int func, u32 *val)
{
    int ret = 0;
    phys_dev_t *pdev;

    ret = check_dev_acc(current, bus, dev, func, &pdev);
    if ( ret != 0 )
        return ret;

    *val = pdev->dev->irq;
    return 0;
}

static void phys_dev_interrupt(int irq, void *dev_id, struct pt_regs *ptregs)
{
    phys_dev_t          *pdev;
    struct task_struct  *p;
    unsigned long cpu_mask = 0;

    if ( !(pdev = (phys_dev_t *)dev_id) )
    {
        printk("spurious interrupt, no proper device id, %d\n", irq);
        return;
    }
    
    p = pdev->owner;

    if ( test_bit(irq, &p->shared_info->physirq_pend) )
    {
        /* Some interrupt already delivered to guest */
        return;
    }

    /* notify guest */
    set_bit(irq, &p->shared_info->physirq_pend);
    set_bit(ST_IRQ_DELIVERED, &pdev->state);
    cpu_mask |= mark_guest_event(p, _EVENT_PHYSIRQ);
    guest_event_notify(cpu_mask);
}

/* this is called instead of the PICs original end handler. 
 * the real end handler is only called once the guest signalled the handling
 * of the event. */
static void end_virt_irq (unsigned int i)
{
    /* nothing */
}

/*
 * a guest request an IRQ from a device to be routed to it
 * - shared interrupts are not allowed for now
 * - we change the hw_irq handler to something else
 */
static long pci_request_irq(int irq)
{
    int err;
    phys_dev_t *pdev = NULL, *t;
    hw_irq_controller *new, *orig;
    struct list_head *tmp;

    printk("request irq %d\n", irq);

    /* find pdev */

    list_for_each(tmp, &current->pcidev_list)
    {
        t = list_entry(tmp,  phys_dev_t, node);
        if ( t->dev->irq == irq )
        {
            pdev = t;
            break;
        }
    }

    if ( pdev == NULL )
    {
        printk("no device matching IRQ %d\n", irq);
        return -EINVAL;
    }

    if ( irq >= MAX_IRQS )
    {
        printk("requested IRQ to big %d\n", irq);
        return -EINVAL;
    }

    if ( irqs[irq] != NULL )
    {
        printk ("irq already in use %d\n", irq);
        return -EPERM;
    }

    /* allocate a hw_irq controller and copy the original */
    if ( !(new  = kmalloc(sizeof(hw_irq_controller), GFP_KERNEL)) )
    {
        printf("error allocating new irq controller\n");
        return -ENOMEM;
    }
    orig = irq_desc[irq].handler;
    new->typename = orig->typename;
    new->startup = orig->startup;
    new->shutdown = orig->shutdown;
    new->enable = orig->enable;
    new->disable = orig->disable;
    new->ack = orig->ack;
    new->end = orig->end;
    new->set_affinity = orig->set_affinity;

    /* swap the end routine */
    new->end = end_virt_irq;

    /* change the irq controllers */
    pdev->orig_handler = orig;
    pdev->new_handler  = new;
    irq_desc[irq].handler = new;
    irqs[irq] = pdev;
    
    printk ("setup handler %d\n", irq);

    /* request the IRQ. this is not shared and we use a slow handler! */
    err = request_irq(irq, phys_dev_interrupt, SA_INTERRUPT,
                      "foo", (void *)pdev);
    if ( err )
    {
        printk("error requesting irq\n");
        /* restore original */
        irq_desc[irq].handler = pdev->orig_handler;
        /* free memory */
        kfree(new);
        return err;
    }

    printk ("done\n");

    return 0;
}

static long pci_free_irq(int irq)
{
    phys_dev_t *pdev;

    if ( irq >= MAX_IRQS )
    {
        printk("requested IRQ to big %d\n", irq);
        return -EINVAL;
    }

    if ( irqs[irq] == NULL )
    {
        printk ("irq not used %d\n", irq);
        return -EINVAL;
    }

    pdev = irqs[irq];

    /* shutdown IRQ */
    free_irq(irq, (void *)pdev);

    /* restore irq controller  */
    irq_desc[irq].handler = pdev->orig_handler;

    /* clean up */
    pdev->orig_handler = NULL;
    irqs[irq] = NULL;
    kfree(pdev->new_handler);
    pdev->new_handler = NULL;

    printk("freed irq %d", irq);
    return 0;
}

static long pci_enable_irq(int irq)
{
    /* XXX not sure we need this */
    /* guest can enable phys_irq event for now */
    return 0;
}

static long pci_disable_irq(int irq)
{
    /* XXX not sure we need this */
    /* guest can disable phys_irq event for now */
    return 0;
}

static long pci_finished_irq(int irq)
{
    phys_dev_t *pdev;
    
    if ( !(pdev = irqs[irq]) )
    {
        printk("finished_irq called for unregistered irq %d\n", irq);
        return -EINVAL;
    }
   
    if ( pdev->owner != current )
    {
        printk("finished_irq called dom not owning irq %d\n", irq);
        return -EPERM;
    }

    if ( !test_bit(ST_IRQ_DELIVERED, &pdev->state) )
    {
        printk("finished_irq called for undelivered irq %d\n", irq);
        return -EINVAL;
    }

    if ( test_bit(irq, &current->shared_info->physirq_pend) )
    {
        printk("finished_irq called for un-acknowleged irq %d\n", irq);        
        return -EINVAL;
    }

    clear_bit(ST_IRQ_DELIVERED, &pdev->state);

    /* call original end handler */
    pdev->orig_handler->end(irq);

    return 0;
}


/*
 * demux hypervisor call.
 */
long do_physdev_op(physdev_op_t *uop)
{
    physdev_op_t op;
    long ret;

    if ( unlikely(copy_from_user(&op, uop, sizeof(op)) != 0) )
        return -EFAULT;

    switch ( op.cmd )
    {
    case PHYSDEVOP_CFGREG_READ:
        ret = pci_cfgreg_read (op.u.cfg_read.seg, op.u.cfg_read.bus,
                               op.u.cfg_read.dev, op.u.cfg_read.func,
                               op.u.cfg_read.reg, op.u.cfg_read.len,
                               &op.u.cfg_read.value);
        break;

    case PHYSDEVOP_CFGREG_WRITE:
        ret = pci_cfgreg_write (op.u.cfg_write.seg, op.u.cfg_write.bus,
                                op.u.cfg_write.dev, op.u.cfg_write.func,
                                op.u.cfg_write.reg, op.u.cfg_write.len,
                                op.u.cfg_write.value);
        break;

    case PHYSDEVOP_FIND_IRQ:
        ret = pci_find_irq (op.u.find_irq.seg, op.u.find_irq.bus,
                            op.u.find_irq.dev, op.u.find_irq.func,
                            &op.u.find_irq.irq);
        break;

    case PHYSDEVOP_REQUEST_IRQ:
        ret = pci_request_irq (op.u.request_irq.irq);
        break;

    case PHYSDEVOP_FREE_IRQ:
        ret = pci_free_irq (op.u.free_irq.irq);
        break;

    case PHYSDEVOP_ENABLE_IRQ:
        ret = pci_enable_irq (op.u.enable_irq.irq);
        break;

    case PHYSDEVOP_DISABLE_IRQ:
        ret = pci_disable_irq (op.u.disable_irq.irq);
        break;

    case PHYSDEVOP_FINISHED_IRQ:
        ret = pci_finished_irq (op.u.finished_irq.irq);
        break;

    default:
        ret = -EINVAL;
        break;
    }

    copy_to_user(uop, &op, sizeof(op));
    return ret;
}


/*
 * Domain 0 has read access to all devices.
 * XXX this is a bit of a hack
 */
void physdev_init_dom0(struct task_struct *p)
{
    struct pci_dev *dev;
    phys_dev_t *pdev;

    printk("Give DOM0 read access to all PCI devices\n");

    pci_for_each_dev(dev)
    {
        /* add device */
        pdev = kmalloc(sizeof(phys_dev_t), GFP_KERNEL);
        pdev->dev = dev;
        pdev->flags = ACC_READ;
        pdev->state = 0;
        pdev->owner = p;
        list_add(&pdev->node, &p->pcidev_list);
	}    
}
