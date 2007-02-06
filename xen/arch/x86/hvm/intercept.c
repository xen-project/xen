/*
 * intercept.c: Handle performance critical I/O packets in hypervisor space
 *
 * Copyright (c) 2004, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <asm/regs.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/domain.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <io_ports.h>
#include <xen/event.h>
#include <xen/compile.h>
#include <public/version.h>


extern struct hvm_mmio_handler hpet_mmio_handler;
extern struct hvm_mmio_handler vlapic_mmio_handler;
extern struct hvm_mmio_handler vioapic_mmio_handler;

#define HVM_MMIO_HANDLER_NR 3

static struct hvm_mmio_handler *hvm_mmio_handlers[HVM_MMIO_HANDLER_NR] =
{
    &hpet_mmio_handler,
    &vlapic_mmio_handler,
    &vioapic_mmio_handler
};

struct hvm_buffered_io_range {
    unsigned long start_addr;
    unsigned long length;
};

#define HVM_BUFFERED_IO_RANGE_NR 1

static struct hvm_buffered_io_range buffered_stdvga_range = {0xA0000, 0x20000};
static struct hvm_buffered_io_range
*hvm_buffered_io_ranges[HVM_BUFFERED_IO_RANGE_NR] =
{
    &buffered_stdvga_range
};

static inline void hvm_mmio_access(struct vcpu *v,
                                   ioreq_t *p,
                                   hvm_mmio_read_t read_handler,
                                   hvm_mmio_write_t write_handler)
{
    unsigned int tmp1, tmp2;
    unsigned long data;

    switch ( p->type ) {
    case IOREQ_TYPE_COPY:
    {
        if ( !p->data_is_ptr ) {
            if ( p->dir == IOREQ_READ )
                p->data = read_handler(v, p->addr, p->size);
            else    /* p->dir == IOREQ_WRITE */
                write_handler(v, p->addr, p->size, p->data);
        } else {    /* p->data_is_ptr */
            int i, sign = (p->df) ? -1 : 1;

            if ( p->dir == IOREQ_READ ) {
                for ( i = 0; i < p->count; i++ ) {
                    data = read_handler(v,
                        p->addr + (sign * i * p->size),
                        p->size);
                    (void)hvm_copy_to_guest_phys(
                        p->data + (sign * i * p->size),
                        &data,
                        p->size);
                }
            } else {/* p->dir == IOREQ_WRITE */
                for ( i = 0; i < p->count; i++ ) {
                    (void)hvm_copy_from_guest_phys(
                        &data,
                        p->data + (sign * i * p->size),
                        p->size);
                    write_handler(v,
                        p->addr + (sign * i * p->size),
                        p->size, data);
                }
            }
        }
        break;
    }

    case IOREQ_TYPE_AND:
        tmp1 = read_handler(v, p->addr, p->size);
        if ( p->dir == IOREQ_WRITE ) {
            tmp2 = tmp1 & (unsigned long) p->data;
            write_handler(v, p->addr, p->size, tmp2);
        }
        p->data = tmp1;
        break;

    case IOREQ_TYPE_ADD:
        tmp1 = read_handler(v, p->addr, p->size);
        if (p->dir == IOREQ_WRITE) {
            tmp2 = tmp1 + (unsigned long) p->data;
            write_handler(v, p->addr, p->size, tmp2);
        }
        p->data = tmp1;
        break;

    case IOREQ_TYPE_OR:
        tmp1 = read_handler(v, p->addr, p->size);
        if ( p->dir == IOREQ_WRITE ) {
            tmp2 = tmp1 | (unsigned long) p->data;
            write_handler(v, p->addr, p->size, tmp2);
        }
        p->data = tmp1;
        break;

    case IOREQ_TYPE_XOR:
        tmp1 = read_handler(v, p->addr, p->size);
        if ( p->dir == IOREQ_WRITE ) {
            tmp2 = tmp1 ^ (unsigned long) p->data;
            write_handler(v, p->addr, p->size, tmp2);
        }
        p->data = tmp1;
        break;

    case IOREQ_TYPE_XCHG:
        /*
         * Note that we don't need to be atomic here since VCPU is accessing
         * its own local APIC.
         */
        tmp1 = read_handler(v, p->addr, p->size);
        write_handler(v, p->addr, p->size, (unsigned long) p->data);
        p->data = tmp1;
        break;

    default:
        printk("hvm_mmio_access: error ioreq type %x\n", p->type);
        domain_crash_synchronous();
        break;
    }
}

/* List of handlers for various HVM save and restore types */
static struct { 
    hvm_save_handler save;
    hvm_load_handler load; 
    const char *name;
} hvm_sr_handlers [HVM_SAVE_CODE_MAX + 1] = {{NULL, NULL, "<?>"},};

/* Init-time function to add entries to that list */
void hvm_register_savevm(uint16_t typecode, 
                         const char *name,
                         hvm_save_handler save_state,
                         hvm_load_handler load_state)
{
    ASSERT(typecode <= HVM_SAVE_CODE_MAX);
    ASSERT(hvm_sr_handlers[typecode].save == NULL);
    ASSERT(hvm_sr_handlers[typecode].load == NULL);
    hvm_sr_handlers[typecode].save = save_state;
    hvm_sr_handlers[typecode].load = load_state;
    hvm_sr_handlers[typecode].name = name;
}


int hvm_save(struct domain *d, hvm_domain_context_t *h)
{
    uint32_t eax, ebx, ecx, edx;
    char *c;
    struct hvm_save_header hdr;
    struct hvm_save_end end;
    hvm_save_handler handler;
    uint16_t i;

    hdr.magic = HVM_FILE_MAGIC;
    hdr.version = HVM_FILE_VERSION;

    /* Save some CPUID bits */
    cpuid(1, &eax, &ebx, &ecx, &edx);
    hdr.cpuid = eax;

    /* Save xen changeset */
    c = strrchr(XEN_CHANGESET, ':');
    if ( c )
        hdr.changeset = simple_strtoll(c, NULL, 16);
    else 
        hdr.changeset = -1ULL; /* Unknown */

    if ( hvm_save_entry(HEADER, 0, h, &hdr) != 0 )
    {
        gdprintk(XENLOG_ERR, "HVM save: failed to write header\n");
        return -EFAULT;
    } 

    /* Save all available kinds of state */
    for ( i = 0; i <= HVM_SAVE_CODE_MAX; i++ ) 
    {
        handler = hvm_sr_handlers[i].save;
        if ( handler != NULL ) 
        {
            gdprintk(XENLOG_INFO, "HVM save: %s\n",  hvm_sr_handlers[i].name);
            if ( handler(d, h) != 0 ) 
            {
                gdprintk(XENLOG_ERR, 
                         "HVM save: failed to save type %"PRIu16"\n", i);
                return -EFAULT;
            } 
        }
    }

    /* Save an end-of-file marker */
    if ( hvm_save_entry(END, 0, h, &end) != 0 )
    {
        /* Run out of data */
        gdprintk(XENLOG_ERR, "HVM save: no room for end marker.\n");
        return -EFAULT;
    }

    /* Save macros should not have let us overrun */
    ASSERT(h->cur <= h->size);
    return 0;
}

int hvm_load(struct domain *d, hvm_domain_context_t *h)
{
    uint32_t eax, ebx, ecx, edx;
    char *c;
    uint64_t cset;
    struct hvm_save_header hdr;
    struct hvm_save_descriptor *desc;
    hvm_load_handler handler;
    struct vcpu *v;
    
    /* Read the save header, which must be first */
    if ( hvm_load_entry(HEADER, h, &hdr) != 0 ) 
        return -1;

    if (hdr.magic != HVM_FILE_MAGIC) {
        gdprintk(XENLOG_ERR, 
                 "HVM restore: bad magic number %#"PRIx32"\n", hdr.magic);
        return -1;
    }

    if (hdr.version != HVM_FILE_VERSION) {
        gdprintk(XENLOG_ERR, 
                 "HVM restore: unsupported version %u\n", hdr.version);
        return -1;
    }

    cpuid(1, &eax, &ebx, &ecx, &edx);
    /*TODO: need to define how big a difference is acceptable */
    if (hdr.cpuid != eax)
        gdprintk(XENLOG_WARNING, "HVM restore: saved CPUID (%#"PRIx32") "
               "does not match host (%#"PRIx32").\n", hdr.cpuid, eax);


    c = strrchr(XEN_CHANGESET, ':');
    if ( hdr.changeset == -1ULL )
        gdprintk(XENLOG_WARNING, 
                 "HVM restore: Xen changeset was not saved.\n");
    else if ( c == NULL )
        gdprintk(XENLOG_WARNING, 
                 "HVM restore: Xen changeset is not available.\n");
    else
    {
        cset = simple_strtoll(c, NULL, 16);
        if ( hdr.changeset != cset )
        gdprintk(XENLOG_WARNING, "HVM restore: saved Xen changeset (%#"PRIx64
                 ") does not match host (%#"PRIx64").\n", hdr.changeset, cset);
    }

    /* Down all the vcpus: we only re-enable the ones that had state saved. */
    for_each_vcpu(d, v) 
        if ( test_and_set_bit(_VCPUF_down, &v->vcpu_flags) )
            vcpu_sleep_nosync(v);

    while(1) {

        if ( h->size - h->cur < sizeof(struct hvm_save_descriptor) )
        {
            /* Run out of data */
            gdprintk(XENLOG_ERR, 
                     "HVM restore: save did not end with a null entry\n");
            return -1;
        }
        
        /* Read the typecode of the next entry  and check for the end-marker */
        desc = (struct hvm_save_descriptor *)(&h->data[h->cur]);
        if ( desc->typecode == 0 )
            return 0; 
        
        /* Find the handler for this entry */
        if ( desc->typecode > HVM_SAVE_CODE_MAX 
             || (handler = hvm_sr_handlers[desc->typecode].load) == NULL ) 
        {
            gdprintk(XENLOG_ERR, 
                     "HVM restore: unknown entry typecode %u\n", 
                     desc->typecode);
            return -1;
        }

        /* Load the entry */
        gdprintk(XENLOG_INFO, "HVM restore: %s %"PRIu16"\n",  
                 hvm_sr_handlers[desc->typecode].name, desc->instance);
        if ( handler(d, h) != 0 ) 
        {
            gdprintk(XENLOG_ERR, 
                     "HVM restore: failed to load entry %u/%u\n", 
                     desc->typecode, desc->instance);
            return -1;
        }
    }

    /* Not reached */
}


int hvm_buffered_io_intercept(ioreq_t *p)
{
    struct vcpu *v = current;
    spinlock_t  *buffered_io_lock;
    buffered_iopage_t *buffered_iopage =
        (buffered_iopage_t *)(v->domain->arch.hvm_domain.buffered_io_va);
    unsigned long tmp_write_pointer = 0;
    int i;

    /* ignore READ ioreq_t! */
    if ( p->dir == IOREQ_READ )
        return 0;

    for ( i = 0; i < HVM_BUFFERED_IO_RANGE_NR; i++ ) {
        if ( p->addr >= hvm_buffered_io_ranges[i]->start_addr &&
             p->addr + p->size - 1 < hvm_buffered_io_ranges[i]->start_addr +
                                     hvm_buffered_io_ranges[i]->length )
            break;
    }

    if ( i == HVM_BUFFERED_IO_RANGE_NR )
        return 0;

    buffered_io_lock = &v->domain->arch.hvm_domain.buffered_io_lock;
    spin_lock(buffered_io_lock);

    if ( buffered_iopage->write_pointer - buffered_iopage->read_pointer ==
         (unsigned int)IOREQ_BUFFER_SLOT_NUM ) {
        /* the queue is full.
         * send the iopacket through the normal path.
         * NOTE: The arithimetic operation could handle the situation for
         * write_pointer overflow.
         */
        spin_unlock(buffered_io_lock);
        return 0;
    }

    tmp_write_pointer = buffered_iopage->write_pointer % IOREQ_BUFFER_SLOT_NUM;

    memcpy(&buffered_iopage->ioreq[tmp_write_pointer], p, sizeof(ioreq_t));

    /*make the ioreq_t visible before write_pointer*/
    wmb();
    buffered_iopage->write_pointer++;

    spin_unlock(buffered_io_lock);

    return 1;
}

int hvm_mmio_intercept(ioreq_t *p)
{
    struct vcpu *v = current;
    int i;

    for ( i = 0; i < HVM_MMIO_HANDLER_NR; i++ )
    {
        if ( hvm_mmio_handlers[i]->check_handler(v, p->addr) )
        {
            hvm_mmio_access(v, p,
                            hvm_mmio_handlers[i]->read_handler,
                            hvm_mmio_handlers[i]->write_handler);
            return 1;
        }
    }

    return 0;
}

/*
 * Check if the request is handled inside xen
 * return value: 0 --not handled; 1 --handled
 */
int hvm_io_intercept(ioreq_t *p, int type)
{
    struct vcpu *v = current;
    struct hvm_io_handler *handler =
                           &(v->domain->arch.hvm_domain.io_handler);
    int i;
    unsigned long addr, size;

    for (i = 0; i < handler->num_slot; i++) {
        if( type != handler->hdl_list[i].type)
            continue;
        addr = handler->hdl_list[i].addr;
        size = handler->hdl_list[i].size;
        if (p->addr >= addr &&
            p->addr <  addr + size)
            return handler->hdl_list[i].action(p);
    }
    return 0;
}

int register_io_handler(
    struct domain *d, unsigned long addr, unsigned long size,
    intercept_action_t action, int type)
{
    struct hvm_io_handler *handler = &d->arch.hvm_domain.io_handler;
    int num = handler->num_slot;

    BUG_ON(num >= MAX_IO_HANDLER);

    handler->hdl_list[num].addr = addr;
    handler->hdl_list[num].size = size;
    handler->hdl_list[num].action = action;
    handler->hdl_list[num].type = type;
    handler->num_slot++;

    return 1;
}
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
