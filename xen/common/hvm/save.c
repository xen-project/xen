/*
 * hvm/save.c: Save and restore HVM guest's emulated hardware state.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2007, XenSource Inc.
 * Copyright (c) 2007, Isaku Yamahata <yamahata at valinux co jp>
 *                     VA Linux Systems Japan K.K.
 *                     split arch generic part
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
#include <xen/lib.h>
#include <xen/version.h>
#include <public/version.h>
#include <xen/sched.h>
#include <xen/guest_access.h>

#include <asm/hvm/support.h>

/* List of handlers for various HVM save and restore types */
static struct { 
    hvm_save_handler save;
    hvm_load_handler load; 
    const char *name;
    size_t size;
    int kind;
} hvm_sr_handlers [HVM_SAVE_CODE_MAX + 1] = {{NULL, NULL, "<?>"},};

/* Init-time function to add entries to that list */
void __init hvm_register_savevm(uint16_t typecode,
                                const char *name,
                                hvm_save_handler save_state,
                                hvm_load_handler load_state,
                                size_t size, int kind)
{
    ASSERT(typecode <= HVM_SAVE_CODE_MAX);
    ASSERT(hvm_sr_handlers[typecode].save == NULL);
    ASSERT(hvm_sr_handlers[typecode].load == NULL);
    hvm_sr_handlers[typecode].save = save_state;
    hvm_sr_handlers[typecode].load = load_state;
    hvm_sr_handlers[typecode].name = name;
    hvm_sr_handlers[typecode].size = size;
    hvm_sr_handlers[typecode].kind = kind;
}

size_t hvm_save_size(struct domain *d) 
{
    struct vcpu *v;
    size_t sz;
    int i;
    
    /* Basic overhead for header and footer */
    sz = (2 * sizeof (struct hvm_save_descriptor)) + HVM_SAVE_LENGTH(HEADER);

    /* Plus space for each thing we will be saving */
    for ( i = 0; i <= HVM_SAVE_CODE_MAX; i++ ) 
        if ( hvm_sr_handlers[i].kind == HVMSR_PER_VCPU )
            for_each_vcpu(d, v)
                sz += hvm_sr_handlers[i].size;
        else 
            sz += hvm_sr_handlers[i].size;

    return sz;
}

/* Extract a single instance of a save record, by marshalling all
 * records of that type and copying out the one we need. */
int hvm_save_one(struct domain *d, uint16_t typecode, uint16_t instance, 
                 XEN_GUEST_HANDLE_64(uint8) handle)
{
    int rv = 0;
    size_t sz = 0;
    struct vcpu *v;
    hvm_domain_context_t ctxt = { 0, };

    if ( d->is_dying 
         || typecode > HVM_SAVE_CODE_MAX 
         || hvm_sr_handlers[typecode].size < sizeof(struct hvm_save_descriptor)
         || hvm_sr_handlers[typecode].save == NULL )
        return -EINVAL;

    if ( hvm_sr_handlers[typecode].kind == HVMSR_PER_VCPU )
        for_each_vcpu(d, v)
            sz += hvm_sr_handlers[typecode].size;
    else 
        sz = hvm_sr_handlers[typecode].size;
    
    ctxt.size = sz;
    ctxt.data = xmalloc_bytes(sz);
    if ( !ctxt.data )
        return -ENOMEM;

    if ( hvm_sr_handlers[typecode].save(d, &ctxt) != 0 )
    {
        printk(XENLOG_G_ERR "HVM%d save: failed to save type %"PRIu16"\n",
               d->domain_id, typecode);
        rv = -EFAULT;
    }
    else
    {
        uint32_t off;
        const struct hvm_save_descriptor *desc;

        rv = -EBADSLT;
        for ( off = 0; off < (ctxt.cur - sizeof(*desc)); off += desc->length )
        {
            desc = (void *)(ctxt.data + off);
            /* Move past header */
            off += sizeof(*desc);
            if ( instance == desc->instance )
            {
                uint32_t copy_length = desc->length;

                if ( off + copy_length > ctxt.cur )
                    copy_length = ctxt.cur - off;
                rv = 0;
                if ( copy_to_guest(handle, ctxt.data + off, copy_length) )
                    rv = -EFAULT;
                break;
            }
        }
    }

    xfree(ctxt.data);
    return rv;
}

int hvm_save(struct domain *d, hvm_domain_context_t *h)
{
    char *c;
    struct hvm_save_header hdr;
    struct hvm_save_end end;
    hvm_save_handler handler;
    uint16_t i;

    if ( d->is_dying )
        return -EINVAL;

    hdr.magic = HVM_FILE_MAGIC;
    hdr.version = HVM_FILE_VERSION;

    /* Save xen changeset */
    c = strrchr(xen_changeset(), ':');
    if ( c )
        hdr.changeset = simple_strtoll(c, NULL, 16);
    else 
        hdr.changeset = -1ULL; /* Unknown */

    arch_hvm_save(d, &hdr);

    if ( hvm_save_entry(HEADER, 0, h, &hdr) != 0 )
    {
        printk(XENLOG_G_ERR "HVM%d save: failed to write header\n",
               d->domain_id);
        return -EFAULT;
    } 

    /* Save all available kinds of state */
    for ( i = 0; i <= HVM_SAVE_CODE_MAX; i++ ) 
    {
        handler = hvm_sr_handlers[i].save;
        if ( handler != NULL ) 
        {
            printk(XENLOG_G_INFO "HVM%d save: %s\n",
                   d->domain_id, hvm_sr_handlers[i].name);
            if ( handler(d, h) != 0 ) 
            {
                printk(XENLOG_G_ERR
                       "HVM%d save: failed to save type %"PRIu16"\n",
                       d->domain_id, i);
                return -EFAULT;
            } 
        }
    }

    /* Save an end-of-file marker */
    if ( hvm_save_entry(END, 0, h, &end) != 0 )
    {
        /* Run out of data */
        printk(XENLOG_G_ERR "HVM%d save: no room for end marker\n",
               d->domain_id);
        return -EFAULT;
    }

    /* Save macros should not have let us overrun */
    ASSERT(h->cur <= h->size);
    return 0;
}

int hvm_load(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_save_header hdr;
    struct hvm_save_descriptor *desc;
    hvm_load_handler handler;
    struct vcpu *v;
    
    if ( d->is_dying )
        return -EINVAL;

    /* Read the save header, which must be first */
    if ( hvm_load_entry(HEADER, h, &hdr) != 0 ) 
        return -1;

    if ( arch_hvm_load(d, &hdr) )
        return -1;

    /* Down all the vcpus: we only re-enable the ones that had state saved. */
    for_each_vcpu(d, v) 
        if ( test_and_set_bit(_VPF_down, &v->pause_flags) )
            vcpu_sleep_nosync(v);

    for ( ; ; )
    {
        if ( h->size - h->cur < sizeof(struct hvm_save_descriptor) )
        {
            /* Run out of data */
            printk(XENLOG_G_ERR
                   "HVM%d restore: save did not end with a null entry\n",
                   d->domain_id);
            return -1;
        }
        
        /* Read the typecode of the next entry  and check for the end-marker */
        desc = (struct hvm_save_descriptor *)(&h->data[h->cur]);
        if ( desc->typecode == 0 )
            return 0; 
        
        /* Find the handler for this entry */
        if ( (desc->typecode > HVM_SAVE_CODE_MAX) ||
             ((handler = hvm_sr_handlers[desc->typecode].load) == NULL) )
        {
            printk(XENLOG_G_ERR "HVM%d restore: unknown entry typecode %u\n",
                   d->domain_id, desc->typecode);
            return -1;
        }

        /* Load the entry */
        printk(XENLOG_G_INFO "HVM%d restore: %s %"PRIu16"\n", d->domain_id,
               hvm_sr_handlers[desc->typecode].name, desc->instance);
        if ( handler(d, h) != 0 ) 
        {
            printk(XENLOG_G_ERR "HVM%d restore: failed to load entry %u/%u\n",
                   d->domain_id, desc->typecode, desc->instance);
            return -1;
        }
    }

    /* Not reached */
}

int _hvm_init_entry(struct hvm_domain_context *h,
                    uint16_t tc, uint16_t inst, uint32_t len)
{
    struct hvm_save_descriptor *d 
        = (struct hvm_save_descriptor *)&h->data[h->cur];
    if ( h->size - h->cur < len + sizeof (*d) )
    {
        printk(XENLOG_G_WARNING "HVM save: no room for"
               " %"PRIu32" + %zu bytes for typecode %"PRIu16"\n",
               len, sizeof(*d), tc);
        return -1;
    }
    d->typecode = tc;
    d->instance = inst;
    d->length = len;
    h->cur += sizeof(*d);
    return 0;
}

void _hvm_write_entry(struct hvm_domain_context *h,
                      void *src, uint32_t src_len)
{
    memcpy(&h->data[h->cur], src, src_len);
    h->cur += src_len;
}

int _hvm_check_entry(struct hvm_domain_context *h, 
                     uint16_t type, uint32_t len, bool_t strict_length)
{
    struct hvm_save_descriptor *d 
        = (struct hvm_save_descriptor *)&h->data[h->cur];
    if ( sizeof(*d) > h->size - h->cur)
    {
        printk(XENLOG_G_WARNING
               "HVM restore: not enough data left to read %zu bytes "
               "for type %u header\n", sizeof(*d), type);
        return -1;
    }
    if ( (type != d->typecode) ||
         (strict_length ? (len != d->length) : (len < d->length)) ||
         (d->length > (h->size - h->cur - sizeof(*d))) )
    {
        printk(XENLOG_G_WARNING
               "HVM restore mismatch: expected %s type %u length %u, "
               "saw type %u length %u.  %zu bytes remaining\n",
               strict_length ? "strict" : "zeroextended", type, len,
               d->typecode, d->length, h->size - h->cur - sizeof(*d));
        return -1;
    }
    h->cur += sizeof(*d);
    return 0;
}

void _hvm_read_entry(struct hvm_domain_context *h,
                     void *dest, uint32_t dest_len)
{
    struct hvm_save_descriptor *d 
        = (struct hvm_save_descriptor *)&h->data[h->cur - sizeof(*d)];
    BUG_ON(d->length > dest_len);
    memcpy(dest, &h->data[h->cur], d->length);
    if ( d->length < dest_len )
        memset((char *)dest + d->length, 0, dest_len - d->length);
    h->cur += d->length;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
