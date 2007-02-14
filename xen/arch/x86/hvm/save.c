/*
 * hvm/save.c: Save and restore HVM guest's emulated hardware state.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2007, XenSource Inc.
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
#include <xen/compile.h>
#include <xen/lib.h>
#include <public/version.h>
#include <xen/sched.h>

#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/domain.h>
#include <asm/current.h>


/* List of handlers for various HVM save and restore types */
static struct { 
    hvm_save_handler save;
    hvm_load_handler load; 
    const char *name;
    size_t size;
    int kind;
} hvm_sr_handlers [HVM_SAVE_CODE_MAX + 1] = {{NULL, NULL, "<?>"},};

/* Init-time function to add entries to that list */
void hvm_register_savevm(uint16_t typecode, 
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
