/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * save.h: HVM support routines for save/restore
 */

#ifndef __XEN_HVM_SAVE_H__
#define __XEN_HVM_SAVE_H__

#include <xen/types.h>
#include <xen/init.h>
#include <public/xen.h>
#include <public/hvm/save.h>

/* Marshalling and unmarshalling uses a buffer with size and cursor. */
typedef struct hvm_domain_context {
    uint32_t cur;
    uint32_t size;
    uint8_t *data;
} hvm_domain_context_t;

/* Marshalling an entry: check space and fill in the header */
int _hvm_init_entry(struct hvm_domain_context *h,
                    uint16_t tc, uint16_t inst, uint32_t len);

/* Marshalling: copy the contents in a type-safe way */
void _hvm_write_entry(struct hvm_domain_context *h,
                      void *src, uint32_t src_len);

/* Marshalling: init and copy; evaluates to zero on success */
#define hvm_save_entry(_x, _inst, _h, _src) ({                  \
    int r;                                                      \
    r = _hvm_init_entry((_h), HVM_SAVE_CODE(_x),                \
                        (_inst), HVM_SAVE_LENGTH(_x));          \
    if ( r == 0 )                                               \
        _hvm_write_entry((_h), (_src), HVM_SAVE_LENGTH(_x));    \
    r; })

/* Unmarshalling: test an entry's size and typecode and record the instance */
int _hvm_check_entry(struct hvm_domain_context *h,
                     uint16_t type, uint32_t len, bool strict_length);

/*
 * Unmarshalling: check, then return pointer. Evaluates to non-NULL on success.
 * This macro requires the save entry to be the same size as the dest structure.
 */
#define hvm_get_entry(x, h) ({                                  \
    const void *ptr = NULL;                                     \
    BUILD_BUG_ON(HVM_SAVE_HAS_COMPAT(x));                       \
    if ( _hvm_check_entry(h, HVM_SAVE_CODE(x),                  \
                          HVM_SAVE_LENGTH(x), true) == 0 )      \
    {                                                           \
        ptr = &(h)->data[(h)->cur];                             \
        (h)->cur += HVM_SAVE_LENGTH(x);                         \
    }                                                           \
    ptr; })

/* Unmarshalling: copy the contents in a type-safe way */
void _hvm_read_entry(struct hvm_domain_context *h,
                     void *dest, uint32_t dest_len);

/*
 * Unmarshalling: check, then copy. Evaluates to zero on success. This load
 * function requires the save entry to be the same size as the dest structure.
 */
#define _hvm_load_entry(x, h, dst, strict) ({                           \
    int r_;                                                             \
    struct hvm_save_descriptor *desc_                                   \
        = (struct hvm_save_descriptor *)&(h)->data[(h)->cur];           \
    if ( (r_ = _hvm_check_entry(h, HVM_SAVE_CODE(x),                    \
                                HVM_SAVE_LENGTH(x), strict)) == 0 )     \
    {                                                                   \
        _hvm_read_entry(h, dst, HVM_SAVE_LENGTH(x));                    \
        if ( HVM_SAVE_HAS_COMPAT(x) &&                                  \
             desc_->length != HVM_SAVE_LENGTH(x) )                      \
            r_ = HVM_SAVE_FIX_COMPAT(x, dst, desc_->length);            \
    }                                                                   \
    else if ( HVM_SAVE_HAS_COMPAT(x) &&                                 \
              (r_ = _hvm_check_entry(h, HVM_SAVE_CODE(x),               \
                                     HVM_SAVE_LENGTH_COMPAT(x),         \
                                     strict)) == 0 )                    \
    {                                                                   \
        _hvm_read_entry(h, dst, HVM_SAVE_LENGTH_COMPAT(x));             \
        r_ = HVM_SAVE_FIX_COMPAT(x, dst, desc_->length);                \
    }                                                                   \
    r_; })

#define hvm_load_entry(x, h, dst)            \
    _hvm_load_entry(x, h, dst, true)
#define hvm_load_entry_zeroextend(x, h, dst) \
    _hvm_load_entry(x, h, dst, false)

/* Unmarshalling: what is the instance ID of the next entry? */
static inline unsigned int hvm_load_instance(const struct hvm_domain_context *h)
{
    const struct hvm_save_descriptor *d = (const void *)&h->data[h->cur];

    return d->instance;
}

/* Handler types for different types of save-file entry. 
 * The save handler may save multiple instances of a type into the buffer;
 * the load handler will be called once for each instance found when
 * restoring.  Both return non-zero on error. */
typedef int (*hvm_save_handler) (struct vcpu *v,
                                 hvm_domain_context_t *h);
typedef int (*hvm_check_handler)(const struct domain *d,
                                 hvm_domain_context_t *h);
typedef int (*hvm_load_handler) (struct domain *d,
                                 hvm_domain_context_t *h);

/* Init-time function to declare a pair of handlers for a type,
 * and the maximum buffer space needed to save this type of state */
void hvm_register_savevm(uint16_t typecode,
                         const char *name, 
                         hvm_save_handler save_state,
                         hvm_check_handler check_state,
                         hvm_load_handler load_state,
                         size_t size, int kind);

/* The space needed for saving can be per-domain or per-vcpu: */
#define HVMSR_PER_DOM  0
#define HVMSR_PER_VCPU 1

/* Syntactic sugar around that function: specify the max number of
 * saves, and this calculates the size of buffer needed */
#define HVM_REGISTER_SAVE_RESTORE(_x, _save, check, _load, _num, _k)      \
static int __init cf_check __hvm_register_##_x##_save_and_restore(void)   \
{                                                                         \
    hvm_register_savevm(HVM_SAVE_CODE(_x),                                \
                        #_x,                                              \
                        _save,                                            \
                        check,                                            \
                        _load,                                            \
                        (_num) * (HVM_SAVE_LENGTH(_x)                     \
                                  + sizeof (struct hvm_save_descriptor)), \
                        _k);                                              \
    return 0;                                                             \
}                                                                         \
__initcall(__hvm_register_##_x##_save_and_restore);


/* Entry points for saving and restoring HVM domain state */
size_t hvm_save_size(struct domain *d);
int hvm_save(struct domain *d, hvm_domain_context_t *h);
int hvm_save_one(struct domain *d, unsigned int typecode, unsigned int instance,
                 XEN_GUEST_HANDLE_64(uint8) handle, uint64_t *bufsz);
int hvm_load(struct domain *d, bool real, hvm_domain_context_t *h);

#endif /* __XEN_HVM_SAVE_H__ */
