#ifndef _VMX_INTERCEPT_H
#define _VMX_INTERCEPT_H

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/time.h>
#include <xen/errno.h>
#include <public/io/ioreq.h>

#define MAX_IO_HANDLER 10

typedef int (*intercept_action_t)(ioreq_t*);

enum {PORTIO, MMIO};

struct vmx_handler_t {
    int num_slot;
    struct {
        unsigned long       addr;
        int type;
        unsigned long       offset;
        intercept_action_t  action;
    } hdl_list[MAX_IO_HANDLER];
};

/* global io interception point in HV */
extern int vmx_io_intercept(ioreq_t *p, int type);
extern int register_io_handler(unsigned long addr, unsigned long offset, 
                               intercept_action_t action, int type);

static inline int vmx_portio_intercept(ioreq_t *p)
{
    return vmx_io_intercept(p, PORTIO);
}

static inline int vmx_mmio_intercept(ioreq_t *p)
{
    return vmx_io_intercept(p, MMIO);
}

static inline int register_portio_handler(unsigned long addr, 
                                          unsigned long offset, 
                                          intercept_action_t action)
{
    return register_io_handler(addr, offset, action, PORTIO);
}

static inline int register_mmio_handler(unsigned long addr, 
                                        unsigned long offset, 
                                        intercept_action_t action)
{
    return register_io_handler(addr, offset, action, MMIO);
}

#endif /* _VMX_INTERCEPT_H */
