
#ifndef _VMX_INTERCEPT_H
#define _VMX_INTERCEPT_H

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/time.h>
#include <xen/errno.h>
#include <public/io/ioreq.h>


#define MAX_IO_HANDLER 6

typedef int (*intercept_action_t)(ioreq_t*);

struct vmx_handler_t {
    int num_slot;
    struct {
        unsigned long       addr;
        unsigned long       offset;
        intercept_action_t  action;
    } hdl_list[MAX_IO_HANDLER];
};

/* global io interception point in HV */
extern int vmx_io_intercept(ioreq_t*);
extern int register_io_handler(unsigned long, unsigned long, intercept_action_t);


#endif /* _VMX_INTERCEPT_H */
