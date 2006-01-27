/******************************************************************************
 * hypercall.h
 */

#ifndef __XEN_HYPERCALL_H__
#define __XEN_HYPERCALL_H__

#include <xen/config.h>
#include <xen/types.h>
#include <xen/time.h>
#include <public/xen.h>
#include <asm/hypercall.h>

extern long
do_ni_hypercall(
    void);

extern long
do_sched_op(
    int cmd,
    unsigned long arg);

struct dom0_op;
extern long
do_dom0_op(
    struct dom0_op *u_dom0_op);

extern long
do_memory_op(
    int cmd,
    void *arg);

struct multicall_entry;
extern long
do_multicall(
    struct multicall_entry *call_list,
    unsigned int nr_calls);

extern long
do_set_timer_op(
    s_time_t timeout);

struct evtchn_op;
extern long
do_event_channel_op(
    struct evtchn_op *uop);

extern long
do_xen_version(
    int cmd,
    void *arg);

extern long
do_console_io(
    int cmd,
    int count,
    char *buffer);

extern long
do_grant_table_op(
    unsigned int cmd,
    void *uop,
    unsigned int count);

extern long
do_vm_assist(
    unsigned int cmd,
    unsigned int type);

extern long
do_vcpu_op(
    int cmd,
    int vcpuid,
    void *arg);

struct acm_op;
extern long
do_acm_op(
    struct acm_op *u_acm_op);

extern long
do_nmi_op(
    unsigned int cmd,
    void *arg);

#endif /* __XEN_HYPERCALL_H__ */
