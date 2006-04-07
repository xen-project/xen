/******************************************************************************
 * xenoprof.h
 * 
 * Interface for enabling system wide profiling based on hardware performance
 * counters
 * 
 * Copyright (C) 2005 Hewlett-Packard Co.
 * Written by Aravind Menon & Jose Renato Santos
 */

#ifndef __XEN_PUBLIC_XENOPROF_H__
#define __XEN_PUBLIC_XENOPROF_H__

/*
 * Commands to HYPERVISOR_pmc_op().
 */
#define XENOPROF_init               0
#define XENOPROF_set_active         1
#define XENOPROF_reserve_counters   3
#define XENOPROF_setup_events       4
#define XENOPROF_enable_virq        5
#define XENOPROF_start              6
#define XENOPROF_stop               7
#define XENOPROF_disable_virq       8
#define XENOPROF_release_counters   9
#define XENOPROF_shutdown          10

#define MAX_OPROF_EVENTS    32
#define MAX_OPROF_DOMAINS   25	
#define XENOPROF_CPU_TYPE_SIZE 64

/* Xenoprof performance events (not Xen events) */
struct event_log {
    uint64_t eip;
    uint8_t mode;
    uint8_t event;
};

/* Xenoprof buffer shared between Xen and domain - 1 per VCPU */
typedef struct xenoprof_buf {
    uint32_t event_head;
    uint32_t event_tail;
    uint32_t event_size;
    uint32_t vcpu_id;
    uint64_t xen_samples;
    uint64_t kernel_samples;
    uint64_t user_samples;
    uint64_t lost_samples;
    struct event_log event_log[1];
} xenoprof_buf_t;
DEFINE_GUEST_HANDLE(xenoprof_buf_t);

typedef struct xenoprof_init_result {
    int32_t  num_events;
    int32_t  is_primary;
    int32_t  nbuf;
    int32_t  bufsize;
    uint64_t buf_maddr;
    char cpu_type[XENOPROF_CPU_TYPE_SIZE];
} xenoprof_init_result_t;
DEFINE_GUEST_HANDLE(xenoprof_init_result_t);

typedef struct xenoprof_counter_config {
    unsigned long count;
    unsigned long enabled;
    unsigned long event;
    unsigned long kernel;
    unsigned long user;
    unsigned long unit_mask;
} xenoprof_counter_config_t;
DEFINE_GUEST_HANDLE(xenoprof_counter_config_t);

#endif /* __XEN_PUBLIC_XENOPROF_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
