/******************************************************************************
 * xc.h
 * 
 * A library for low-level access to the Xen control interfaces.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#ifndef __XC_H__
#define __XC_H__

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned long      u32;
typedef unsigned long long u64;
typedef signed char        s8;
typedef signed short       s16;
typedef signed long        s32;
typedef signed long long   s64;

/* Obtain or relinquish a handle on the 'xc' library. */
int xc_interface_open(void);
int xc_interface_close(int xc_handle);

typedef struct {
    u32           domid;
    unsigned int  cpu;
    unsigned int  dying:1, crashed:1, shutdown:1, 
                  paused:1, blocked:1, running:1;
    unsigned int  shutdown_reason; /* only meaningful if shutdown==1 */
    unsigned long nr_pages;
    unsigned long shared_info_frame;
    u64           cpu_time;
#define XC_DOMINFO_MAXNAME 16
    char          name[XC_DOMINFO_MAXNAME];
    unsigned long max_memkb;
} xc_dominfo_t;

typedef struct xc_shadow_control_stats_st
{
    unsigned long fault_count;
    unsigned long dirty_count;
    unsigned long dirty_net_count;     
    unsigned long dirty_block_count;     
} xc_shadow_control_stats_t;

int xc_domain_create(int xc_handle, 
                     unsigned int mem_kb, 
                     const char *name,
                     int cpu,
                     float cpu_weight,
                     u32 *pdomid);
int xc_domain_pause(int xc_handle, 
                    u32 domid);
int xc_domain_unpause(int xc_handle, 
                      u32 domid);
int xc_domain_destroy(int xc_handle, 
                      u32 domid);
int xc_domain_pincpu(int xc_handle,
                     u32 domid,
                     int cpu);
int xc_domain_getinfo(int xc_handle,
                      u32 first_domid, 
                      unsigned int max_doms,
                      xc_dominfo_t *info);
int xc_domain_setcpuweight(int xc_handle,
                           u32 domid,
                           float weight);

int xc_shadow_control(int xc_handle,
                      u32 domid, 
                      unsigned int sop,
                      unsigned long *dirty_bitmap,
                      unsigned long pages,
                      xc_shadow_control_stats_t *stats);


#define XCFLAGS_VERBOSE   1
#define XCFLAGS_LIVE      2
#define XCFLAGS_DEBUG     4
#define XCFLAGS_CONFIGURE 8

struct XcIOContext;
int xc_linux_save(int xc_handle, struct XcIOContext *ioctxt);
int xc_linux_restore(int xc_handle, struct XcIOContext *ioctxt);

int xc_linux_build(int xc_handle,
                   u32 domid,
                   const char *image_name,
                   const char *ramdisk_name,
                   const char *cmdline,
                   unsigned int control_evtchn,
                   unsigned long flags);

int xc_bvtsched_global_set(int xc_handle,
                           unsigned long ctx_allow);

int xc_bvtsched_domain_set(int xc_handle,
                           u32 domid,
                           u32 mcuadv,
                           int warpback,
                           s32 warpvalue,
                           long long warpl,
                           long long warpu);

int xc_bvtsched_global_get(int xc_handle,
                           unsigned long *ctx_allow);

int xc_bvtsched_domain_get(int xc_handle,
                           u32 domid,
                           u32 *mcuadv,
                           int *warpback,
                           s32 *warpvalue,
                           long long *warpl,
                           long long *warpu);

int xc_atropos_domain_set(int xc_handle,
                          u32 domid,
                          u64 period, u64 slice, u64 latency,
                          int xtratime);

int xc_atropos_domain_get(int xc_handle,
                          u32 domid,
                          u64* period, u64 *slice, u64 *latency,
                          int *xtratime);

int xc_rrobin_global_set(int xc_handle, u64 slice);

int xc_rrobin_global_get(int xc_handle, u64 *slice);

#define DOMID_SELF              (0x7FF0U)
#define DOMID_IO                (0x7FF1U)
#define DOMID_XEN               (0x7FF2U)

typedef struct {
#define EVTCHNSTAT_closed       0  /* Chennel is not in use.                 */
#define EVTCHNSTAT_unbound      1  /* Channel is not bound to a source.      */
#define EVTCHNSTAT_interdomain  2  /* Channel is connected to remote domain. */
#define EVTCHNSTAT_pirq         3  /* Channel is bound to a phys IRQ line.   */
#define EVTCHNSTAT_virq         4  /* Channel is bound to a virtual IRQ line */
    int status;
    union {
        struct {
            u32 dom;
            int port;
        } interdomain;
        int pirq;
        int virq;
    } u;
} xc_evtchn_status_t;

int xc_evtchn_bind_interdomain(int xc_handle,
                               u32 dom1,   /* may be DOMID_SELF */
                               u32 dom2,   /* may be DOMID_SELF */
                               int *port1,
                               int *port2);
int xc_evtchn_bind_virq(int xc_handle,
                        int virq,
                        int *port);
int xc_evtchn_close(int xc_handle,
                    u32 dom,   /* may be DOMID_SELF */
                    int port);
int xc_evtchn_send(int xc_handle,
                   int local_port);
int xc_evtchn_status(int xc_handle,
                     u32 dom, /* may be DOMID_SELF */
                     int port,
                     xc_evtchn_status_t *status);

int xc_physdev_pci_access_modify(int xc_handle,
                                 u32 domid,
                                 int bus,
                                 int dev,
                                 int func,
                                 int enable);

int xc_readconsolering(int xc_handle,
                       char *str, 
                       unsigned int max_chars, 
                       int clear);

typedef struct {
    int ht_per_core;
    int cores;
    unsigned long total_pages;
    unsigned long free_pages;
    unsigned long cpu_khz;
} xc_physinfo_t;

int xc_physinfo(int xc_handle,
                xc_physinfo_t *info);

int xc_sched_id(int xc_handle,
                int *sched_id);

int xc_domain_setname(int xc_handle,
                      u32 domid, 
                      char *name);

int xc_domain_setinitialmem(int xc_handle,
                            u32 domid, 
                            unsigned int initial_memkb);

int xc_domain_setmaxmem(int xc_handle,
                            u32 domid, 
                            unsigned int max_memkb);

int xc_domain_setvmassist(int xc_handle,
                          u32 domid, 
                          unsigned int cmd,
                          unsigned int type);


void *xc_map_foreign_range(int xc_handle, u32 dom,
                            int size, int prot,
                            unsigned long mfn );

void *xc_map_foreign_batch(int xc_handle, u32 dom, int prot,
                           unsigned long *arr, int num );

#endif /* __XC_H__ */
