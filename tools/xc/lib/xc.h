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
    u64           domid;
    unsigned int  cpu;
    int           has_cpu;
    int           stopped;
    unsigned long nr_pages;
    u64           cpu_time;
#define XC_DOMINFO_MAXNAME 16
    char          name[XC_DOMINFO_MAXNAME];
} xc_dominfo_t;

int xc_domain_create(int xc_handle, 
                     unsigned int mem_kb, 
                     const char *name,
                     u64 *pdomid);
int xc_domain_start(int xc_handle, 
                    u64 domid);
int xc_domain_stop(int xc_handle, 
                   u64 domid);
int xc_domain_destroy(int xc_handle, 
                      u64 domid, 
                      int force);
int xc_domain_pincpu(int xc_handle,
                     u64 domid,
                     int cpu);
int xc_domain_getinfo(int xc_handle,
                      u64 first_domid, 
                      unsigned int max_doms,
                      xc_dominfo_t *info);

int xc_linux_save(int xc_handle,
                  u64 domid, 
                  const char *state_file, 
                  int verbose);
int xc_linux_restore(int xc_handle,
                     const char *state_file, 
                     int verbose,
                     u64 *pdomid);
int xc_linux_build(int xc_handle,
                   u64 domid,
                   const char *image_name,
                   const char *ramdisk_name,
                   const char *cmdline);

int xc_netbsd_build(int xc_handle,
                    u64 domid,
                    const char *image_name,
                    const char *cmdline);

int xc_bvtsched_global_set(int xc_handle,
                           unsigned long ctx_allow);
int xc_bvtsched_domain_set(int xc_handle,
                           u64 domid,
                           unsigned long mcuadv,
                           unsigned long warp,
                           unsigned long warpl,
                           unsigned long warpu);

typedef struct {
    unsigned long credit_bytes;
    unsigned long credit_usec;
} xc_vif_sched_params_t;

typedef struct {
    u64 tx_bytes, tx_pkts;
    u64 rx_bytes, rx_pkts;
} xc_vif_stats_t;

int xc_vif_scheduler_set(int xc_handle,
                         u64 domid, 
                         unsigned int vifid,
                         xc_vif_sched_params_t *params);
int xc_vif_scheduler_get(int xc_handle,
                         u64 domid, 
                         unsigned int vifid,
                         xc_vif_sched_params_t *params);
int xc_vif_stats_get(int xc_handle,
                     u64 domid, 
                     unsigned int vifid,
                     xc_vif_stats_t *stats);

typedef struct {
#define XC_VBDDOM_PROBE_ALL (~0ULL)
    u64            domid;
    unsigned short vbdid;
#define XC_VBDF_WRITEABLE (1<<0)
    unsigned long  flags;
    u64            nr_sectors;
} xc_vbd_t;

typedef struct {
    unsigned short real_device;
    u64            start_sector;
    u64            nr_sectors;
} xc_vbdextent_t;

typedef struct {
    int ht_per_core;
    int cores;
    unsigned long total_pages;
    unsigned long free_pages;
    unsigned long cpu_khz;
} xc_physinfo_t;

int xc_vbd_create(int xc_handle,
                  u64 domid, 
                  unsigned short vbdid, 
                  int writeable);
int xc_vbd_destroy(int xc_handle,
                   u64 domid, 
                   unsigned short vbdid);
int xc_vbd_grow(int xc_handle,
                u64 domid, 
                unsigned short vbdid,
                xc_vbdextent_t *extent);
int xc_vbd_shrink(int xc_handle,
                  u64 domid, 
                  unsigned short vbdid);
int xc_vbd_setextents(int xc_handle,
                      u64 domid, 
                      unsigned short vbdid,
                      unsigned int nr_extents,
                      xc_vbdextent_t *extents);
int xc_vbd_getextents(int xc_handle,
                      u64 domid, 
                      unsigned short vbdid,
                      unsigned int max_extents,
                      xc_vbdextent_t *extents,
                      int *writeable);
int xc_vbd_probe(int xc_handle,
                 u64 domid,
                 unsigned int max_vbds,
                 xc_vbd_t *vbds);

#define DOMID_SELF              (~1ULL)
#define EVTCHNSTAT_closed       0  /* Chennel is not in use.              */
#define EVTCHNSTAT_disconnected 1  /* Channel is not connected to remote. */
#define EVTCHNSTAT_connected    2  /* Channel is connected to remote.     */
int xc_evtchn_open(int xc_handle,
                   u64 dom1,   /* may be DOMID_SELF */
                   u64 dom2,   /* may be DOMID_SELF */
                   int *port1,
                   int *port2);
int xc_evtchn_close(int xc_handle,
                    u64 dom,   /* may be DOMID_SELF */
                    int port);
int xc_evtchn_send(int xc_handle,
                   int local_port);
int xc_evtchn_status(int xc_handle,
                     u64 dom1, /* may be DOMID_SELF */
                     int port1,
                     u64 *dom2,
                     int *port2,
                     int *chn_status);

int xc_readconsolering(int xc_handle,
                       char *str, 
                       unsigned int max_chars, 
                       int clear);

int xc_physinfo(int xc_handle,
		xc_physinfo_t *info);

#endif /* __XC_H__ */
