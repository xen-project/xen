/******************************************************************************
 * xi.h
 * 
 * A library for low-level access to the Xen control interfaces.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#ifndef __XI_H__
#define __XI_H__

int xi_interface_open(void);
int xi_interface_close(void);

typedef struct {
    unsigned int  domid;
    unsigned int  cpu;
    int           has_cpu;
    int           stopped;
    unsigned long nr_pages;
    unsigned long long cpu_time;
#define XI_DOMINFO_MAXNAME 16
    char          name[XI_DOMINFO_MAXNAME];
} xi_dominfo_t;

int xi_domain_create(unsigned int mem_kb, const char *name);
int xi_domain_start(unsigned int domid);
int xi_domain_stop(unsigned int domid);
int xi_domain_destroy(unsigned int domid, int force);
int xi_domain_getinfo(unsigned int first_domid, 
                      unsigned int max_doms,
                      xi_dominfo_t *info);

int xi_linux_save(unsigned int domid, const char *state_file, int verbose);
int xi_linux_restore(const char *state_file, int verbose);
int xi_linux_build(unsigned int domid,
                   const char *image_name,
                   const char *ramdisk_name,
                   const char *cmdline,
                   int verbose);

int xi_bvtsched_global_set(unsigned long ctx_allow);
int xi_bvtsched_domain_set(unsigned int domid,
                           unsigned long mcuadv,
                           unsigned long warp,
                           unsigned long warpl,
                           unsigned long warpu);

typedef struct {
    unsigned long credit_bytes;
    unsigned long credit_usec;
} xi_vif_sched_params_t;

typedef struct {
    unsigned long long tx_bytes, tx_pkts;
    unsigned long long rx_bytes, rx_pkts;
} xi_vif_stats_t;

int xi_vif_scheduler_set(unsigned int domid, 
                         unsigned int vifid,
                         xi_vif_sched_params_t *params);
int xi_vif_scheduler_get(unsigned int domid, 
                         unsigned int vifid,
                         xi_vif_sched_params_t *params);
int xi_vif_stats_get(unsigned int domid, 
                         unsigned int vifid,
                         xi_vif_stats_t *stats);

typedef struct {
#define XI_VBDDOM_PROBE_ALL (~0U)
    unsigned int   domid;
    unsigned short vbdid;
#define XI_VBDF_WRITEABLE (1<<0)
    unsigned long  flags;
    unsigned long  nr_sectors;
} xi_vbd_t;


int xi_vbd_create(unsigned int domid, unsigned short vbdid, int writeable);
int xi_vbd_destroy(unsigned int domid, unsigned short vbdid);
int xi_vbd_add_extent(unsigned int domid, 
                      unsigned short vbdid,
                      unsigned short real_device,
                      unsigned long start_sector,
                      unsigned long nr_sectors);
int xi_vbd_delete_extent(unsigned int domid, 
                         unsigned short vbdid,
                         unsigned short real_device,
                         unsigned long start_sector,
                         unsigned long nr_sectors);
int xi_vbd_probe(unsigned int domid,
                 unsigned short vbdid,
                 unsigned int max_vbds,
                 xi_vbd_t *vbds);

int xi_readconsolering(char *str, unsigned int max_chars, int clear);


#endif /* __XI_H__ */
