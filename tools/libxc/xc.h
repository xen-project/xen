/******************************************************************************
 * xc.h
 * 
 * A library for low-level access to the Xen control interfaces.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#ifndef __XC_H__
#define __XC_H__

int xc_interface_open(void);
int xc_interface_close(void);

typedef struct {
    unsigned int  domid;
    unsigned int  cpu;
    int           has_cpu;
    int           stopped;
    unsigned long nr_pages;
    unsigned long long cpu_time;
#define XC_DOMINFO_MAXNAME 16
    char          name[XC_DOMINFO_MAXNAME];
} xc_dominfo_t;

int xc_domain_create(unsigned int mem_kb, const char *name);
int xc_domain_start(unsigned int domid);
int xc_domain_stop(unsigned int domid);
int xc_domain_destroy(unsigned int domid, int force);
int xc_domain_getinfo(unsigned int first_domid, 
                      unsigned int max_doms,
                      xc_dominfo_t *info);

int xc_linux_save(unsigned int domid, const char *state_file, int verbose);
int xc_linux_restore(const char *state_file, int verbose);
int xc_linux_build(unsigned int domid,
                   const char *image_name,
                   const char *ramdisk_name,
                   const char *cmdline,
                   int verbose);

int xc_bvtsched_global_set(unsigned long ctx_allow);
int xc_bvtsched_domain_set(unsigned int domid,
                           unsigned long mcuadv,
                           unsigned long warp,
                           unsigned long warpl,
                           unsigned long warpu);

typedef struct {
    unsigned long credit_bytes;
    unsigned long credit_usec;
} xc_vif_sched_params_t;

typedef struct {
    unsigned long long tx_bytes, tx_pkts;
    unsigned long long rx_bytes, rx_pkts;
} xc_vif_stats_t;

int xc_vif_scheduler_set(unsigned int domid, 
                         unsigned int vifid,
                         xc_vif_sched_params_t *params);
int xc_vif_scheduler_get(unsigned int domid, 
                         unsigned int vifid,
                         xc_vif_sched_params_t *params);
int xc_vif_stats_get(unsigned int domid, 
                         unsigned int vifid,
                         xc_vif_stats_t *stats);

typedef struct {
#define XC_VBDDOM_PROBE_ALL (~0U)
    unsigned int   domid;
    unsigned short vbdid;
#define XC_VBDF_WRITEABLE (1<<0)
    unsigned long  flags;
    unsigned long  nr_sectors;
} xc_vbd_t;


int xc_vbd_create(unsigned int domid, unsigned short vbdid, int writeable);
int xc_vbd_destroy(unsigned int domid, unsigned short vbdid);
int xc_vbd_add_extent(unsigned int domid, 
                      unsigned short vbdid,
                      unsigned short real_device,
                      unsigned long start_sector,
                      unsigned long nr_sectors);
int xc_vbd_delete_extent(unsigned int domid, 
                         unsigned short vbdid,
                         unsigned short real_device,
                         unsigned long start_sector,
                         unsigned long nr_sectors);
int xc_vbd_probe(unsigned int domid,
                 unsigned short vbdid,
                 unsigned int max_vbds,
                 xc_vbd_t *vbds);

int xc_readconsolering(char *str, unsigned int max_chars, int clear);


#endif /* __XC_H__ */
