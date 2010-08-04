/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */
#ifndef LIBXL_H
#define LIBXL_H

#include <stdint.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <xenctrl.h>
#include <xs.h>
#include <sys/wait.h> /* for pid_t */

typedef struct {
    uint8_t uuid[16];
    uint32_t domid;
    uint8_t running:1;
    uint8_t blocked:1;
    uint8_t paused:1;
    uint8_t shutdown:1;
    uint8_t dying:1;

    /*
     * Valid SHUTDOWN_* value from xen/sched.h iff (shutdown||dying).
     *
     * Otherwise set to a value guaranteed not to clash with any valid
     * SHUTDOWN_* constant.
     */
    unsigned int shutdown_reason;

    uint64_t max_memkb;
    uint64_t cpu_time;
    uint32_t vcpu_max_id;
    uint32_t vcpu_online;
} libxl_dominfo;

typedef struct {
    uint32_t poolid;
} libxl_poolinfo;

typedef struct {
    uint8_t uuid[16];
    uint32_t domid;
} libxl_vminfo;

typedef struct {
    int xen_version_major;
    int xen_version_minor;
    char *xen_version_extra;
    char *compiler;
    char *compile_by;
    char *compile_domain;
    char *compile_date;
    char *capabilities;
    char *changeset;
    unsigned long virt_start;
    unsigned long pagesize;
    char *commandline;
} libxl_version_info;

typedef struct {
    xentoollog_logger *lg;
    xc_interface *xch;
    struct xs_handle *xsh;

    /* mini-GC */
    int alloc_maxsize;
    void **alloc_ptrs;

    /* for callers who reap children willy-nilly; caller must only
     * set this after libxl_init and before any other call - or
     * may leave them untouched */
    int (*waitpid_instead)(pid_t pid, int *status, int flags);
    libxl_version_info version_info;
} libxl_ctx;

const libxl_version_info* libxl_get_version_info(libxl_ctx *ctx);

typedef struct {
    bool hvm;
    bool hap;
    bool oos;
    int ssidref;
    char *name;
    uint8_t uuid[16];
    char **xsdata;
    char **platformdata;
    uint32_t poolid;
    char *poolname;
} libxl_domain_create_info;

typedef struct {
    /*
     * Path is always set if the file refernece is valid. However if
     * mapped is true then the actual file may already be unlinked.
     */
    char *path;
    int mapped;
    void *data;
    size_t size;
} libxl_file_reference;

/*
 * Instances of libxl_file_reference contained in this struct which
 * have been mapped (with libxl_file_reference_map) will be unmapped
 * by libxl_domain_build/restore. If either of these are never called
 * then the user is responsible for calling
 * libxl_file_reference_unmap.
 */
typedef struct {
    int max_vcpus;
    int cur_vcpus;
    int tsc_mode;
    uint32_t max_memkb;
    uint32_t target_memkb;
    uint32_t video_memkb;
    uint32_t shadow_memkb;
    bool disable_migrate;
    libxl_file_reference kernel;
    int hvm;
    union {
        struct {
            bool pae;
            bool apic;
            bool acpi;
            bool nx;
            bool viridian;
            char *timeoffset;
            bool hpet;
            bool vpt_align;
            int timer_mode;
        } hvm;
        struct {
            uint32_t   slack_memkb;
            const char *bootloader;
            const char *bootloader_args;
            char *cmdline;
            libxl_file_reference ramdisk;
            const char *features;
        } pv;
    } u;
} libxl_domain_build_info;

typedef struct {
    uint32_t store_port;
    unsigned long store_mfn;
    uint32_t console_port;
    unsigned long console_mfn;
} libxl_domain_build_state;

typedef struct {
#define XL_SUSPEND_DEBUG 1
#define XL_SUSPEND_LIVE 2
    int flags;
    int (*suspend_callback)(void *, int);
} libxl_domain_suspend_info;

typedef enum {
    XENFV = 1,
    XENPV,
} libxl_qemu_machine_type;

typedef struct {
    int domid;
    uint8_t uuid[16]; /* this is use only with stubdom, and must be different from the domain uuid */
    char *dom_name;
    char *device_model;
    char *saved_state;
    libxl_qemu_machine_type type;
    int videoram; /* size of the videoram in MB */
    bool stdvga; /* stdvga enabled or disabled */
    bool vnc; /* vnc enabled or disabled */
    char *vnclisten; /* address:port that should be listened on for the VNC server if vnc is set */
    char *vncpasswd; /* the VNC password */
    int vncdisplay; /* set VNC display number */
    bool vncunused; /* try to find an unused port for the VNC server */
    char *keymap; /* set keyboard layout, default is en-us keyboard */
    bool sdl; /* sdl enabled or disabled */
    bool opengl; /* opengl enabled or disabled (if enabled requires sdl enabled) */
    bool nographic; /* no graphics, use serial port */
    char *serial; /* serial port re-direct to pty deivce */
    char *boot; /* boot order, for example dca */
    bool usb; /* usb support enabled or disabled */
    char *usbdevice; /* enable usb mouse: tablet for absolute mouse, mouse for PS/2 protocol relative mouse */
    char *soundhw; /* enable sound hardware */
    bool apic; /* apic enabled or disabled */
    int vcpus; /* max number of vcpus */
    int vcpu_avail; /* vcpus actually available */
    int xen_platform_pci; /* enable/disable the xen platform pci device */
    char **extra; /* extra parameters pass directly to qemu, NULL terminated */
    /* Network is missing */
} libxl_device_model_info;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    int devid;
    bool vnc; /* vnc enabled or disabled */
    char *vnclisten; /* address:port that should be listened on for the VNC server if vnc is set */
    char *vncpasswd; /* the VNC password */
    int vncdisplay; /* set VNC display number */
    bool vncunused; /* try to find an unused port for the VNC server */
    char *keymap; /* set keyboard layout, default is en-us keyboard */
    bool sdl; /* sdl enabled or disabled */
    bool opengl; /* opengl enabled or disabled (if enabled requires sdl enabled) */
    char *display;
    char *xauthority;
} libxl_device_vfb;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    int devid;
} libxl_device_vkb;

typedef enum {
    CONSTYPE_XENCONSOLED,
    CONSTYPE_IOEMU,
} libxl_console_constype;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    int devid;
    libxl_console_constype constype;
    libxl_domain_build_state *build_state;
} libxl_device_console;

typedef enum {
    PHYSTYPE_QCOW = 1,
    PHYSTYPE_QCOW2,
    PHYSTYPE_VHD,
    PHYSTYPE_AIO,
    PHYSTYPE_FILE,
    PHYSTYPE_PHY,
} libxl_disk_phystype;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    char *physpath;
    libxl_disk_phystype phystype;
    char *virtpath;
    int unpluggable;
    int readwrite;
    int is_cdrom;
} libxl_device_disk;

typedef enum {
    NICTYPE_IOEMU = 1,
    NICTYPE_VIF,
} libxl_nic_type;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    int devid;
    int mtu;
    char *model;
    uint8_t mac[6];
    struct in_addr ip;
    char *bridge;
    char *ifname;
    char *script;
    libxl_nic_type nictype;
} libxl_device_nic;

typedef struct {
    int devid;
    uint8_t front_mac[6];
    uint8_t back_mac[6];
    uint32_t backend_domid;
    uint32_t domid;
    uint32_t trusted:1;
    uint32_t back_trusted:1;
    uint32_t filter_mac:1;
    uint32_t front_filter_mac:1;
    uint32_t pdev;
    uint32_t max_bypasses;
    char *bridge;
} libxl_device_net2;

typedef struct {
    union {
        unsigned int value;
        struct {
            unsigned int reserved1:2;
            unsigned int reg:6;
            unsigned int func:3;
            unsigned int dev:5;
            unsigned int bus:8;
            unsigned int reserved2:7;
            unsigned int enable:1;
        };
    };
    unsigned int domain;
    unsigned int vdevfn;
    bool msitranslate;
    bool power_mgmt;
} libxl_device_pci;

enum {
    ERROR_VERSION = -1,
    ERROR_FAIL = -2,
    ERROR_NI = -3,
    ERROR_NOMEM = -4,
    ERROR_INVAL = -5,
    ERROR_BADFAIL = -6,
};

#define LIBXL_VERSION 0

/* context functions */
int libxl_ctx_init(libxl_ctx *ctx, int version, xentoollog_logger*);
int libxl_ctx_free(libxl_ctx *ctx);
int libxl_ctx_set_log(libxl_ctx *ctx, xentoollog_logger*);
int libxl_ctx_postfork(libxl_ctx *ctx);

/* domain related functions */
int libxl_domain_make(libxl_ctx *ctx, libxl_domain_create_info *info, uint32_t *domid);
int libxl_domain_build(libxl_ctx *ctx, libxl_domain_build_info *info, uint32_t domid, /* out */ libxl_domain_build_state *state);
int libxl_domain_restore(libxl_ctx *ctx, libxl_domain_build_info *info,
                         uint32_t domid, int fd, libxl_domain_build_state *state,
                         libxl_device_model_info *dm_info);
int libxl_domain_suspend(libxl_ctx *ctx, libxl_domain_suspend_info *info,
                          uint32_t domid, int fd);
int libxl_domain_resume(libxl_ctx *ctx, uint32_t domid);
int libxl_domain_shutdown(libxl_ctx *ctx, uint32_t domid, int req);
int libxl_domain_destroy(libxl_ctx *ctx, uint32_t domid, int force);
int libxl_domain_preserve(libxl_ctx *ctx, uint32_t domid, libxl_domain_create_info *info, const char *name_suffix, uint8_t new_uuid[16]);

int libxl_file_reference_map(libxl_ctx *ctx, libxl_file_reference *f);
int libxl_file_reference_unmap(libxl_ctx *ctx, libxl_file_reference *f);

/*
 * Run the configured bootloader for a PV domain and update
 * info->kernel, info->u.pv.ramdisk and info->u.pv.cmdline as
 * appropriate (any initial values present in these fields must have
 * been allocated with malloc).
 *
 * Is a NOP on non-PV domains or those with no bootloader configured.
 *
 * Users should call libxl_file_reference_unmap on the kernel and
 * ramdisk to cleanup or rely on libxl_domain_{build,restore} to do
 * it.
 */
int libxl_run_bootloader(libxl_ctx *ctx,
                         libxl_domain_build_info *info,
                         libxl_device_disk *disk,
                         uint32_t domid);

char *libxl_uuid2string(libxl_ctx *ctx, const uint8_t uuid[16]);
  /* 0 means ERROR_ENOMEM, which we have logged */

/* events handling */

typedef enum {
    LIBXL_EVENT_DOMAIN_DEATH,
    LIBXL_EVENT_DISK_EJECT,
} libxl_event_type;

typedef struct {
    /* event type */
    libxl_event_type type;
    /* data for internal use of the library */
    char *path;
    char *token;
} libxl_event;

typedef struct {
    char *path;
    char *token;
} libxl_waiter;


int libxl_get_wait_fd(libxl_ctx *ctx, int *fd);
/* waiter is allocated by the caller */
int libxl_wait_for_domain_death(libxl_ctx *ctx, uint32_t domid, libxl_waiter *waiter);
/* waiter is a preallocated array of num_disks libxl_waiter elements */
int libxl_wait_for_disk_ejects(libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disks, int num_disks, libxl_waiter *waiter);
int libxl_get_event(libxl_ctx *ctx, libxl_event *event);
int libxl_stop_waiting(libxl_ctx *ctx, libxl_waiter *waiter);
int libxl_free_event(libxl_event *event);
int libxl_free_waiter(libxl_waiter *waiter);

/*
 * Returns:
 *  - 0 if the domain is dead but there is no cleanup to be done. e.g
 *    because someone else has already done it.
 *  - 1 if the domain is dead and there is cleanup to be done.
 *
 * Can return error if the domain exists and is still running.
 *
 * *info will contain valid domain state iff 1 is returned. In
 * particular if 1 is returned then info->shutdown_reason is
 * guaranteed to be valid since by definition the domain is
 * (shutdown||dying))
 */
int libxl_event_get_domain_death_info(libxl_ctx *ctx, uint32_t domid, libxl_event *event, libxl_dominfo *info);

/*
 * Returns true and fills *disk if the caller should eject the disk
 */
int libxl_event_get_disk_eject_info(libxl_ctx *ctx, uint32_t domid, libxl_event *event, libxl_device_disk *disk);

int libxl_domain_rename(libxl_ctx *ctx, uint32_t domid,
                        const char *old_name, const char *new_name,
                        xs_transaction_t trans);
  /* if old_name is NULL, any old name is OK; otherwise we check
   * transactionally that the domain has the old old name; if
   * trans is not 0 we use caller's transaction and caller must do retries */

int libxl_domain_pause(libxl_ctx *ctx, uint32_t domid);
int libxl_domain_unpause(libxl_ctx *ctx, uint32_t domid);

int libxl_domain_core_dump(libxl_ctx *ctx, uint32_t domid, const char *filename);

int libxl_domain_setmaxmem(libxl_ctx *ctx, uint32_t domid, uint32_t target_memkb);
int libxl_set_memory_target(libxl_ctx *ctx, uint32_t domid, uint32_t target_memkb, int enforce);

int libxl_vncviewer_exec(libxl_ctx *ctx, uint32_t domid, int autopass);
int libxl_console_exec(libxl_ctx *ctx, uint32_t domid, int cons_num);
/* libxl_primary_console_exec finds the domid and console number
 * corresponding to the primary console of the given vm, then calls
 * libxl_console_exec with the right arguments (domid might be different
 * if the guest is using stubdoms).
 * This function can be called after creating the device model, in
 * case of HVM guests, and before libxl_run_bootloader in case of PV
 * guests using pygrub. */ 
int libxl_primary_console_exec(libxl_ctx *ctx, uint32_t domid_vm);

int libxl_domain_info(libxl_ctx*, libxl_dominfo *info_r,
                      uint32_t domid);
libxl_dominfo * libxl_list_domain(libxl_ctx*, int *nb_domain);
libxl_poolinfo * libxl_list_pool(libxl_ctx*, int *nb_pool);
libxl_vminfo * libxl_list_vm(libxl_ctx *ctx, int *nb_vm);

typedef struct libxl_device_model_starting libxl_device_model_starting;
int libxl_create_device_model(libxl_ctx *ctx,
                              libxl_device_model_info *info,
                              libxl_device_disk *disk, int num_disks,
                              libxl_device_nic *vifs, int num_vifs,
                              libxl_device_model_starting **starting_r);
int libxl_create_xenpv_qemu(libxl_ctx *ctx, libxl_device_vfb *vfb,
                            int num_console, libxl_device_console *console,
                            libxl_device_model_starting **starting_r);
  /* Caller must either: pass starting_r==0, or on successful
   * return pass *starting_r (which will be non-0) to
   * libxl_confirm_device_model or libxl_detach_device_model. */
int libxl_confirm_device_model_startup(libxl_ctx *ctx,
                              libxl_device_model_starting *starting);
int libxl_detach_device_model(libxl_ctx *ctx,
                              libxl_device_model_starting *starting);
  /* DM is detached even if error is returned */

typedef struct {
    char *backend;
    uint32_t backend_id;
    char *frontend;
    uint32_t frontend_id;
    int devid;
    int state;
    int evtch;
    int rref;
} libxl_diskinfo;

int libxl_device_disk_add(libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disk);
int libxl_device_disk_del(libxl_ctx *ctx, libxl_device_disk *disk, int wait);
libxl_device_disk *libxl_device_disk_list(libxl_ctx *ctx, uint32_t domid, int *num);
int libxl_device_disk_getinfo(libxl_ctx *ctx, uint32_t domid,
                              libxl_device_disk *disk, libxl_diskinfo *diskinfo);
int libxl_cdrom_insert(libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disk);

/*
 * Make a disk available in this domain. Returns path to a device.
 */
const char * libxl_device_disk_local_attach(libxl_ctx *ctx, libxl_device_disk *disk);
int libxl_device_disk_local_detach(libxl_ctx *ctx, libxl_device_disk *disk);

typedef struct {
    char *backend;
    uint32_t backend_id;
    char *frontend;
    uint32_t frontend_id;
    int devid;
    int state;
    char *script;
    uint8_t mac[6];
    int evtch;
    int rref_tx;
    int rref_rx;
} libxl_nicinfo;

int libxl_device_nic_add(libxl_ctx *ctx, uint32_t domid, libxl_device_nic *nic);
int libxl_device_nic_del(libxl_ctx *ctx, libxl_device_nic *nic, int wait);
libxl_nicinfo *libxl_list_nics(libxl_ctx *ctx, uint32_t domid, unsigned int *nb);

int libxl_device_console_add(libxl_ctx *ctx, uint32_t domid, libxl_device_console *console);

int libxl_device_vkb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vkb *vkb);
int libxl_device_vkb_clean_shutdown(libxl_ctx *ctx, uint32_t domid);
int libxl_device_vkb_hard_shutdown(libxl_ctx *ctx, uint32_t domid);

int libxl_device_vfb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vfb *vfb);
int libxl_device_vfb_clean_shutdown(libxl_ctx *ctx, uint32_t domid);
int libxl_device_vfb_hard_shutdown(libxl_ctx *ctx, uint32_t domid);

int libxl_device_pci_add(libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev);
int libxl_device_pci_remove(libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev);
int libxl_device_pci_shutdown(libxl_ctx *ctx, uint32_t domid);
int libxl_device_pci_list_assigned(libxl_ctx *ctx, libxl_device_pci **list, uint32_t domid, int *num);
int libxl_device_pci_list_assignable(libxl_ctx *ctx, libxl_device_pci **list, int *num);
int libxl_device_pci_parse_bdf(libxl_ctx *ctx, libxl_device_pci *pcidev, const char *str);

/*
 * Functions for allowing users of libxl to store private data
 * relating to a domain.  The data is an opaque sequence of bytes and
 * is not interpreted or used by libxl.
 *
 * Data is indexed by the userdata userid, which is a short printable
 * ASCII string.  The following list is a registry of userdata userids
 * (the registry may be updated by posting a patch to xen-devel):
 *
 *  userid      Data contents
 *   "xl"        domain config file in xl format, Unix line endings
 *
 * libxl does not enforce the registration of userdata userids or the
 * semantics of the data.  For specifications of the data formats
 * see the code or documentation for the libxl caller in question.
 */
int libxl_userdata_store(libxl_ctx *ctx, uint32_t domid,
                              const char *userdata_userid,
                              const uint8_t *data, int datalen);
  /* If datalen==0, data is not used and the user data for
   * that domain and userdata_userid is deleted. */
int libxl_userdata_retrieve(libxl_ctx *ctx, uint32_t domid,
                                 const char *userdata_userid,
                                 uint8_t **data_r, int *datalen_r);
  /* On successful return, *data_r is from malloc.
   * If there is no data for that domain and userdata_userid,
   * *data_r and *datalen_r will be set to 0.
   * data_r and datalen_r may be 0.
   * On error return, *data_r and *datalen_r are undefined.
   */

typedef enum {
    POWER_BUTTON,
    SLEEP_BUTTON
} libxl_button;

int libxl_button_press(libxl_ctx *ctx, uint32_t domid, libxl_button button);

typedef struct {
    uint32_t vcpuid; /* vcpu's id */
    uint32_t cpu; /* current mapping */
    uint8_t online:1; /* currently online (not hotplugged)? */
    uint8_t blocked:1; /* blocked waiting for an event? */
    uint8_t running:1; /* currently scheduled on its CPU? */
    uint64_t vcpu_time; /* total vcpu time ran (ns) */
    uint64_t *cpumap; /* current cpu's affinities */
} libxl_vcpuinfo;

typedef struct {
    uint32_t threads_per_core;
    uint32_t cores_per_socket;

    uint32_t max_cpu_id;
    uint32_t nr_cpus;
    uint32_t cpu_khz;

    uint64_t total_pages;
    uint64_t free_pages;
    uint64_t scrub_pages;

    uint32_t nr_nodes;
    uint32_t hw_cap[8];
    uint32_t phys_cap;
}  libxl_physinfo;

int libxl_get_physinfo(libxl_ctx *ctx, libxl_physinfo *physinfo);
libxl_vcpuinfo *libxl_list_vcpu(libxl_ctx *ctx, uint32_t domid,
                                       int *nb_vcpu, int *cpusize);
int libxl_set_vcpuaffinity(libxl_ctx *ctx, uint32_t domid, uint32_t vcpuid,
                           uint64_t *cpumap, int cpusize);
int libxl_set_vcpucount(libxl_ctx *ctx, uint32_t domid, uint32_t count);

int libxl_get_sched_id(libxl_ctx *ctx);


typedef struct {
    int weight;
    int cap;
} libxl_sched_credit;

int libxl_sched_credit_domain_get(libxl_ctx *ctx, uint32_t domid,
                                  libxl_sched_credit *scinfo);
int libxl_sched_credit_domain_set(libxl_ctx *ctx, uint32_t domid,
                                  libxl_sched_credit *scinfo);
int libxl_send_trigger(libxl_ctx *ctx, uint32_t domid,
                       char *trigger_name, uint32_t vcpuid);
int libxl_send_sysrq(libxl_ctx *ctx, uint32_t domid, char sysrq);
int libxl_send_debug_keys(libxl_ctx *ctx, char *keys);

typedef struct {
    char *buffer;
    unsigned int size;
    unsigned int count;
    unsigned int clear;
    unsigned int incremental;
    unsigned int index;
}  libxl_xen_console_reader;

libxl_xen_console_reader *
    libxl_xen_console_read_start(libxl_ctx *ctx, int clear);
int libxl_xen_console_read_line(libxl_ctx *ctx,
                                libxl_xen_console_reader *cr,
                                char **line_r);
void libxl_xen_console_read_finish(libxl_ctx *ctx,
                                   libxl_xen_console_reader *cr);

uint32_t libxl_vm_get_start_time(libxl_ctx *ctx, uint32_t domid);

char *libxl_tmem_list(libxl_ctx *ctx, uint32_t domid, int use_long);
int libxl_tmem_freeze(libxl_ctx *ctx, uint32_t domid);
int libxl_tmem_destroy(libxl_ctx *ctx, uint32_t domid);
int libxl_tmem_thaw(libxl_ctx *ctx, uint32_t domid);
int libxl_tmem_set(libxl_ctx *ctx, uint32_t domid, char* name,
                   uint32_t set);
int libxl_tmem_shared_auth(libxl_ctx *ctx, uint32_t domid, char* uuid,
                           int auth);
int libxl_tmem_freeable(libxl_ctx *ctx);

typedef struct {
    char *backend;
    uint32_t backend_id;
    char *frontend;
    uint32_t frontend_id;
    int devid;
    int state;
    uint8_t mac[6];
    int trusted;
    uint8_t back_mac[6];
    int filter_mac;
} libxl_net2info;

int libxl_device_net2_add(libxl_ctx *ctx, uint32_t domid,
                          libxl_device_net2 *net2);
libxl_net2info *libxl_device_net2_list(libxl_ctx *ctx, uint32_t domid,
                                       unsigned int *nb);
int libxl_device_net2_del(libxl_ctx *ctx, libxl_device_net2 *net2,
                          int wait);

/* common paths */
const char *libxl_sbindir_path(void);
const char *libxl_bindir_path(void);
const char *libxl_libexec_path(void);
const char *libxl_libdir_path(void);
const char *libxl_sharedir_path(void);
const char *libxl_private_bindir_path(void);
const char *libxl_xenfirmwaredir_path(void);
const char *libxl_xen_config_dir_path(void);
const char *libxl_xen_script_dir_path(void);

#endif /* LIBXL_H */

