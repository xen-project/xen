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

#include "osdeps.h"
#include <stdint.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <xenctrl.h>
#include "xen_uuid.h"

typedef int bool;

typedef void (*libxl_log_callback)(void *userdata, int loglevel, const char *file,
                                   int line, const char *func, char *s);

struct libxl_dominfo {
    xen_uuid_t uuid[16];
    uint32_t domid;
};

struct libxl_ctx {
    int xch;
    struct xs_handle *xsh;
    /* errors/debug buf */
    void *log_userdata;
    libxl_log_callback log_callback;

    /* mini-GC */
    int alloc_maxsize;
    void **alloc_ptrs;
};

typedef struct {
    bool hvm;
    bool hap;
    int ssidref;
    char *name;
    xen_uuid_t *uuid;
    char **xsdata;
    char **platformdata;
} libxl_domain_create_info;

typedef struct {
    int timer_mode;
    int hpet;
    int vpt_align;
    int max_vcpus;
    uint32_t max_memkb;
    uint32_t video_memkb;
    uint32_t shadow_memkb;
    const char *kernel;
    int hvm;
    union {
        struct {
            bool pae;
            bool apic;
            bool acpi;
            bool nx;
            bool viridian;
            char *timeoffset;
        } hvm;
        struct {
            const char *cmdline;
            const char *ramdisk;
            const char *features;
        } pv;
    } u;
} libxl_domain_build_info;

typedef struct libxl_domain_build_state_ libxl_domain_build_state;

typedef struct {
    int flags;
    int (*suspend_callback)(void *, int);
} libxl_domain_suspend_info;

typedef enum {
    XENFV,
    XENPV,
} libxl_qemu_machine_type;

typedef struct {
    int domid;
    char *dom_name;
    char *device_model;
    libxl_qemu_machine_type type;
    int videoram; /* size of the videoram in MB */
    bool stdvga; /* stdvga enabled or disabled */
    bool vnc; /* vnc enabled or disabled */
    char *vnclisten; /* address:port that should be listened on for the VNC server if vnc is set */
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
    bool apic; /* apic enabled or disabled */
    char **extra; /* extra parameters pass directly to qemu, NULL terminated */
    /* Network is missing */
} libxl_device_model_info;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    int devid;
    bool vnc; /* vnc enabled or disabled */
    char *vnclisten; /* address:port that should be listened on for the VNC server if vnc is set */
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
    PHYSTYPE_QCOW,
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
    NICTYPE_IOEMU,
    NICTYPE_VIF,
} libxl_nic_type;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    int devid;
    int mtu;
    char *model;
    uint8_t mac[6];
    char *smac;
    struct in_addr ip;
    char *bridge;
    char *ifname;
    char *script;
    libxl_nic_type nictype;
} libxl_device_nic;

typedef struct  {
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

#define ERROR_FAIL (-2)
#define ERROR_NI (-101)
#define ERROR_NOMEM (-1032)
#define ERROR_INVAL (-1245)

/* context functions */
int libxl_ctx_init(struct libxl_ctx *ctx);
int libxl_ctx_free(struct libxl_ctx *ctx);
int libxl_ctx_set_log(struct libxl_ctx *ctx, libxl_log_callback log_callback, void *log_data);

/* domain related functions */
int libxl_domain_make(struct libxl_ctx *ctx, libxl_domain_create_info *info, uint32_t *domid);
libxl_domain_build_state *libxl_domain_build(struct libxl_ctx *ctx, libxl_domain_build_info *info, uint32_t domid);
int libxl_domain_restore(struct libxl_ctx *ctx, libxl_domain_build_info *info,
                          uint32_t domid, int fd);
int libxl_domain_suspend(struct libxl_ctx *ctx, libxl_domain_suspend_info *info,
                          uint32_t domid, int fd);
int libxl_domain_shutdown(struct libxl_ctx *ctx, uint32_t domid, int req);
int libxl_domain_destroy(struct libxl_ctx *ctx, uint32_t domid, int force);

int libxl_domain_pause(struct libxl_ctx *ctx, uint32_t domid);
int libxl_domain_unpause(struct libxl_ctx *ctx, uint32_t domid);

struct libxl_dominfo * libxl_domain_list(struct libxl_ctx *ctx, int *nb_domain);
xc_dominfo_t * libxl_domain_infolist(struct libxl_ctx *ctx, int *nb_domain);

int libxl_create_device_model(struct libxl_ctx *ctx,
                              libxl_device_model_info *info,
                              libxl_device_nic *vifs, int num_vifs);
int libxl_create_xenpv_qemu(struct libxl_ctx *ctx, libxl_device_vfb *vfb,
                            int num_console, libxl_device_console *console);

int libxl_device_disk_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disk);
int libxl_device_disk_clean_shutdown(struct libxl_ctx *ctx, uint32_t domid);
int libxl_device_disk_hard_shutdown(struct libxl_ctx *ctx, uint32_t domid);

int libxl_device_nic_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_nic *nic);
int libxl_device_nic_clean_shutdown(struct libxl_ctx *ctx, uint32_t domid);
int libxl_device_nic_hard_shutdown(struct libxl_ctx *ctx, uint32_t domid);

int libxl_device_console_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_console *console);

int libxl_device_vkb_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_vkb *vkb);
int libxl_device_vkb_clean_shutdown(struct libxl_ctx *ctx, uint32_t domid);
int libxl_device_vkb_hard_shutdown(struct libxl_ctx *ctx, uint32_t domid);

int libxl_device_vfb_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_vfb *vfb);
int libxl_device_vfb_clean_shutdown(struct libxl_ctx *ctx, uint32_t domid);
int libxl_device_vfb_hard_shutdown(struct libxl_ctx *ctx, uint32_t domid);

#define PCI_BDF                "%04x:%02x:%02x.%01x"
#define PCI_BDF_VDEVFN         "%04x:%02x:%02x.%01x@%02x"
int libxl_device_pci_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev);
int libxl_device_pci_remove(struct libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev);
int libxl_device_pci_shutdown(struct libxl_ctx *ctx, uint32_t domid);
libxl_device_pci *libxl_device_pci_list(struct libxl_ctx *ctx, uint32_t domid, int *num);
int libxl_device_pci_init(libxl_device_pci *pcidev, unsigned int domain,
                          unsigned int bus, unsigned int dev,
                          unsigned int func, unsigned int vdevfn);

#endif
