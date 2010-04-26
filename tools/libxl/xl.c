/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Stefano Stabellini <stefano.stabellini@eu.citrix.com>
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

#include "libxl_osdeps.h"

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h> /* for time */
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <sys/utsname.h> /* for utsname in xl info */
#include <xenctrl.h>
#include <ctype.h>
#include <inttypes.h>

#include "libxl.h"
#include "libxl_utils.h"
#include "libxlutil.h"

#define UUID_FMT "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"

static int logfile = 2;

/* every libxl action in xl uses this same libxl context */
static struct libxl_ctx ctx;

/* when we operate on a domain, it is this one: */
static uint32_t domid;
static const char *common_domname;


static const char savefileheader_magic[32]=
    "Xen saved domain, xl format\n \0 \r";

static const char migrate_receiver_banner[]=
    "xl migration receiver ready, send binary domain data.\n";
static const char migrate_receiver_ready[]=
    "domain received, ready to unpause";
static const char migrate_permission_to_go[]=
    "domain is yours, you are cleared to unpause";
static const char migrate_report[]=
    "my copy unpause results are as follows";
  /* followed by one byte:
   *     0: everything went well, domain is running
   *            next thing is we all exit
   * non-0: things went badly
   *            next thing should be a migrate_permission_to_go
   *            from target to source
   */

struct save_file_header {
    char magic[32]; /* savefileheader_magic */
    /* All uint32_ts are in domain's byte order. */
    uint32_t byteorder; /* SAVEFILE_BYTEORDER_VALUE */
    uint32_t mandatory_flags; /* unknown flags => reject restore */
    uint32_t optional_flags; /* unknown flags => reject restore */
    uint32_t optional_data_len; /* skip, or skip tail, if not understood */
};

/* Optional data, in order:
 *   4 bytes uint32_t  config file size
 *   n bytes           config file in Unix text file format
 */

#define SAVEFILE_BYTEORDER_VALUE ((uint32_t)0x01020304UL)

void log_callback(void *userdata, int loglevel, const char *file, int line, const char *func, char *s)
{
    char str[1024];

    snprintf(str, sizeof(str), "[%d] %s:%d:%s: %s\n", loglevel, file, line, func, s);
    write(logfile, str, strlen(str));
}

static int domain_qualifier_to_domid(const char *p, uint32_t *domid_r,
                                     int *was_name_r)
{
    int i, alldigit;

    alldigit = 1;
    for (i = 0; p[i]; i++) {
        if (!isdigit((uint8_t)p[i])) {
            alldigit = 0;
            break;
        }
    }

    if (i > 0 && alldigit) {
        *domid_r = strtoul(p, NULL, 10);
        if (was_name_r) *was_name_r = 0;
        return 0;
    } else {
        /* check here if it's a uuid and do proper conversion */
    }
    if (was_name_r) *was_name_r = 1;
    return libxl_name_to_domid(&ctx, p, domid_r);
}

static void find_domain(const char *p)
{
    int rc, was_name;

    rc = domain_qualifier_to_domid(p, &domid, &was_name);
    if (rc) {
        fprintf(stderr, "%s is an invalid domain identifier (rc=%d)\n", p, rc);
        exit(2);
    }
    common_domname = was_name ? p : 0;
}

#define LOG(_f, _a...)   dolog(__FILE__, __LINE__, __func__, _f "\n", ##_a)

void dolog(const char *file, int line, const char *func, char *fmt, ...)
{
    va_list ap;
    char *s;
    int rc;

    va_start(ap, fmt);
    rc = vasprintf(&s, fmt, ap);
    va_end(ap);
    if (rc >= 0)
        write(logfile, s, rc);
}

static void init_create_info(libxl_domain_create_info *c_info)
{
    memset(c_info, '\0', sizeof(*c_info));
    c_info->xsdata = NULL;
    c_info->platformdata = NULL;
    c_info->hvm = 1;
    c_info->oos = 1;
    c_info->ssidref = 0;
}

static void init_build_info(libxl_domain_build_info *b_info, libxl_domain_create_info *c_info)
{
    memset(b_info, '\0', sizeof(*b_info));
    b_info->timer_mode = -1;
    b_info->hpet = 1;
    b_info->vpt_align = -1;
    b_info->max_vcpus = 1;
    b_info->max_memkb = 32 * 1024;
    b_info->target_memkb = b_info->max_memkb;
    if (c_info->hvm) {
        b_info->shadow_memkb = libxl_get_required_shadow_memory(b_info->max_memkb, b_info->max_vcpus);
        b_info->video_memkb = 8 * 1024;
        b_info->kernel = "/usr/lib/xen/boot/hvmloader";
        b_info->hvm = 1;
        b_info->u.hvm.pae = 1;
        b_info->u.hvm.apic = 1;
        b_info->u.hvm.acpi = 1;
        b_info->u.hvm.nx = 1;
        b_info->u.hvm.viridian = 0;
    } else {
        b_info->u.pv.slack_memkb = 8 * 1024;
    }
}

static void init_dm_info(libxl_device_model_info *dm_info,
        libxl_domain_create_info *c_info, libxl_domain_build_info *b_info)
{
    int i;
    memset(dm_info, '\0', sizeof(*dm_info));

    for (i = 0; i < 16; i++) {
        dm_info->uuid[i] = rand();
    }

    dm_info->dom_name = c_info->name;
    dm_info->device_model = "/usr/lib/xen/bin/qemu-dm";
    dm_info->videoram = b_info->video_memkb / 1024;
    dm_info->apic = b_info->u.hvm.apic;

    dm_info->stdvga = 0;
    dm_info->vnc = 1;
    dm_info->vnclisten = "127.0.0.1";
    dm_info->vncdisplay = 0;
    dm_info->vncunused = 0;
    dm_info->keymap = NULL;
    dm_info->sdl = 0;
    dm_info->opengl = 0;
    dm_info->nographic = 0;
    dm_info->serial = NULL;
    dm_info->boot = "cda";
    dm_info->usb = 0;
    dm_info->usbdevice = NULL;
}

static void init_nic_info(libxl_device_nic *nic_info, int devnum)
{
    memset(nic_info, '\0', sizeof(*nic_info));

    nic_info->backend_domid = 0;
    nic_info->domid = 0;
    nic_info->devid = devnum;
    nic_info->mtu = 1492;
    nic_info->model = "e1000";
    nic_info->mac[0] = 0x00;
    nic_info->mac[1] = 0x16;
    nic_info->mac[2] = 0x3e;
    nic_info->mac[3] = 1 + (int) (0x7f * (rand() / (RAND_MAX + 1.0)));
    nic_info->mac[4] = 1 + (int) (0xff * (rand() / (RAND_MAX + 1.0)));
    nic_info->mac[5] = 1 + (int) (0xff * (rand() / (RAND_MAX + 1.0)));
    nic_info->ifname = NULL;
    nic_info->bridge = "xenbr0";
    nic_info->script = "/etc/xen/scripts/vif-bridge";
    nic_info->nictype = NICTYPE_IOEMU;
}

static void init_vfb_info(libxl_device_vfb *vfb, int dev_num)
{
    memset(vfb, 0x00, sizeof(libxl_device_vfb));
    vfb->devid = dev_num;
    vfb->vnc = 1;
    vfb->vnclisten = "127.0.0.1";
    vfb->vncdisplay = 0;
    vfb->vncunused = 1;
    vfb->keymap = NULL;
    vfb->sdl = 0;
    vfb->opengl = 0;
}

static void init_vkb_info(libxl_device_vkb *vkb, int dev_num)
{
    memset(vkb, 0x00, sizeof(libxl_device_vkb));
    vkb->devid = dev_num;
}

static void init_console_info(libxl_device_console *console, int dev_num, libxl_domain_build_state *state)
{
    memset(console, 0x00, sizeof(libxl_device_console));
    console->devid = dev_num;
    console->constype = CONSTYPE_XENCONSOLED;
    if (state)
        console->build_state = state;
}

static void printf_info(libxl_domain_create_info *c_info,
                        libxl_domain_build_info *b_info,
                        libxl_device_disk *disks,
                        int num_disks,
                        libxl_device_nic *vifs,
                        int num_vifs,
                        libxl_device_pci *pcidevs,
                        int num_pcidevs,
                        libxl_device_vfb *vfbs,
                        int num_vfbs,
                        libxl_device_vkb *vkb,
                        int num_vkbs,
                        libxl_device_model_info *dm_info)
{
    int i;
    printf("*** domain_create_info ***\n");
    printf("hvm: %d\n", c_info->hvm);
    printf("hap: %d\n", c_info->hap);
    printf("oos: %d\n", c_info->oos);
    printf("ssidref: %d\n", c_info->ssidref);
    printf("name: %s\n", c_info->name);
    printf("uuid: " UUID_FMT "\n",
           (c_info->uuid)[0], (c_info->uuid)[1], (c_info->uuid)[2], (c_info->uuid)[3],
           (c_info->uuid)[4], (c_info->uuid)[5], (c_info->uuid)[6], (c_info->uuid)[7],
           (c_info->uuid)[8], (c_info->uuid)[9], (c_info->uuid)[10], (c_info->uuid)[11],
           (c_info->uuid)[12], (c_info->uuid)[13], (c_info->uuid)[14], (c_info->uuid)[15]);
    if (c_info->xsdata)
        printf("xsdata: contains data\n");
    else
        printf("xsdata: (null)\n");
    if (c_info->platformdata)
        printf("platformdata: contains data\n");
    else
        printf("platformdata: (null)\n");


    printf("\n\n\n*** domain_build_info ***\n");
    printf("timer_mode: %d\n", b_info->timer_mode);
    printf("hpet: %d\n", b_info->hpet);
    printf("vpt_align: %d\n", b_info->vpt_align);
    printf("max_vcpus: %d\n", b_info->max_vcpus);
    printf("tsc_mode: %d\n", b_info->tsc_mode);
    printf("max_memkb: %d\n", b_info->max_memkb);
    printf("target_memkb: %d\n", b_info->target_memkb);
    printf("kernel: %s\n", b_info->kernel);
    printf("hvm: %d\n", b_info->hvm);

    if (c_info->hvm) {
        printf("video_memkb: %d\n", b_info->video_memkb);
        printf("shadow_memkb: %d\n", b_info->shadow_memkb);
        printf("    pae: %d\n", b_info->u.hvm.pae);
        printf("    apic: %d\n", b_info->u.hvm.apic);
        printf("    acpi: %d\n", b_info->u.hvm.acpi);
        printf("    nx: %d\n", b_info->u.hvm.nx);
        printf("    viridian: %d\n", b_info->u.hvm.viridian);
    } else {
        printf("cmdline: %s\n", b_info->u.pv.cmdline);
        printf("ramdisk: %s\n", b_info->u.pv.ramdisk);
    }

    for (i = 0; i < num_disks; i++) {
        printf("\n\n\n*** disks_info: %d ***\n", i);
        printf("backend_domid %d\n", disks[i].backend_domid);
        printf("domid %d\n", disks[i].domid);
        printf("physpath %s\n", disks[i].physpath);
        printf("phystype %d\n", disks[i].phystype);
        printf("virtpath %s\n", disks[i].virtpath);
        printf("unpluggable %d\n", disks[i].unpluggable);
        printf("readwrite %d\n", disks[i].readwrite);
        printf("is_cdrom %d\n", disks[i].is_cdrom);
    }

    for (i = 0; i < num_vifs; i++) {
        printf("\n\n\n*** vifs_info: %d ***\n", i);
        printf("backend_domid %d\n", vifs[i].backend_domid);
        printf("domid %d\n", vifs[i].domid);
        printf("devid %d\n", vifs[i].devid);
        printf("mtu %d\n", vifs[i].mtu);
        printf("model %s\n", vifs[i].model);
        printf("mac %02x:%02x:%02x:%02x:%02x:%02x\n", vifs[i].mac[0], vifs[i].mac[1], vifs[i].mac[2], vifs[i].mac[3], vifs[i].mac[4], vifs[i].mac[5]);
    }

    for (i = 0; i < num_pcidevs; i++) {
        printf("\n\n\n*** pcidevs_info: %d ***\n", i);
        printf("pci dev "PCI_BDF_VDEVFN"\n", pcidevs[i].domain, pcidevs[i].bus, pcidevs[i].dev, pcidevs[i].func, pcidevs[i].vdevfn);
        printf("opts msitranslate %d power_mgmt %d\n", pcidevs[i].msitranslate, pcidevs[i].power_mgmt);
    }

    for (i = 0; i < num_vfbs; i++) {
        printf("\n\n\n*** vfbs_info: %d ***\n", i);
        printf("backend_domid %d\n", vfbs[i].backend_domid);
        printf("domid %d\n", vfbs[i].domid);
        printf("devid %d\n", vfbs[i].devid);
        printf("vnc: %d\n", vfbs[i].vnc);
        printf("vnclisten: %s\n", vfbs[i].vnclisten);
        printf("vncdisplay: %d\n", vfbs[i].vncdisplay);
        printf("vncunused: %d\n", vfbs[i].vncunused);
        printf("keymap: %s\n", vfbs[i].keymap);
        printf("sdl: %d\n", vfbs[i].sdl);
        printf("opengl: %d\n", vfbs[i].opengl);
        printf("display: %s\n", vfbs[i].display);
        printf("xauthority: %s\n", vfbs[i].xauthority);
    }

    if (c_info->hvm) {
        printf("\n\n\n*** device_model_info ***\n");
        printf("domid: %d\n", dm_info->domid);
        printf("dom_name: %s\n", dm_info->dom_name);
        printf("device_model: %s\n", dm_info->device_model);
        printf("videoram: %d\n", dm_info->videoram);
        printf("stdvga: %d\n", dm_info->stdvga);
        printf("vnc: %d\n", dm_info->vnc);
        printf("vnclisten: %s\n", dm_info->vnclisten);
        printf("vncdisplay: %d\n", dm_info->vncdisplay);
        printf("vncunused: %d\n", dm_info->vncunused);
        printf("keymap: %s\n", dm_info->keymap);
        printf("sdl: %d\n", dm_info->sdl);
        printf("opengl: %d\n", dm_info->opengl);
        printf("nographic: %d\n", dm_info->nographic);
        printf("serial: %s\n", dm_info->serial);
        printf("boot: %s\n", dm_info->boot);
        printf("usb: %d\n", dm_info->usb);
        printf("usbdevice: %s\n", dm_info->usbdevice);
        printf("apic: %d\n", dm_info->apic);
    }
}

static void parse_config_data(const char *configfile_filename_report,
                              const char *configfile_data,
                              int configfile_len,
                              libxl_domain_create_info *c_info,
                              libxl_domain_build_info *b_info,
                              libxl_device_disk **disks,
                              int *num_disks,
                              libxl_device_nic **vifs,
                              int *num_vifs,
                              libxl_device_pci **pcidevs,
                              int *num_pcidevs,
                              libxl_device_vfb **vfbs,
                              int *num_vfbs,
                              libxl_device_vkb **vkbs,
                              int *num_vkbs,
                              libxl_device_model_info *dm_info)
{
    const char *buf;
    long l;
    XLU_Config *config;
    XLU_ConfigList *vbds, *nics, *pcis, *cvfbs;
    int pci_power_mgmt = 0;
    int pci_msitranslate = 1;
    int i, e;

    config= xlu_cfg_init(stderr, configfile_filename_report);
    if (!config) {
        fprintf(stderr, "Failed to allocate for configuration\n");
        exit(1);
    }

    e= xlu_cfg_readdata(config, configfile_data, configfile_len);
    if (e) {
        fprintf(stderr, "Failed to parse config file: %s\n", strerror(e));
        exit(1);
    }

    init_create_info(c_info);

    c_info->hvm = 0;
    if (!xlu_cfg_get_string (config, "builder", &buf) &&
        !strncmp(buf, "hvm", strlen(buf)))
        c_info->hvm = 1;

    /* hap is missing */
    if (!xlu_cfg_get_string (config, "name", &buf))
        c_info->name = strdup(buf);
    else
        c_info->name = "test";
    for (i = 0; i < 16; i++) {
        c_info->uuid[i] = rand();
    }

    if (!xlu_cfg_get_long(config, "oos", &l))
        c_info->oos = l;

    init_build_info(b_info, c_info);

    /* the following is the actual config parsing with overriding values in the structures */
    if (!xlu_cfg_get_long (config, "vcpus", &l))
        b_info->max_vcpus = l;

    if (!xlu_cfg_get_long (config, "memory", &l)) {
        b_info->max_memkb = l * 1024;
        b_info->target_memkb = b_info->max_memkb;
    }

    if (!xlu_cfg_get_long(config, "tsc_mode", &l))
        b_info->tsc_mode = l;

    if (!xlu_cfg_get_long (config, "shadow_memory", &l))
        b_info->shadow_memkb = l * 1024;

    if (!xlu_cfg_get_long (config, "videoram", &l))
        b_info->video_memkb = l * 1024;

    if (!xlu_cfg_get_string (config, "kernel", &buf))
        b_info->kernel = strdup(buf);

    if (c_info->hvm == 1) {
        if (!xlu_cfg_get_long (config, "pae", &l))
            b_info->u.hvm.pae = l;
        if (!xlu_cfg_get_long (config, "apic", &l))
            b_info->u.hvm.apic = l;
        if (!xlu_cfg_get_long (config, "acpi", &l))
            b_info->u.hvm.acpi = l;
        if (!xlu_cfg_get_long (config, "nx", &l))
            b_info->u.hvm.nx = l;
        if (!xlu_cfg_get_long (config, "viridian", &l))
            b_info->u.hvm.viridian = l;
    } else {
        char *cmdline;
        if (!xlu_cfg_get_string (config, "root", &buf)) {
            asprintf(&cmdline, "root=%s", buf);
            b_info->u.pv.cmdline = cmdline;
        }
        if (!xlu_cfg_get_string (config, "ramdisk", &buf))
            b_info->u.pv.ramdisk = strdup(buf);
    }

    if (!xlu_cfg_get_list (config, "disk", &vbds, 0)) {
        *num_disks = 0;
        *disks = NULL;
        while ((buf = xlu_cfg_get_listitem (vbds, *num_disks)) != NULL) {
            char *buf2 = strdup(buf);
            char *p, *p2;
            *disks = (libxl_device_disk *) realloc(*disks, sizeof (libxl_device_disk) * ((*num_disks) + 1));
            (*disks)[*num_disks].backend_domid = 0;
            (*disks)[*num_disks].domid = 0;
            (*disks)[*num_disks].unpluggable = 0;
            p = strtok(buf2, ",:");
            while (*p == ' ')
                p++;
            if (!strcmp(p, "phy")) {
                (*disks)[*num_disks].phystype = PHYSTYPE_PHY;
            } else if (!strcmp(p, "file")) {
                (*disks)[*num_disks].phystype = PHYSTYPE_FILE;
            } else if (!strcmp(p, "tap")) {
                p = strtok(NULL, ":");
                if (!strcmp(p, "aio")) {
                    (*disks)[*num_disks].phystype = PHYSTYPE_AIO;
                } else if (!strcmp(p, "vhd")) {
                    (*disks)[*num_disks].phystype = PHYSTYPE_VHD;
                } else if (!strcmp(p, "qcow")) {
                    (*disks)[*num_disks].phystype = PHYSTYPE_QCOW;
                } else if (!strcmp(p, "qcow2")) {
                    (*disks)[*num_disks].phystype = PHYSTYPE_QCOW2;
                }
            }
            p = strtok(NULL, ",");
            while (*p == ' ')
                p++;
            (*disks)[*num_disks].physpath= strdup(p);
            p = strtok(NULL, ",");
            while (*p == ' ')
                p++;
            p2 = strchr(p, ':');
            if (p2 == NULL) {
                (*disks)[*num_disks].virtpath = strdup(p);
                (*disks)[*num_disks].is_cdrom = 0;
                (*disks)[*num_disks].unpluggable = 1;
            } else {
                *p2 = '\0';
                (*disks)[*num_disks].virtpath = strdup(p);
                if (!strcmp(p2 + 1, "cdrom")) {
                    (*disks)[*num_disks].is_cdrom = 1;
                    (*disks)[*num_disks].unpluggable = 1;
                } else
                    (*disks)[*num_disks].is_cdrom = 0;
            }
            p = strtok(NULL, ",");
            while (*p == ' ')
                p++;
            (*disks)[*num_disks].readwrite = (p[0] == 'w') ? 1 : 0;
            free(buf2);
            *num_disks = (*num_disks) + 1;
        }
    }

    if (!xlu_cfg_get_list (config, "vif", &nics, 0)) {
        *num_vifs = 0;
        *vifs = NULL;
        while ((buf = xlu_cfg_get_listitem (nics, *num_vifs)) != NULL) {
            char *buf2 = strdup(buf);
            char *p, *p2;
            *vifs = (libxl_device_nic *) realloc(*vifs, sizeof (libxl_device_nic) * ((*num_vifs) + 1));
            init_nic_info((*vifs) + (*num_vifs), (*num_vifs) + 1);
            p = strtok(buf2, ",");
            if (!p)
                goto skip;
            do {
                while (*p == ' ')
                    p++;
                if ((p2 = strchr(p, '=')) == NULL)
                    break;
                *p2 = '\0';
                if (!strcmp(p, "model")) {
                    (*vifs)[*num_vifs].model = strdup(p2 + 1);
                } else if (!strcmp(p, "mac")) {
                    char *p3 = p2 + 1;
                    *(p3 + 2) = '\0';
                    (*vifs)[*num_vifs].mac[0] = strtol(p3, NULL, 16);
                    p3 = p3 + 3;
                    *(p3 + 2) = '\0';
                    (*vifs)[*num_vifs].mac[1] = strtol(p3, NULL, 16);
                    p3 = p3 + 3;
                    *(p3 + 2) = '\0';
                    (*vifs)[*num_vifs].mac[2] = strtol(p3, NULL, 16);
                    p3 = p3 + 3;
                    *(p3 + 2) = '\0';
                    (*vifs)[*num_vifs].mac[3] = strtol(p3, NULL, 16);
                    p3 = p3 + 3;
                    *(p3 + 2) = '\0';
                    (*vifs)[*num_vifs].mac[4] = strtol(p3, NULL, 16);
                    p3 = p3 + 3;
                    *(p3 + 2) = '\0';
                    (*vifs)[*num_vifs].mac[5] = strtol(p3, NULL, 16);
                } else if (!strcmp(p, "bridge")) {
                    (*vifs)[*num_vifs].bridge = strdup(p2 + 1);
                } else if (!strcmp(p, "type")) {
                    if (!strcmp(p2 + 1, "ioemu"))
                        (*vifs)[*num_vifs].nictype = NICTYPE_IOEMU;
                    else
                        (*vifs)[*num_vifs].nictype = NICTYPE_VIF;
                } else if (!strcmp(p, "ip")) {
                    inet_pton(AF_INET, p2 + 1, &((*vifs)[*num_vifs].ip));
                } else if (!strcmp(p, "script")) {
                    (*vifs)[*num_vifs].script = strdup(p2 + 1);
                } else if (!strcmp(p, "vifname")) {
                    (*vifs)[*num_vifs].ifname = strdup(p2 + 1);
                } else if (!strcmp(p, "rate")) {
                    fprintf(stderr, "the rate parameter for vifs is currently not supported\n");
                } else if (!strcmp(p, "accel")) {
                    fprintf(stderr, "the accel parameter for vifs is currently not supported\n");
                }
            } while ((p = strtok(NULL, ",")) != NULL);
skip:
            free(buf2);
            *num_vifs = (*num_vifs) + 1;
        }
    }

    if (!xlu_cfg_get_list (config, "vfb", &cvfbs, 0)) {
        *num_vfbs = 0;
        *num_vkbs = 0;
        *vfbs = NULL;
        *vkbs = NULL;
        while ((buf = xlu_cfg_get_listitem (cvfbs, *num_vfbs)) != NULL) {
            char *buf2 = strdup(buf);
            char *p, *p2;
            *vfbs = (libxl_device_vfb *) realloc(*vfbs, sizeof(libxl_device_vfb) * ((*num_vfbs) + 1));
            init_vfb_info((*vfbs) + (*num_vfbs), (*num_vfbs));

            *vkbs = (libxl_device_vkb *) realloc(*vkbs, sizeof(libxl_device_vkb) * ((*num_vkbs) + 1));
            init_vkb_info((*vkbs) + (*num_vkbs), (*num_vkbs));

            p = strtok(buf2, ",");
            if (!p)
                goto skip_vfb;
            do {
                while (*p == ' ')
                    p++;
                if ((p2 = strchr(p, '=')) == NULL)
                    break;
                *p2 = '\0';
                if (!strcmp(p, "vnc")) {
                    (*vfbs)[*num_vfbs].vnc = atoi(p2 + 1);
                } else if (!strcmp(p, "vnclisten")) {
                    (*vfbs)[*num_vfbs].vnclisten = strdup(p2 + 1);
                } else if (!strcmp(p, "vncdisplay")) {
                    (*vfbs)[*num_vfbs].vncdisplay = atoi(p2 + 1);
                } else if (!strcmp(p, "vncunused")) {
                    (*vfbs)[*num_vfbs].vncunused = atoi(p2 + 1);
                } else if (!strcmp(p, "keymap")) {
                    (*vfbs)[*num_vfbs].keymap = strdup(p2 + 1);
                } else if (!strcmp(p, "sdl")) {
                    (*vfbs)[*num_vfbs].sdl = atoi(p2 + 1);
                } else if (!strcmp(p, "opengl")) {
                    (*vfbs)[*num_vfbs].opengl = atoi(p2 + 1);
                } else if (!strcmp(p, "display")) {
                    (*vfbs)[*num_vfbs].display = strdup(p2 + 1);
                } else if (!strcmp(p, "xauthority")) {
                    (*vfbs)[*num_vfbs].xauthority = strdup(p2 + 1);
                }
            } while ((p = strtok(NULL, ",")) != NULL);
skip_vfb:
            free(buf2);
            *num_vfbs = (*num_vfbs) + 1;
            *num_vkbs = (*num_vkbs) + 1;
        }
    }

    if (!xlu_cfg_get_long (config, "pci_msitranslate", &l))
        pci_msitranslate = l;

    if (!xlu_cfg_get_long (config, "pci_power_mgmt", &l))
        pci_power_mgmt = l;

    if (!xlu_cfg_get_list (config, "pci", &pcis, 0)) {
        *num_pcidevs = 0;
        *pcidevs = NULL;
        while ((buf = xlu_cfg_get_listitem (pcis, *num_pcidevs)) != NULL) {
            unsigned int domain = 0, bus = 0, dev = 0, func = 0, vdevfn = 0;
            char *buf2 = strdup(buf);
            char *p;
            *pcidevs = (libxl_device_pci *) realloc(*pcidevs, sizeof (libxl_device_pci) * ((*num_pcidevs) + 1));
            memset(*pcidevs + *num_pcidevs, 0x00, sizeof(libxl_device_pci));
            p = strtok(buf2, ",");
            if (!p)
                goto skip_pci;
            if (!sscanf(p, PCI_BDF_VDEVFN, &domain, &bus, &dev, &func, &vdevfn)) {
                sscanf(p, "%02x:%02x.%01x@%02x", &bus, &dev, &func, &vdevfn);
                domain = 0;
            }
            libxl_device_pci_init(*pcidevs + *num_pcidevs, domain, bus, dev, func, vdevfn);
            (*pcidevs)[*num_pcidevs].msitranslate = pci_msitranslate;
            (*pcidevs)[*num_pcidevs].power_mgmt = pci_power_mgmt;
            while ((p = strtok(NULL, ",=")) != NULL) {
                while (*p == ' ')
                    p++;
                if (!strcmp(p, "msitranslate")) {
                    p = strtok(NULL, ",=");
                    (*pcidevs)[*num_pcidevs].msitranslate = atoi(p);
                } else if (!strcmp(p, "power_mgmt")) {
                    p = strtok(NULL, ",=");
                    (*pcidevs)[*num_pcidevs].power_mgmt = atoi(p);
                }
            }
            *num_pcidevs = (*num_pcidevs) + 1;
skip_pci:
            free(buf2);
        }
    }

    if (c_info->hvm == 1) {
        /* init dm from c and b */
        init_dm_info(dm_info, c_info, b_info);

        /* then process config related to dm */
        if (!xlu_cfg_get_string (config, "device_model", &buf))
            dm_info->device_model = strdup(buf);
        if (!xlu_cfg_get_long (config, "stdvga", &l))
            dm_info->stdvga = l;
        if (!xlu_cfg_get_long (config, "vnc", &l))
            dm_info->vnc = l;
        if (!xlu_cfg_get_string (config, "vnclisten", &buf))
            dm_info->vnclisten = strdup(buf);
        if (!xlu_cfg_get_long (config, "vncdisplay", &l))
            dm_info->vncdisplay = l;
        if (!xlu_cfg_get_long (config, "vncunused", &l))
            dm_info->vncunused = l;
        if (!xlu_cfg_get_string (config, "keymap", &buf))
            dm_info->keymap = strdup(buf);
        if (!xlu_cfg_get_long (config, "sdl", &l))
            dm_info->sdl = l;
        if (!xlu_cfg_get_long (config, "opengl", &l))
            dm_info->opengl = l;
        if (!xlu_cfg_get_long (config, "nographic", &l))
            dm_info->nographic = l;
        if (!xlu_cfg_get_string (config, "serial", &buf))
            dm_info->serial = strdup(buf);
        if (!xlu_cfg_get_string (config, "boot", &buf))
            dm_info->boot = strdup(buf);
        if (!xlu_cfg_get_long (config, "usb", &l))
            dm_info->usb = l;
        if (!xlu_cfg_get_string (config, "usbdevice", &buf))
            dm_info->usbdevice = strdup(buf);
    }

    dm_info->type = c_info->hvm ? XENFV : XENPV;

    xlu_cfg_destroy(config);
}

#define CHK_ERRNO( call ) ({                                            \
        int chk_errno = (call);                                         \
        if (chk_errno) {                                                \
            fprintf(stderr,"xl: fatal error: %s:%d: %s: %s\n",          \
                    __FILE__,__LINE__, strerror(chk_errno), #call);     \
            exit(-ERROR_FAIL);                                          \
        }                                                               \
    })

#define MUST( call ) ({                                                 \
        int must_rc = (call);                                           \
        if (must_rc) {                                                  \
            fprintf(stderr,"xl: fatal error: %s:%d, rc=%d: %s\n",       \
                    __FILE__,__LINE__, must_rc, #call);                 \
            exit(-must_rc);                                             \
        }                                                               \
    })

static void *xmalloc(size_t sz) {
    void *r;
    r = malloc(sz);
    if (!r) { fprintf(stderr,"xl: Unable to malloc %lu bytes.\n",
                      (unsigned long)sz); exit(-ERROR_FAIL); }
    return r;
}

static void *xrealloc(void *ptr, size_t sz) {
    void *r;
    if (!sz) { free(ptr); return 0; }
      /* realloc(non-0, 0) has a useless return value;
       * but xrealloc(anything, 0) is like free
       */
    r = realloc(ptr, sz);
    if (!r) { fprintf(stderr,"xl: Unable to realloc to %lu bytes.\n",
                      (unsigned long)sz); exit(-ERROR_FAIL); }
    return r;
}

static int create_domain(int debug, int daemonize, const char *config_file, const char *restore_file, int paused, int migrate_fd /* -1 means none */, char **migration_domname_r)
{
    libxl_domain_create_info info1;
    libxl_domain_build_info info2;
    libxl_domain_build_state state;
    libxl_device_model_info dm_info;
    libxl_device_disk *disks = NULL;
    libxl_device_nic *vifs = NULL;
    libxl_device_pci *pcidevs = NULL;
    libxl_device_vfb *vfbs = NULL;
    libxl_device_vkb *vkbs = NULL;
    libxl_device_console console;
    int num_disks = 0, num_vifs = 0, num_pcidevs = 0, num_vfbs = 0, num_vkbs = 0;
    int i, fd;
    int need_daemon = 1;
    int ret, rc;
    libxl_device_model_starting *dm_starting = 0;
    libxl_waiter *w1 = NULL, *w2 = NULL;
    void *config_data = 0;
    int config_len = 0;
    int restore_fd = -1;
    struct save_file_header hdr;

    memset(&dm_info, 0x00, sizeof(dm_info));

    if (restore_file) {
        uint8_t *optdata_begin = 0;
        const uint8_t *optdata_here = 0;
        union { uint32_t u32; char b[4]; } u32buf;
        uint32_t badflags;

        restore_fd = migrate_fd >= 0 ? migrate_fd :
            open(restore_file, O_RDONLY);

        CHK_ERRNO( libxl_read_exactly(&ctx, restore_fd, &hdr,
                   sizeof(hdr), restore_file, "header") );
        if (memcmp(hdr.magic, savefileheader_magic, sizeof(hdr.magic))) {
            fprintf(stderr, "File has wrong magic number -"
                    " corrupt or for a different tool?\n");
            return ERROR_INVAL;
        }
        if (hdr.byteorder != SAVEFILE_BYTEORDER_VALUE) {
            fprintf(stderr, "File has wrong byte order\n");
            return ERROR_INVAL;
        }
        fprintf(stderr, "Loading new save file %s"
                " (new xl fmt info"
                " 0x%"PRIx32"/0x%"PRIx32"/%"PRIu32")\n",
                restore_file, hdr.mandatory_flags, hdr.optional_flags,
                hdr.optional_data_len);

        badflags = hdr.mandatory_flags & ~( 0 /* none understood yet */ );
        if (badflags) {
            fprintf(stderr, "Savefile has mandatory flag(s) 0x%"PRIx32" "
                    "which are not supported; need newer xl\n",
                    badflags);
            return ERROR_INVAL;
        }
        if (hdr.optional_data_len) {
            optdata_begin = xmalloc(hdr.optional_data_len);
            CHK_ERRNO( libxl_read_exactly(&ctx, restore_fd, optdata_begin,
                   hdr.optional_data_len, restore_file, "optdata") );
        }

#define OPTDATA_LEFT  (hdr.optional_data_len - (optdata_here - optdata_begin))
#define WITH_OPTDATA(amt, body)                                 \
            if (OPTDATA_LEFT < (amt)) {                         \
                fprintf(stderr, "Savefile truncated.\n");       \
                return ERROR_INVAL;                             \
            } else {                                            \
                body;                                           \
                optdata_here += (amt);                          \
            }

        optdata_here = optdata_begin;

        if (OPTDATA_LEFT) {
            fprintf(stderr, " Savefile contains xl domain config\n");
            WITH_OPTDATA(4, {
                memcpy(u32buf.b, optdata_here, 4);
                config_len = u32buf.u32;
            });
            WITH_OPTDATA(config_len, {
                config_data = xmalloc(config_len);
                memcpy(config_data, optdata_here, config_len);
            });
        }

    }

    if (config_file) {
        free(config_data);  config_data = 0;
        ret = libxl_read_file_contents(&ctx, config_file,
                                       &config_data, &config_len);
        if (ret) { fprintf(stderr, "Failed to read config file: %s: %s\n",
                           config_file, strerror(errno)); return ERROR_FAIL; }
    } else {
        if (!config_data) {
            fprintf(stderr, "Config file not specified and"
                    " none in save file\n");
            return ERROR_INVAL;
        }
        config_file = "<saved>";
    }

    printf("Parsing config file %s\n", config_file);

    parse_config_data(config_file, config_data, config_len, &info1, &info2, &disks, &num_disks, &vifs, &num_vifs, &pcidevs, &num_pcidevs, &vfbs, &num_vfbs, &vkbs, &num_vkbs, &dm_info);

    if (migrate_fd >= 0) {
        if (info1.name) {
            /* when we receive a domain we get its name from the config
             * file; and we receive it to a temporary name */
            assert(!common_domname);
            common_domname = info1.name;
            asprintf(migration_domname_r, "%s--incoming", info1.name);
            info1.name = *migration_domname_r;
        }
    }

    if (debug)
        printf_info(&info1, &info2, disks, num_disks, vifs, num_vifs, pcidevs, num_pcidevs, vfbs, num_vfbs, vkbs, num_vkbs, &dm_info);

start:
    domid = 0;

    ret = libxl_domain_make(&ctx, &info1, &domid);
    if (ret) {
        fprintf(stderr, "cannot make domain: %d\n", ret);
        return ERROR_FAIL;
    }

    ret = libxl_userdata_store(&ctx, domid, "xl",
                                    config_data, config_len);
    if (ret) {
        perror("cannot save config file");
        return ERROR_FAIL;
    }

    if (!restore_file || !need_daemon) {
        if (dm_info.saved_state) {
            free(dm_info.saved_state);
            dm_info.saved_state = NULL;
        }
        ret = libxl_domain_build(&ctx, &info2, domid, &state);
    } else {
        ret = libxl_domain_restore(&ctx, &info2, domid, restore_fd, &state, &dm_info);
    }

    if (ret) {
        fprintf(stderr, "cannot (re-)build domain: %d\n", ret);
        return ERROR_FAIL;
    }

    for (i = 0; i < num_disks; i++) {
        disks[i].domid = domid;
        ret = libxl_device_disk_add(&ctx, domid, &disks[i]);
        if (ret) {
            fprintf(stderr, "cannot add disk %d to domain: %d\n", i, ret);
            return ERROR_FAIL;
        }
    }
    for (i = 0; i < num_vifs; i++) {
        vifs[i].domid = domid;
        ret = libxl_device_nic_add(&ctx, domid, &vifs[i]);
        if (ret) {
            fprintf(stderr, "cannot add nic %d to domain: %d\n", i, ret);
            return ERROR_FAIL;
        }
    }
    if (info1.hvm) {
        dm_info.domid = domid;
        MUST( libxl_create_device_model(&ctx, &dm_info, disks, num_disks,
                                        vifs, num_vifs, &dm_starting) );
    } else {
        for (i = 0; i < num_vfbs; i++) {
            vfbs[i].domid = domid;
            libxl_device_vfb_add(&ctx, domid, &vfbs[i]);
            vkbs[i].domid = domid;
            libxl_device_vkb_add(&ctx, domid, &vkbs[i]);
        }
        init_console_info(&console, 0, &state);
        console.domid = domid;
        if (num_vfbs)
            console.constype = CONSTYPE_IOEMU;
        libxl_device_console_add(&ctx, domid, &console);
        if (num_vfbs)
            libxl_create_xenpv_qemu(&ctx, vfbs, 1, &console, &dm_starting);
    }

    if (dm_starting)
        MUST( libxl_confirm_device_model_startup(&ctx, dm_starting) );
    for (i = 0; i < num_pcidevs; i++)
        libxl_device_pci_add(&ctx, domid, &pcidevs[i]);

    if (!paused)
        libxl_domain_unpause(&ctx, domid);

    if (!daemonize)
        return 0; /* caller gets success in parent */

    if (need_daemon) {
        char *fullname, *name;
        pid_t child1, got_child;
        int nullfd;

        child1 = libxl_fork(&ctx);
        if (child1) {
            int status;
            for (;;) {
                got_child = waitpid(child1, &status, 0);
                if (got_child == child1) break;
                assert(got_child == -1);
                if (errno != EINTR) {
                    perror("failed to wait for daemonizing child");
                    return ERROR_FAIL;
                }
            }
            if (status) {
                libxl_report_child_exitstatus(&ctx, XL_LOG_ERROR,
                           "daemonizing child", child1, status);
                return ERROR_FAIL;
            }
            return 0; /* caller gets success in parent */
        }

        rc = libxl_ctx_postfork(&ctx);
        if (rc) {
            LOG("failed to reinitialise context after fork");
            exit(-1);
        }

        asprintf(&name, "xl-%s", info1.name);
        rc = libxl_create_logfile(&ctx, name, &fullname);
        if (rc) {
            LOG("failed to open logfile %s",fullname,strerror(errno));
            exit(-1);
        }

        CHK_ERRNO(( logfile = open(fullname, O_WRONLY|O_CREAT, 0644) )<0);
        free(fullname);
        free(name);

        CHK_ERRNO(( nullfd = open("/dev/null", O_RDONLY) )<0);
        dup2(nullfd, 0);
        dup2(logfile, 1);
        dup2(logfile, 2);

        daemon(0, 1);
        need_daemon = 0;
    }
    LOG("Waiting for domain %s (domid %d) to die [pid %ld]",
        info1.name, domid, (long)getpid());
    w1 = (libxl_waiter*) xmalloc(sizeof(libxl_waiter) * num_disks);
    w2 = (libxl_waiter*) xmalloc(sizeof(libxl_waiter));
    libxl_wait_for_disk_ejects(&ctx, domid, disks, num_disks, w1);
    libxl_wait_for_domain_death(&ctx, domid, w2);
    libxl_get_wait_fd(&ctx, &fd);
    while (1) {
        int ret;
        fd_set rfds;
        xc_domaininfo_t info;
        libxl_event event;
        libxl_device_disk disk;
        memset(&info, 0x00, sizeof(xc_dominfo_t));

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        ret = select(fd + 1, &rfds, NULL, NULL, NULL);
        if (!ret)
            continue;
        libxl_get_event(&ctx, &event);
        switch (event.type) {
            case DOMAIN_DEATH:
                if (libxl_event_get_domain_death_info(&ctx, domid, &event, &info)) {
                    LOG("Domain %d is dead", domid);
                    if (info.flags & XEN_DOMINF_dying || (info.flags & XEN_DOMINF_shutdown && (((info.flags >> XEN_DOMINF_shutdownshift) & XEN_DOMINF_shutdownmask) != SHUTDOWN_suspend))) {
                        LOG("Domain %d needs to be clean: destroying the domain", domid);
                        libxl_domain_destroy(&ctx, domid, 0);
                        if (info.flags & XEN_DOMINF_shutdown &&
                            (((info.flags >> XEN_DOMINF_shutdownshift) & XEN_DOMINF_shutdownmask) == SHUTDOWN_reboot)) {
                            libxl_free_waiter(w1);
                            libxl_free_waiter(w2);
                            free(w1);
                            free(w2);
                            LOG("Done. Rebooting now");
                            goto start;
                        }
                        LOG("Done. Exiting now");
                    }
                    LOG("Domain %d does not need to be clean, exiting now", domid);
                    exit(0);
                }
                break;
            case DISK_EJECT:
                if (libxl_event_get_disk_eject_info(&ctx, domid, &event, &disk))
                    libxl_cdrom_insert(&ctx, domid, &disk);
                break;
        }
        libxl_free_event(&event);
    }

    close(logfile);
    exit(0);
}

static void help(char *command)
{
    if (!command || !strcmp(command, "help")) {
        printf("Usage xl <subcommand> [args]\n\n");
        printf("xl full list of subcommands:\n\n");
        printf(" create                        create a domain from config file <filename>\n\n");
        printf(" list                          list information about all domains\n\n");
        printf(" destroy                       terminate a domain immediately\n\n");
        printf(" pci-attach                    insert a new pass-through pci device\n\n");
        printf(" pci-detach                    remove a domain's pass-through pci device\n\n");
        printf(" pci-list                      list pass-through pci devices for a domain\n\n");
        printf(" pause                         pause execution of a domain\n\n");
        printf(" unpause                       unpause a paused domain\n\n");
        printf(" console                       attach to domain's console\n\n");
        printf(" save                          save a domain state to restore later\n\n");
        printf(" restore                       restore a domain from a saved state\n\n");
        printf(" cd-insert                     insert a cdrom into a guest's cd drive\n\n");
        printf(" cd-eject                      eject a cdrom from a guest's cd drive\n\n");
        printf(" mem-set                       set the current memory usage for a domain\n\n");
        printf(" button-press                  indicate an ACPI button press to the domain\n\n");
        printf(" vcpu-list                     list the VCPUs for all/some domains.\n\n");
        printf(" vcpu-pin                      Set which CPUs a VCPU can use.\n\n");
        printf(" vcpu-set                      Set the number of active VCPUs allowed for the domain.\n\n");
    } else if(!strcmp(command, "create")) {
        printf("Usage: xl create <ConfigFile> [options] [vars]\n\n");
        printf("Create a domain based on <ConfigFile>.\n\n");
        printf("Options:\n\n");
        printf("-h                     Print this help.\n");
        printf("-p                     Leave the domain paused after it is created.\n");
        printf("-d                     Enable debug messages.\n");
        printf("-e                     Do not wait in the background for the death of the domain.\n");
    } else if(!strcmp(command, "list")) {
        printf("Usage: xl list [-v] [Domain]\n\n");
        printf("List information about all/some domains.\n\n");
    } else if(!strcmp(command, "pci-attach")) {
        printf("Usage: xl pci-attach <Domain> <BDF> [Virtual Slot]\n\n");
        printf("Insert a new pass-through pci device.\n\n");
    } else if(!strcmp(command, "pci-detach")) {
        printf("Usage: xl pci-detach <Domain> <BDF>\n\n");
        printf("Remove a domain's pass-through pci device.\n\n");
    } else if(!strcmp(command, "pci-list")) {
        printf("Usage: xl pci-list <Domain>\n\n");
        printf("List pass-through pci devices for a domain.\n\n");
    } else if(!strcmp(command, "pause")) {
        printf("Usage: xl pause <Domain>\n\n");
        printf("Pause execution of a domain.\n\n");
    } else if(!strcmp(command, "unpause")) {
        printf("Usage: xl unpause <Domain>\n\n");
        printf("Unpause a paused domain.\n\n");
    } else if(!strcmp(command, "save")) {
        printf("Usage: xl save [options] <Domain> <CheckpointFile> [<ConfigFile>]\n\n");
        printf("Save a domain state to restore later.\n\n");
        printf("Options:\n\n");
        printf("-h                     Print this help.\n");
        printf("-c                     Leave domain running after creating the snapshot.\n");
    } else if(!strcmp(command, "restore")) {
        printf("Usage: xl restore [options] [<ConfigFile>] <CheckpointFile>\n\n");
        printf("Restore a domain from a saved state.\n\n");
        printf("Options:\n\n");
        printf("-h                     Print this help.\n");
        printf("-p                     Do not unpause domain after restoring it.\n");
        printf("-e                     Do not wait in the background for the death of the domain.\n");
        printf("-d                     Enable debug messages.\n");
    } else if(!strcmp(command, "migrate")) {
        printf("Usage: xl migrate [options] <Domain> <host>\n\n");
        printf("Save a domain state to restore later.\n\n");
        printf("Options:\n\n");
        printf("-h                     Print this help.\n");
        printf("-C <config>            Send <config> instead of config file from creation.\n");
        printf("-s <sshcommand>        Use <sshcommand> instead of ssh.  String will be passed to sh.  If empty, run <host> instead of ssh <host> xl migrate-receive [-d -e]\n");
        printf("-e                     Do not wait in the background (on <host>) for the death of the domain.\n");
    } else if(!strcmp(command, "migrate-receive")) {
        printf("Usage: xl migrate-receive  - for internal use only");
    } else if(!strcmp(command, "restore")) {
        printf("Usage: xl restore [options] [<ConfigFile>] <CheckpointFile>\n\n");
        printf("Restore a domain from a saved state.\n\n");
        printf("Options:\n\n");
        printf("-h                     Print this help.\n");
        printf("-O                     Old (configless) xl save format.\n");
        printf("-p                     Do not unpause domain after restoring it.\n");
        printf("-e                     Do not wait in the background for the death of the domain.\n");
    } else if(!strcmp(command, "destroy")) {
        printf("Usage: xl destroy <Domain>\n\n");
        printf("Terminate a domain immediately.\n\n");
    } else if (!strcmp(command, "console")) {
        printf("Usage: xl console <Domain>\n\n");
        printf("Attach to domain's console.\n\n");
    } else if (!strcmp(command, "cd-insert")) {
        printf("Usage: xl cd-insert <Domain> <VirtualDevice> <type:path>\n\n");
        printf("Insert a cdrom into a guest's cd drive.\n\n");
    } else if (!strcmp(command, "cd-eject")) {
        printf("Usage: xl cd-eject <Domain> <VirtualDevice>\n\n");
        printf("Eject a cdrom from a guest's cd drive.\n\n");
    } else if (!strcmp(command, "mem-set")) {
        printf("Usage: xl mem-set <Domain> <MemKB>\n\n");
        printf("Set the current memory usage for a domain.\n\n");
    } else if (!strcmp(command, "button-press")) {
        printf("Usage: xl button-press <Domain> <Button>\n\n");
        printf("Indicate <Button> press to a domain.\n");
        printf("<Button> may be 'power' or 'sleep'.\n\n");
    } else if (!strcmp(command, "vcpu-list")) {
        printf("Usage: xl vcpu-list [Domain, ...]\n\n");
        printf("List the VCPUs for all/some domains.\n\n");
    } else if (!strcmp(command, "vcpu-pin")) {
        printf("Usage: xl vcpu-pin <Domain> <VCPU|all> <CPUs|all>\n\n");
        printf("Set which CPUs a VCPU can use.\n\n");
    } else if (!strcmp(command, "vcpu-set")) {
        printf("Usage: xl vcpu-set <Domain> <vCPUs>\n\n");
        printf("Set the number of active VCPUs for allowed for the domain.\n\n");
    }
}

void set_memory_target(char *p, char *mem)
{
    char *endptr;
    uint32_t memorykb;

    find_domain(p);

    memorykb = strtoul(mem, &endptr, 10);
    if (*endptr != '\0') {
        fprintf(stderr, "invalid memory size: %s\n", mem);
        exit(3);
    }
    printf("setting domid %d memory to : %d\n", domid, memorykb);
    libxl_set_memory_target(&ctx, domid, memorykb);
}

int main_memset(int argc, char **argv)
{
    int opt = 0;
    char *p = NULL, *mem;

    while ((opt = getopt(argc, argv, "h:")) != -1) {
        switch (opt) {
        case 'h':
            help("mem-set");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }
    if (optind >= argc - 1) {
        help("mem-set");
        exit(2);
    }

    p = argv[optind];
    mem = argv[optind + 1];

    set_memory_target(p, mem);
    exit(0);
}

void console(char *p, int cons_num)
{
    find_domain(p);
    libxl_console_attach(&ctx, domid, cons_num);
}

void cd_insert(char *dom, char *virtdev, char *phys)
{
    libxl_device_disk disk;
    char *p;

    find_domain(dom);

    disk.backend_domid = 0;
    disk.domid = domid;
    if (phys) {
        p = strchr(phys, ':');
        if (!p) {
            fprintf(stderr, "No type specified, ");
            disk.physpath = phys;
            if (!strncmp(phys, "/dev", 4)) {
                fprintf(stderr, "assuming phy:\n");
                disk.phystype = PHYSTYPE_PHY;
            } else {
                fprintf(stderr, "assuming file:\n");
                disk.phystype = PHYSTYPE_FILE;
            }
        } else {
            *p = '\0';
            p++;
            disk.physpath = p;
            libxl_string_to_phystype(&ctx, phys, &disk.phystype);
        }
    } else {
            disk.physpath = NULL;
            disk.phystype = 0;
    }
    disk.virtpath = virtdev;
    disk.unpluggable = 1;
    disk.readwrite = 0;
    disk.is_cdrom = 1;

    libxl_cdrom_insert(&ctx, domid, &disk);
}

int main_cd_eject(int argc, char **argv)
{
    int opt = 0;
    char *p = NULL, *virtdev;

    while ((opt = getopt(argc, argv, "hn:")) != -1) {
        switch (opt) {
        case 'h':
            help("cd-eject");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }
    if (optind >= argc - 1) {
        help("cd-eject");
        exit(2);
    }

    p = argv[optind];
    virtdev = argv[optind + 1];

    cd_insert(p, virtdev, NULL);
    exit(0);
}

int main_cd_insert(int argc, char **argv)
{
    int opt = 0;
    char *p = NULL, *file = NULL, *virtdev;

    while ((opt = getopt(argc, argv, "hn:")) != -1) {
        switch (opt) {
        case 'h':
            help("cd-insert");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }
    if (optind >= argc - 2) {
        help("cd-insert");
        exit(2);
    }

    p = argv[optind];
    virtdev = argv[optind + 1];
    file = argv[optind + 2];

    cd_insert(p, virtdev, file);
    exit(0);
}

int main_console(int argc, char **argv)
{
    int opt = 0, cons_num = 0;
    char *p = NULL;

    while ((opt = getopt(argc, argv, "hn:")) != -1) {
        switch (opt) {
        case 'h':
            help("console");
            exit(0);
        case 'n':
            if (optarg) {
                cons_num = strtol(optarg, NULL, 10);
            }
            break;
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }
    if (optind >= argc) {
        help("console");
        exit(2);
    }

    p = argv[optind];

    console(p, cons_num);
    exit(0);
}

void pcilist(char *dom)
{
    libxl_device_pci *pcidevs;
    int num, i;

    find_domain(dom);

    pcidevs = libxl_device_pci_list(&ctx, domid, &num);
    if (!num)
        return;
    printf("VFn  domain bus  slot func\n");
    for (i = 0; i < num; i++) {
        printf("0x%02x 0x%04x 0x%02x 0x%02x 0x%01x\n", pcidevs[i].vdevfn, pcidevs[i].domain, pcidevs[i].bus, pcidevs[i].dev, pcidevs[i].func);
    }
    free(pcidevs);
}

int main_pcilist(int argc, char **argv)
{
    int opt;
    char *domname = NULL;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("pci-list");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }
    if (optind >= argc) {
        help("pci-list");
        exit(2);
    }

    domname = argv[optind];

    pcilist(domname);
    exit(0);
}

void pcidetach(char *dom, char *bdf)
{
    libxl_device_pci pcidev;
    unsigned int domain, bus, dev, func;

    find_domain(dom);

    memset(&pcidev, 0x00, sizeof(pcidev));
    sscanf(bdf, PCI_BDF, &domain, &bus, &dev, &func);
    libxl_device_pci_init(&pcidev, domain, bus, dev, func, 0);
    libxl_device_pci_remove(&ctx, domid, &pcidev);
}

int main_pcidetach(int argc, char **argv)
{
    int opt;
    char *domname = NULL, *bdf = NULL;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("pci-attach");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }
    if (optind >= argc - 1) {
        help("pci-detach");
        exit(2);
    }

    domname = argv[optind];
    bdf = argv[optind + 1];

    pcidetach(domname, bdf);
    exit(0);
}
void pciattach(char *dom, char *bdf, char *vs)
{
    libxl_device_pci pcidev;
    unsigned int domain, bus, dev, func;

    find_domain(dom);

    memset(&pcidev, 0x00, sizeof(pcidev));
    sscanf(bdf, PCI_BDF, &domain, &bus, &dev, &func);
    libxl_device_pci_init(&pcidev, domain, bus, dev, func, 0);
    libxl_device_pci_add(&ctx, domid, &pcidev);
}

int main_pciattach(int argc, char **argv)
{
    int opt;
    char *domname = NULL, *bdf = NULL, *vs = NULL;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("pci-attach");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }
    if (optind >= argc - 1) {
        help("pci-attach");
        exit(2);
    }

    domname = argv[optind];
    bdf = argv[optind + 1];

    if (optind + 1 < argc)
        vs = argv[optind + 2];

    pciattach(domname, bdf, vs);
    exit(0);
}

void pause_domain(char *p)
{
    find_domain(p);
    libxl_domain_pause(&ctx, domid);
}

void unpause_domain(char *p)
{
    find_domain(p);
    libxl_domain_unpause(&ctx, domid);
}

void destroy_domain(char *p)
{
    int rc;
    find_domain(p);
    rc = libxl_domain_destroy(&ctx, domid, 0);
    if (rc) { fprintf(stderr,"destroy failed (rc=%d)\n.",rc); exit(-1); }
}

void list_domains(int verbose)
{
    struct libxl_dominfo *info;
    int nb_domain, i;

    info = libxl_list_domain(&ctx, &nb_domain);

    if (!info) {
        fprintf(stderr, "libxl_domain_infolist failed.\n");
        exit(1);
    }
    printf("Name                                        ID   Mem VCPUs\tState\tTime(s)\n");
    for (i = 0; i < nb_domain; i++) {
        printf("%-40s %5d %5lu %5d        %c%c%c %8.1f",
                libxl_domid_to_name(&ctx, info[i].domid),
                info[i].domid,
                (unsigned long) (info[i].max_memkb / 1024),
                info[i].vcpu_online,
                info[i].running ? 'r' : '-',
                info[i].paused ? 'p' : '-',
                info[i].dying ? 'd' : '-',
                ((float)info[i].cpu_time / 1e9));
        if (verbose) {
            char *uuid = libxl_uuid2string(&ctx, info[i].uuid);
            printf(" %s", uuid);
        }
        putchar('\n');
    }
    free(info);
}

void list_vm(void)
{
    struct libxl_vminfo *info;
    int nb_vm, i;

    info = libxl_list_vm(&ctx, &nb_vm);

    if (info < 0) {
        fprintf(stderr, "libxl_domain_infolist failed.\n");
        exit(1);
    }
    printf("UUID                                  ID    name\n");
    for (i = 0; i < nb_vm; i++) {
        printf(UUID_FMT "  %d    %-30s\n",
            info[i].uuid[0], info[i].uuid[1], info[i].uuid[2], info[i].uuid[3],
            info[i].uuid[4], info[i].uuid[5], info[i].uuid[6], info[i].uuid[7],
            info[i].uuid[8], info[i].uuid[9], info[i].uuid[10], info[i].uuid[11],
            info[i].uuid[12], info[i].uuid[13], info[i].uuid[14], info[i].uuid[15],
            info[i].domid, libxl_domid_to_name(&ctx, info[i].domid));
    }
    free(info);
}

static void save_domain_core_begin(char *domain_spec,
                                   const char *override_config_file,
                                   uint8_t **config_data_r,
                                   int *config_len_r)
{
    int rc;

    find_domain(domain_spec);

    /* configuration file in optional data: */

    if (override_config_file) {
        void *config_v = 0;
        rc = libxl_read_file_contents(&ctx, override_config_file,
                                      &config_v, config_len_r);
        *config_data_r = config_v;
    } else {
        rc = libxl_userdata_retrieve(&ctx, domid, "xl",
                                     config_data_r, config_len_r);
    }
    if (rc) {
        fputs("Unable to get config file\n",stderr);
        exit(2);
    }
}

void save_domain_core_writeconfig(int fd, const char *filename,
                                  const uint8_t *config_data, int config_len)
{
    struct save_file_header hdr;
    uint8_t *optdata_begin;
    union { uint32_t u32; char b[4]; } u32buf;

    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, savefileheader_magic, sizeof(hdr.magic));
    hdr.byteorder = SAVEFILE_BYTEORDER_VALUE;

    optdata_begin= 0;

#define ADD_OPTDATA(ptr, len) ({                                            \
    if ((len)) {                                                        \
        hdr.optional_data_len += (len);                                 \
        optdata_begin = xrealloc(optdata_begin, hdr.optional_data_len); \
        memcpy(optdata_begin + hdr.optional_data_len - (len),           \
               (ptr), (len));                                           \
    }                                                                   \
                          })

    u32buf.u32 = config_len;
    ADD_OPTDATA(u32buf.b,    4);
    ADD_OPTDATA(config_data, config_len);

    /* that's the optional data */

    CHK_ERRNO( libxl_write_exactly(&ctx, fd,
        &hdr, sizeof(hdr), filename, "header") );
    CHK_ERRNO( libxl_write_exactly(&ctx, fd,
        optdata_begin, hdr.optional_data_len, filename, "header") );

    fprintf(stderr, "Saving to %s new xl format (info"
            " 0x%"PRIx32"/0x%"PRIx32"/%"PRIu32")\n",
            filename, hdr.mandatory_flags, hdr.optional_flags,
            hdr.optional_data_len);
}

int save_domain(char *p, char *filename, int checkpoint,
                const char *override_config_file)
{
    int fd;
    uint8_t *config_data;
    int config_len;

    save_domain_core_begin(p, override_config_file, &config_data, &config_len);

    if (!config_len) {
        fputs(" Savefile will not contain xl domain config\n", stderr);
    }

    fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "Failed to open temp file %s for writing\n", filename);
        exit(2);
    }

    save_domain_core_writeconfig(fd, filename, config_data, config_len);

    libxl_domain_suspend(&ctx, NULL, domid, fd);
    close(fd);

    if (checkpoint)
        libxl_domain_unpause(&ctx, domid);
    else
        libxl_domain_destroy(&ctx, domid, 0);

    exit(0);
}

static int migrate_read_fixedmessage(int fd, const void *msg, int msgsz,
                                     const char *what, const char *rune) {
    char buf[msgsz];
    const char *stream;
    int rc;

    stream = rune ? "migration receiver stream" : "migration stream";
    rc = libxl_read_exactly(&ctx, fd, buf, msgsz, stream, what);
    if (rc) return ERROR_FAIL;

    if (memcmp(buf, msg, msgsz)) {
        fprintf(stderr, "%s contained unexpected data instead of %s\n",
                stream, what);
        if (rune)
            fprintf(stderr, "(command run was: %s )\n", rune);
        return ERROR_FAIL;
    }
    return 0;
}

static void migration_child_report(pid_t migration_child, int recv_fd) {
    pid_t child;
    int status, sr;
    struct timeval now, waituntil, timeout;
    static const struct timeval pollinterval = { 0, 1000 }; /* 1ms */

    if (!migration_child) return;

    CHK_ERRNO( gettimeofday(&waituntil, 0) );
    waituntil.tv_sec += 2;

    for (;;) {
        child = waitpid(migration_child, &status, WNOHANG);

        if (child == migration_child) {
            if (status)
                libxl_report_child_exitstatus(&ctx, XL_LOG_INFO,
                                              "migration target process",
                                              migration_child, status);
            break;
        }
        if (child == -1) {
            if (errno == EINTR) continue;
            fprintf(stderr, "wait for migration child [%ld] failed: %s\n",
                    (long)migration_child, strerror(errno));
            break;
        }
        assert(child == 0);

        CHK_ERRNO( gettimeofday(&now, 0) );
        if (timercmp(&now, &waituntil, >)) {
            fprintf(stderr, "migration child [%ld] not exiting, no longer"
                    " waiting (exit status will be unreported)\n",
                    (long)migration_child);
            break;
        }
        timersub(&waituntil, &now, &timeout);

        if (recv_fd >= 0) {
            fd_set readfds, exceptfds;
            FD_ZERO(&readfds);
            FD_ZERO(&exceptfds);
            FD_SET(recv_fd, &readfds);
            FD_SET(recv_fd, &exceptfds);
            sr = select(recv_fd+1, &readfds,0,&exceptfds, &timeout);
        } else {
            if (timercmp(&timeout, &pollinterval, >))
                timeout = pollinterval;
            sr = select(0,0,0,0, &timeout);
        }
        if (sr > 0) {
            recv_fd = -1;
        } else if (sr == 0) {
        } else if (sr == -1) {
            if (errno != EINTR) {
                fprintf(stderr, "migration child [%ld] exit wait select"
                        " failed unexpectedly: %s\n",
                        (long)migration_child, strerror(errno));
                break;
            }
        }
    }
    migration_child = 0;
}

static void migrate_domain(char *domain_spec, const char *rune,
                           const char *override_config_file)
{
    pid_t child = -1;
    int rc;
    int sendpipe[2], recvpipe[2];
    int send_fd, recv_fd;
    libxl_domain_suspend_info suspinfo;
    char *away_domname;
    char rc_buf;
    uint8_t *config_data;
    int config_len;

    save_domain_core_begin(domain_spec, override_config_file,
                           &config_data, &config_len);

    if (!common_domname) {
        common_domname = libxl_domid_to_name(&ctx, domid);
        /* libxl_domid_to_name fails ?  don't bother with names then */
    }

    if (!config_len) {
        fprintf(stderr, "No config file stored for running domain and "
                "none supplied - cannot migrate.\n");
        exit(1);
    }

    MUST( libxl_pipe(&ctx, sendpipe) );
    MUST( libxl_pipe(&ctx, recvpipe) );

    child = libxl_fork(&ctx);
    if (child==-1) exit(1);

    if (!child) {
        dup2(sendpipe[0], 0);
        dup2(recvpipe[1], 1);
        close(sendpipe[0]); close(sendpipe[1]);
        close(recvpipe[0]); close(recvpipe[1]);
        execlp("sh","sh","-c",rune,(char*)0);
        perror("failed to exec sh");
        exit(-1);
    }

    close(sendpipe[0]);
    close(recvpipe[1]);
    send_fd = sendpipe[1];
    recv_fd = recvpipe[0];

    signal(SIGPIPE, SIG_IGN);
    /* if receiver dies, we get an error and can clean up
       rather than just dying */

    rc = migrate_read_fixedmessage(recv_fd, migrate_receiver_banner,
                                   sizeof(migrate_receiver_banner)-1,
                                   "banner", rune);
    if (rc) {
        close(send_fd);
        migration_child_report(child, recv_fd);
        exit(-rc);
    }

    save_domain_core_writeconfig(send_fd, "migration stream",
                                 config_data, config_len);

    memset(&suspinfo, 0, sizeof(suspinfo));
    suspinfo.flags |= XL_SUSPEND_LIVE;
    rc = libxl_domain_suspend(&ctx, &suspinfo, domid, send_fd);
    if (rc) {
        fprintf(stderr, "migration sender: libxl_domain_suspend failed"
                " (rc=%d)\n", rc);
        goto failed_resume;
    }

    fprintf(stderr, "migration sender: Transfer complete.\n");

    rc = migrate_read_fixedmessage(recv_fd, migrate_receiver_ready,
                                   sizeof(migrate_receiver_ready),
                                   "ready message", rune);
    if (rc) goto failed_resume;

    /* right, at this point we are about give the destination
     * permission to rename and resume, so we must first rename the
     * domain away ourselves */

    fprintf(stderr, "migration sender: Target has acknowledged transfer.\n");

    if (common_domname) {
        asprintf(&away_domname, "%s--migratedaway", common_domname);
        rc = libxl_domain_rename(&ctx, domid,
                                 common_domname, away_domname, 0);
        if (rc) goto failed_resume;
    }

    /* point of no return - as soon as we have tried to say
     * "go" to the receiver, it's not safe to carry on.  We leave
     * the domain renamed to %s--migratedaway in case that's helpful.
     */

    fprintf(stderr, "migration sender: Giving target permission to start.\n");

    rc = libxl_write_exactly(&ctx, send_fd,
                             migrate_permission_to_go,
                             sizeof(migrate_permission_to_go),
                             "migration stream", "GO message");
    if (rc) goto failed_badly;

    rc = migrate_read_fixedmessage(recv_fd, migrate_report,
                                   sizeof(migrate_report),
                                   "success/failure report message", rune);
    if (rc) goto failed_badly;

    rc = libxl_read_exactly(&ctx, recv_fd,
                            &rc_buf, 1,
                            "migration ack stream", "success/failure status");
    if (rc) goto failed_badly;

    if (rc_buf) {
        fprintf(stderr, "migration sender: Target reports startup failure"
                " (status code %d).\n", rc_buf);

        rc = migrate_read_fixedmessage(recv_fd, migrate_permission_to_go,
                                       sizeof(migrate_permission_to_go),
                                       "permission for sender to resume",
                                       rune);
        if (rc) goto failed_badly;

        fprintf(stderr, "migration sender: Trying to resume at our end.\n");

        if (common_domname) {
            libxl_domain_rename(&ctx, domid,
                                away_domname, common_domname, 0);
        }
        rc = libxl_domain_resume(&ctx, domid);
        if (!rc) fprintf(stderr, "migration sender: Resumed OK.\n");

        fprintf(stderr, "Migration failed due to problems at target.\n");
        exit(-ERROR_FAIL);
    }

    fprintf(stderr, "migration sender: Target reports successful startup.\n");
    libxl_domain_destroy(&ctx, domid, 1); /* bang! */
    fprintf(stderr, "Migration successful.\n");
    exit(0);

 failed_resume:
    close(send_fd);
    migration_child_report(child, recv_fd);
    fprintf(stderr, "Migration failed, resuming at sender.\n");
    libxl_domain_resume(&ctx, domid);
    exit(-ERROR_FAIL);

 failed_badly:
    fprintf(stderr,
 "** Migration failed during final handshake **\n"
 "Domain state is now undefined !\n"
 "Please CHECK AT BOTH ENDS for running instances, before renaming and\n"
 " resuming at most one instance.  Two simultaneous instances of the domain\n"
 " would probably result in SEVERE DATA LOSS and it is now your\n"
 " responsibility to avoid that.  Sorry.\n");

    close(send_fd);
    migration_child_report(child, recv_fd);
    exit(-ERROR_BADFAIL);
}

static void migrate_receive(int debug, int daemonize)
{
    int rc, rc2;
    char rc_buf;
    char *migration_domname;

    signal(SIGPIPE, SIG_IGN);
    /* if we get SIGPIPE we'd rather just have it as an error */

    fprintf(stderr, "migration target: Ready to receive domain.\n");

    CHK_ERRNO( libxl_write_exactly(&ctx, 1,
                                   migrate_receiver_banner,
                                   sizeof(migrate_receiver_banner)-1,
                                   "migration ack stream",
                                   "banner") );

    rc = create_domain(debug, daemonize,
                       0 /* no config file, use incoming */,
                       "incoming migration stream", 1,
                       0, &migration_domname);
    if (rc) {
        fprintf(stderr, "migration target: Domain creation failed"
                " (code %d).\n", rc);
        exit(-rc);
    }

    fprintf(stderr, "migration target: Transfer complete,"
            " requesting permission to start domain.\n");

    rc = libxl_write_exactly(&ctx, 1,
                             migrate_receiver_ready,
                             sizeof(migrate_receiver_ready),
                             "migration ack stream", "ready message");
    if (rc) exit(-rc);

    rc = migrate_read_fixedmessage(0, migrate_permission_to_go,
                                   sizeof(migrate_permission_to_go),
                                   "GO message", 0);
    if (rc) goto perhaps_destroy_notify_rc;

    fprintf(stderr, "migration target: Got permission, starting domain.\n");

    if (migration_domname) {
        rc = libxl_domain_rename(&ctx, domid,
                                 migration_domname, common_domname, 0);
        if (rc) goto perhaps_destroy_notify_rc;
    }

    rc = libxl_domain_unpause(&ctx, domid);
    if (rc) goto perhaps_destroy_notify_rc;

    fprintf(stderr, "migration target: Domain started successsfully.\n");
    rc = 0;

 perhaps_destroy_notify_rc:
    rc2 = libxl_write_exactly(&ctx, 1,
                              migrate_report, sizeof(migrate_report),
                              "migration ack stream",
                              "success/failure report");
    if (rc2) exit(-ERROR_BADFAIL);

    rc_buf = -rc;
    assert(!!rc_buf == !!rc);
    rc2 = libxl_write_exactly(&ctx, 1, &rc_buf, 1,
                              "migration ack stream",
                              "success/failure code");
    if (rc2) exit(-ERROR_BADFAIL);

    if (rc) {
        fprintf(stderr, "migration target: Failure, destroying our copy.\n");

        rc2 = libxl_domain_destroy(&ctx, domid, 1);
        if (rc2) {
            fprintf(stderr, "migration target: Failed to destroy our copy"
                    " (code %d).\n", rc2);
            exit(-ERROR_BADFAIL);
        }

        fprintf(stderr, "migration target: Cleanup OK, granting sender"
                " permission to resume.\n");

        rc2 = libxl_write_exactly(&ctx, 1,
                                  migrate_permission_to_go,
                                  sizeof(migrate_permission_to_go),
                                  "migration ack stream",
                                  "permission to sender to have domain back");
        if (rc2) exit(-ERROR_BADFAIL);
    }

    exit(0);
}

int main_restore(int argc, char **argv)
{
    char *checkpoint_file = NULL;
    char *config_file = NULL;
    int paused = 0, debug = 0, daemonize = 1;
    int opt, rc;

    while ((opt = getopt(argc, argv, "hpde")) != -1) {
        switch (opt) {
        case 'p':
            paused = 1;
            break;
        case 'd':
            debug = 1;
            break;
        case 'e':
            daemonize = 0;
            break;
        case 'h':
            help("restore");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }

    if (argc-optind == 1) {
        checkpoint_file = argv[optind];
    } else if (argc-optind == 2) {
        config_file = argv[optind];
        checkpoint_file = argv[optind + 1];
    } else {
        help("restore");
        exit(2);
    }
    rc = create_domain(debug, daemonize, config_file,
                       checkpoint_file, paused, -1, 0);
    exit(-rc);
}

int main_migrate_receive(int argc, char **argv)
{
    int debug = 0, daemonize = 1;
    int opt;

    while ((opt = getopt(argc, argv, "hed")) != -1) {
        switch (opt) {
        case 'h':
            help("restore");
            exit(2);
            break;
        case 'e':
            daemonize = 0;
            break;
        case 'd':
            debug = 1;
            break;
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }

    if (argc-optind != 0) {
        help("restore");
        exit(2);
    }
    migrate_receive(debug, daemonize);
    exit(0);
}

int main_save(int argc, char **argv)
{
    char *filename = NULL, *p = NULL;
    const char *config_filename;
    int checkpoint = 0;
    int opt;

    while ((opt = getopt(argc, argv, "hc")) != -1) {
        switch (opt) {
        case 'c':
            checkpoint = 1;
            break;
        case 'h':
            help("save");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }

    if (argc-optind < 1 || argc-optind > 3) {
        help("save");
        exit(2);
    }

    p = argv[optind];
    filename = argv[optind + 1];
    config_filename = argv[optind + 2];
    save_domain(p, filename, checkpoint, config_filename);
    exit(0);
}

int main_migrate(int argc, char **argv)
{
    char *p = NULL;
    const char *config_filename = NULL;
    const char *ssh_command = "ssh";
    char *rune = NULL;
    char *host;
    int opt, daemonize = 1, debug = 0;

    while ((opt = getopt(argc, argv, "hC:s:ed")) != -1) {
        switch (opt) {
        case 'h':
            help("migrate");
            exit(0);
        case 'C':
            config_filename = optarg;
            break;
        case 's':
            ssh_command = optarg;
            break;
        case 'e':
            daemonize = 0;
            break;
        case 'd':
            debug = 1;
            break;
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }

    if (argc-optind < 2 || argc-optind > 2) {
        help("save");
        exit(2);
    }

    p = argv[optind];
    host = argv[optind + 1];

    if (!ssh_command[0]) {
        rune= host;
    } else {
        asprintf(&rune, "exec %s %s xl migrate-receive%s%s",
                 ssh_command, host,
                 daemonize ? "" : " -e",
                 debug ? " -d" : "");
    }

    migrate_domain(p, rune, config_filename);
    exit(0);
}

int main_pause(int argc, char **argv)
{
    int opt;
    char *p;
    

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("pause");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }
    if (optind >= argc) {
        help("pause");
        exit(2);
    }

    p = argv[optind];

    pause_domain(p);
    exit(0);
}

int main_unpause(int argc, char **argv)
{
    int opt;
    char *p;
    

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("unpause");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }
    if (optind >= argc) {
        help("unpause");
        exit(2);
    }

    p = argv[optind];

    unpause_domain(p);
    exit(0);
}

int main_destroy(int argc, char **argv)
{
    int opt;
    char *p;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("destroy");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }
    if (optind >= argc) {
        help("destroy");
        exit(2);
    }

    p = argv[optind];

    destroy_domain(p);
    exit(0);
}

int main_list(int argc, char **argv)
{
    int opt, verbose = 0;

    while ((opt = getopt(argc, argv, "hv")) != -1) {
        switch (opt) {
        case 'h':
            help("list");
            exit(0);
        case 'v':
            verbose = 1;
            break;
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }

    list_domains(verbose);
    exit(0);
}

int main_list_vm(int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("list-vm");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }

    list_vm();
    exit(0);
}

int main_create(int argc, char **argv)
{
    char *filename = NULL;
    int paused = 0, debug = 0, daemonize = 1;
    int opt, rc;

    while ((opt = getopt(argc, argv, "hdep")) != -1) {
        switch (opt) {
        case 'p':
            paused = 1;
            break;
        case 'd':
            debug = 1;
            break;
        case 'e':
            daemonize = 0;
            break;
        case 'h':
            help("create");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }

    if (optind >= argc) {
        help("create");
        exit(2);
    }

    filename = argv[optind];
    rc = create_domain(debug, daemonize, filename, NULL, paused,
                       -1, 0);
    exit(-rc);
}

void button_press(char *p, char *b)
{
    libxl_button button;

    find_domain(p);

    if (!strcmp(b, "power")) {
        button = POWER_BUTTON;
    } else if (!strcmp(b, "sleep")) {
        button = SLEEP_BUTTON;
    } else {
        fprintf(stderr, "%s is an invalid button identifier\n", b);
        exit(2);
    }

    libxl_button_press(&ctx, domid, button);
}

int main_button_press(int argc, char **argv)
{
    int opt;
    char *p;
    char *b;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("button-press");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }
    if (optind >= argc - 1) {
        help("button-press");
        exit(2);
    }

    p = argv[optind];
    b = argv[optind + 1];

    button_press(p, b);
    exit(0);
}

static void print_vcpuinfo(uint32_t tdomid,
                           const struct libxl_vcpuinfo *vcpuinfo,
                           uint32_t nr_cpus)
{
    int i, l;
    uint64_t *cpumap;
    uint64_t pcpumap;

    /*      NAME  ID  VCPU */
    printf("%-32s %5u %5u",
           libxl_domid_to_name(&ctx, tdomid), tdomid, vcpuinfo->vcpuid);
    if (!vcpuinfo->online) {
        /*      CPU STA */
        printf("%5c %3c%cp ", '-', '-', '-');
    } else {
        /*      CPU STA */
        printf("%5u %3c%c- ", vcpuinfo->cpu,
               vcpuinfo->running ? 'r' : '-',
               vcpuinfo->blocked ? 'b' : '-');
    }
    /*      TIM */
    printf("%9.1f  ", ((float)vcpuinfo->vcpu_time / 1e9));
    /* CPU AFFINITY */
    pcpumap = nr_cpus > 64 ? -1 : ((1 << nr_cpus) - 1);
    for (cpumap = vcpuinfo->cpumap; nr_cpus; ++cpumap) {
        if (*cpumap < pcpumap) {
            break;
        }
        if (nr_cpus > 64) {
            pcpumap = -1;
            nr_cpus -= 64;
        } else {
            pcpumap = ((1 << nr_cpus) - 1);
            nr_cpus = 0;
        }
    }
    if (!nr_cpus) {
        printf("any cpu\n");
    } else {
        for (cpumap = vcpuinfo->cpumap; nr_cpus; ++cpumap) {
            pcpumap = *cpumap;
            for (i = 0; !(pcpumap & 1); ++i, pcpumap >>= 1)
                ;
            printf("%u", i);
            for (l = i, pcpumap = (pcpumap >> 1); (pcpumap & 1); ++i, pcpumap >>= 1)
                ;
            if (l < i) {
                printf("-%u", i);
            }
            for (++i; pcpumap; ++i, pcpumap >>= 1) {
                if (pcpumap & 1) {
                    printf(",%u", i);
                    for (l = i, pcpumap = (pcpumap >> 1); (pcpumap & 1); ++i, pcpumap >>= 1)
                        ;
                    if (l < i) {
                        printf("-%u", i);
                    }
                    ++i;
                }
            }
            printf("\n");
            nr_cpus = nr_cpus > 64 ? nr_cpus - 64 : 0;
        }
    }
}

void vcpulist(int argc, char **argv)
{
    struct libxl_dominfo *dominfo;
    struct libxl_vcpuinfo *vcpuinfo;
    struct libxl_physinfo physinfo;
    int nb_vcpu, nb_domain, cpusize;

    if (libxl_get_physinfo(&ctx, &physinfo) != 0) {
        fprintf(stderr, "libxl_physinfo failed.\n");
        goto vcpulist_out;
    }
    printf("%-32s %5s %5s %5s %5s %9s %s\n",
           "Name", "ID", "VCPU", "CPU", "State", "Time(s)", "CPU Affinity");
    if (!argc) {
        if (!(dominfo = libxl_list_domain(&ctx, &nb_domain))) {
            fprintf(stderr, "libxl_list_domain failed.\n");
            goto vcpulist_out;
        }
        for (; nb_domain > 0; --nb_domain, ++dominfo) {
            if (!(vcpuinfo = libxl_list_vcpu(&ctx, dominfo->domid, &nb_vcpu, &cpusize))) {
                fprintf(stderr, "libxl_list_vcpu failed.\n");
                goto vcpulist_out;
            }
            for (; nb_vcpu > 0; --nb_vcpu, ++vcpuinfo) {
                print_vcpuinfo(dominfo->domid, vcpuinfo, physinfo.nr_cpus);
            }
        }
    } else {
        for (; argc > 0; ++argv, --argc) {
            if (domain_qualifier_to_domid(*argv, &domid, 0) < 0) {
                fprintf(stderr, "%s is an invalid domain identifier\n", *argv);
            }
            if (!(vcpuinfo = libxl_list_vcpu(&ctx, domid, &nb_vcpu, &cpusize))) {
                fprintf(stderr, "libxl_list_vcpu failed.\n");
                goto vcpulist_out;
            }
            for (; nb_vcpu > 0; --nb_vcpu, ++vcpuinfo) {
                print_vcpuinfo(domid, vcpuinfo, physinfo.nr_cpus);
            }
        }
    }
  vcpulist_out:
    ;
}

void main_vcpulist(int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("vcpu-list");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    vcpulist(argc - 1, argv + 1);
    exit(0);
}

void vcpupin(char *d, const char *vcpu, char *cpu)
{
    struct libxl_vcpuinfo *vcpuinfo;
    struct libxl_physinfo physinfo;
    uint64_t *cpumap = NULL;

    uint32_t vcpuid, cpuida, cpuidb;
    char *endptr, *toka, *tokb;
    int i, nb_vcpu, cpusize;

    vcpuid = strtoul(vcpu, &endptr, 10);
    if (vcpu == endptr) {
        if (strcmp(vcpu, "all")) {
            fprintf(stderr, "Error: Invalid argument.\n");
            return;
        }
        vcpuid = -1;
    }

    find_domain(d);

    if (libxl_get_physinfo(&ctx, &physinfo) != 0) {
        fprintf(stderr, "libxl_get_physinfo failed.\n");
        goto vcpupin_out1;
    }

    cpumap = calloc(physinfo.max_cpu_id + 1, sizeof (uint64_t));
    if (!cpumap) {
        goto vcpupin_out1;
    }
    if (strcmp(cpu, "all")) {
        for (toka = strtok(cpu, ","), i = 0; toka; toka = strtok(NULL, ","), ++i) {
            cpuida = strtoul(toka, &endptr, 10);
            if (toka == endptr) {
                fprintf(stderr, "Error: Invalid argument.\n");
                goto vcpupin_out;
            }
            if (*endptr == '-') {
                tokb = endptr + 1;
                cpuidb = strtoul(tokb, &endptr, 10);
                if ((tokb == endptr) || (cpuida > cpuidb)) {
                    fprintf(stderr, "Error: Invalid argument.\n");
                    goto vcpupin_out;
                }
                while (cpuida <= cpuidb) {
                    cpumap[cpuida / 64] |= (1 << (cpuida % 64));
                    ++cpuida;
                }
            } else {
                cpumap[cpuida / 64] |= (1 << (cpuida % 64));
            }
        }
    }
    else {
        memset(cpumap, -1, sizeof (uint64_t) * (physinfo.max_cpu_id + 1));
    }

    if (vcpuid != -1) {
        if (libxl_set_vcpuaffinity(&ctx, domid, vcpuid,
                                   cpumap, physinfo.max_cpu_id + 1) == -1) {
            fprintf(stderr, "Could not set affinity for vcpu `%u'.\n", vcpuid);
        }
    }
    else {
        if (!(vcpuinfo = libxl_list_vcpu(&ctx, domid, &nb_vcpu, &cpusize))) {
            fprintf(stderr, "libxl_list_vcpu failed.\n");
            goto vcpupin_out;
        }
        for (; nb_vcpu > 0; --nb_vcpu, ++vcpuinfo) {
            if (libxl_set_vcpuaffinity(&ctx, domid, vcpuinfo->vcpuid,
                                       cpumap, physinfo.max_cpu_id + 1) == -1) {
                fprintf(stderr, "libxl_list_vcpu failed on vcpu `%u'.\n", vcpuinfo->vcpuid);
            }
        }
    }
  vcpupin_out1:
    free(cpumap);
  vcpupin_out:
    ;
}

int main_vcpupin(int argc, char **argv)
{
    int opt;

    if (argc != 4) {
        help("vcpu-pin");
        exit(0);
    }
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("vcpu-pin");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    vcpupin(argv[1], argv[2] , argv[3]);
    exit(0);
}

void vcpuset(char *d, char* nr_vcpus)
{
    char *endptr;
    unsigned int max_vcpus;

    max_vcpus = strtoul(nr_vcpus, &endptr, 10);
    if (nr_vcpus == endptr) {
        fprintf(stderr, "Error: Invalid argument.\n");
        return;
    }

    find_domain(d);

    if (libxl_set_vcpucount(&ctx, domid, max_vcpus) == ERROR_INVAL) {
        fprintf(stderr, "Error: Cannot set vcpus greater than max vcpus on running domain or lesser than 1.\n");
    }
}

int main_vcpuset(int argc, char **argv)
{
    int opt;

    if (argc != 3) {
        help("vcpu-set");
        exit(0);
    }
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
        help("vcpu-set");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    vcpuset(argv[1], argv[2]);
    exit(0);
}

static void output_xeninfo(void)
{
    const libxl_version_info *info;
    int sched_id;

    info = libxl_get_version_info(&ctx);
    if ((sched_id = libxl_get_sched_id(&ctx)) < 0) {
        fprintf(stderr, "get_sched_id sysctl failed.\n");
        return;
    }

    printf("xen_major              : %d\n", info->xen_version_major);
    printf("xen_minor              : %d\n", info->xen_version_minor);
    printf("xen_extra              : %s\n", info->xen_version_extra);
    printf("xen_caps               : %s\n", info->capabilities);
    printf("xen_scheduler          : %s\n",
        sched_id == XEN_SCHEDULER_SEDF ? "sedf" :
        sched_id == XEN_SCHEDULER_CREDIT ? "credit" :
        sched_id == XEN_SCHEDULER_CREDIT2 ? "credit2" : "unknown");
    printf("xen_pagesize           : %lu\n", info->pagesize);
    printf("platform_params        : virt_start=0x%lx\n", info->virt_start);
    printf("xen_changeset          : %s\n", info->changeset);
    printf("xen_commandline        : %s\n", info->commandline);
    printf("cc_compiler            : %s\n", info->compiler);
    printf("cc_compile_by          : %s\n", info->compile_by);
    printf("cc_compile_domain      : %s\n", info->compile_domain);
    printf("cc_compile_date        : %s\n", info->compile_date);

    return;
}

static void output_nodeinfo(void)
{
    struct utsname utsbuf;

    uname(&utsbuf);

    printf("host                   : %s\n", utsbuf.nodename);
    printf("release                : %s\n", utsbuf.release);
    printf("version                : %s\n", utsbuf.version);
    printf("machine                : %s\n", utsbuf.machine);

    return;
}

static void output_physinfo(void)
{
    struct libxl_physinfo info;
    const libxl_version_info *vinfo;
    unsigned int i;

    if (libxl_get_physinfo(&ctx, &info) != 0) {
        fprintf(stderr, "libxl_physinfo failed.\n");
        return;
    }

    printf("nr_cpus                : %d\n", info.nr_cpus);
    printf("nr_nodes               : %d\n", info.nr_nodes);
    printf("cores_per_socket       : %d\n", info.cores_per_socket);
    printf("threads_per_core       : %d\n", info.threads_per_core);
    printf("cpu_mhz                : %d\n", info.cpu_khz / 1000);
    printf("hw_caps                : ");
    for (i = 0; i < 8; i++)
        printf("%08x%c", info.hw_cap[i], i < 7 ? ':' : '\n');
    printf("virt_caps              :");
    if (info.phys_cap & XEN_SYSCTL_PHYSCAP_hvm)
        printf(" hvm");
    if (info.phys_cap & XEN_SYSCTL_PHYSCAP_hvm_directio)
        printf(" hvm_directio");
    printf("\n");
    vinfo = libxl_get_version_info(&ctx);
    i = (1 << 20) / vinfo->pagesize;
    printf("total_memory           : %lu\n", info.total_pages / i);
    printf("free_memory            : %lu\n", info.free_pages / i);

    return;
}

void info(int verbose)
{
    output_nodeinfo();

    output_physinfo();

    output_xeninfo();

    printf("xend_config_format     : 4\n");

    return;
}

void main_info(int argc, char **argv)
{
    int opt, verbose;

    verbose = 0;
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("vcpu-list");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    info(verbose);
    exit(0);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        help(NULL);
        exit(1);
    }

    if (libxl_ctx_init(&ctx, LIBXL_VERSION)) {
        fprintf(stderr, "cannot init xl context\n");
        exit(1);
    }
    if (libxl_ctx_set_log(&ctx, log_callback, NULL)) {
        fprintf(stderr, "cannot set xl log callback\n");
        exit(-ERROR_FAIL);
    }

    srand(time(0));

    if (!strcmp(argv[1], "create")) {
        main_create(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "list")) {
        main_list(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "list-vm")) {
        main_list_vm(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "destroy")) {
        main_destroy(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "pci-attach")) {
        main_pciattach(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "pci-detach")) {
        main_pcidetach(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "pci-list")) {
        main_pcilist(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "pause")) {
        main_pause(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "unpause")) {
        main_unpause(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "console")) {
        main_console(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "save")) {
        main_save(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "migrate")) {
        main_migrate(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "restore")) {
        main_restore(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "migrate-receive")) {
        main_migrate_receive(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "cd-insert")) {
        main_cd_insert(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "cd-eject")) {
        main_cd_eject(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "mem-set")) {
        main_memset(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "button-press")) {
        main_button_press(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "vcpu-list")) {
        main_vcpulist(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "vcpu-pin")) {
        main_vcpupin(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "vcpu-set")) {
        main_vcpuset(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "info")) {
        main_info(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "help")) {
        if (argc > 2)
            help(argv[2]);
        else
            help(NULL);
        exit(0);
    } else {
        fprintf(stderr, "command not implemented\n");
        exit(1);
    }
}
