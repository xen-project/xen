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
#include "xl_cmdtable.h"

#define UUID_FMT "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"

int logfile = 2;

/* every libxl action in xl uses this same libxl context */
struct libxl_ctx ctx;

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

static int qualifier_to_id(const char *p, uint32_t *id_r)
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
        *id_r = strtoul(p, NULL, 10);
        return 0;
    } else {
        /* check here if it's a uuid and do proper conversion */
    }
    return 1;
}

static int domain_qualifier_to_domid(const char *p, uint32_t *domid_r,
                                     int *was_name_r)
{
    int was_name;

    was_name = qualifier_to_id(p, domid_r);
    if (was_name_r) *was_name_r = was_name;
    return was_name ? libxl_name_to_domid(&ctx, p, domid_r) : 0;
}

static int pool_qualifier_to_poolid(const char *p, uint32_t *poolid_r,
                                     int *was_name_r)
{
    int was_name;

    was_name = qualifier_to_id(p, poolid_r);
    if (was_name_r) *was_name_r = was_name;
    return was_name ? libxl_name_to_poolid(&ctx, p, poolid_r) : 0;
}

static void find_domain(const char *p)
{
    int rc, was_name;

    rc = domain_qualifier_to_domid(p, &domid, &was_name);
    if (rc) {
        fprintf(stderr, "%s is an invalid domain identifier (rc=%d)\n", p, rc);
        exit(2);
    }
    common_domname = was_name ? p : libxl_domid_to_name(&ctx, domid);
    if (!common_domname) {
        fprintf(stderr, "%s is an invalid domain identifier.\n", p);
        exit(2);
    }
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
        libxl_write_exactly(NULL, logfile, s, rc, NULL, NULL);
}

static void init_create_info(libxl_domain_create_info *c_info)
{
    memset(c_info, '\0', sizeof(*c_info));
    c_info->xsdata = NULL;
    c_info->platformdata = NULL;
    c_info->hvm = 1;
    c_info->oos = 1;
    c_info->ssidref = 0;
    c_info->poolid = 0;
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
        b_info->kernel = "hvmloader";
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
    dm_info->device_model = "qemu-dm";
    dm_info->videoram = b_info->video_memkb / 1024;
    dm_info->apic = b_info->u.hvm.apic;

    dm_info->stdvga = 0;
    dm_info->vnc = 1;
    dm_info->vnclisten = "127.0.0.1";
    dm_info->vncdisplay = 0;
    dm_info->vncunused = 1;
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
    printf("cpupool: %s (%d)\n", c_info->poolname, c_info->poolid);
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

    if (!xlu_cfg_get_string (config, "pool", &buf)) {
        c_info->poolid = -1;
        pool_qualifier_to_poolid(buf, &c_info->poolid, NULL);
    }
    c_info->poolname = libxl_poolid_to_name(&ctx, c_info->poolid);
    if (!c_info->poolname) {
        fprintf(stderr, "Illegal pool specified\n");
        exit(1);
    }

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
            if (asprintf(&cmdline, "root=%s", buf) < 0) {
                fprintf(stderr, "Failed to allocate memory in asprintf\n");
                exit(1);
            }
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
                } else if (!strcmp(p, "vncpasswd")) {
                    (*vfbs)[*num_vfbs].vncpasswd = strdup(p2 + 1);
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
        if (!xlu_cfg_get_string (config, "vncpasswd", &buf))
            dm_info->vncpasswd = strdup(buf);
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

struct domain_create {
    int debug;
    int daemonize;
    int paused;
    const char *config_file;
    const char *extra_config; /* extra config string */
    const char *restore_file;
    int migrate_fd; /* -1 means none */
    char **migration_domname_r;
};

static int create_domain(struct domain_create *dom_info)
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

    int debug = dom_info->debug;
    int daemonize = dom_info->daemonize;
    int paused = dom_info->paused;
    const char *config_file = dom_info->config_file;
    const char *extra_config = dom_info->extra_config;
    const char *restore_file = dom_info->restore_file;
    int migrate_fd = dom_info->migrate_fd;
    char **migration_domname_r = dom_info->migration_domname_r;

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
        if (!restore_file && extra_config
            && strlen(extra_config)) {
            if (config_len > INT_MAX - (strlen(extra_config) + 2)) {
                fprintf(stderr, "Failed to attach extra configration\n");
                return ERROR_FAIL;
            }
            config_data = realloc(config_data, config_len
                + strlen(extra_config) + 2);
            if (!config_data) {
                fprintf(stderr, "Failed to realloc config_data\n");
                return ERROR_FAIL;
            }
            strcat(config_data, "\n");
            strcat(config_data, extra_config);
            strcat(config_data, "\n");
            config_len += (strlen(extra_config) + 2);
        }
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
            if (asprintf(migration_domname_r, "%s--incoming", info1.name) < 0) {
                fprintf(stderr, "Failed to allocate memory in asprintf\n");
                exit(1);
            }
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
        ret = ERROR_FAIL;
        goto error_out;
    }

    ret = libxl_userdata_store(&ctx, domid, "xl",
                                    config_data, config_len);
    if (ret) {
        perror("cannot save config file");
        ret = ERROR_FAIL;
        goto error_out;
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
        ret = ERROR_FAIL;
        goto error_out;
    }

    for (i = 0; i < num_disks; i++) {
        disks[i].domid = domid;
        ret = libxl_device_disk_add(&ctx, domid, &disks[i]);
        if (ret) {
            fprintf(stderr, "cannot add disk %d to domain: %d\n", i, ret);
            ret = ERROR_FAIL;
            goto error_out;
        }
    }
    for (i = 0; i < num_vifs; i++) {
        vifs[i].domid = domid;
        ret = libxl_device_nic_add(&ctx, domid, &vifs[i]);
        if (ret) {
            fprintf(stderr, "cannot add nic %d to domain: %d\n", i, ret);
            ret = ERROR_FAIL;
            goto error_out;
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
        return domid; /* caller gets success in parent */

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
                    ret = ERROR_FAIL;
                    goto error_out;
                }
            }
            if (status) {
                libxl_report_child_exitstatus(&ctx, XL_LOG_ERROR,
                           "daemonizing child", child1, status);
                ret = ERROR_FAIL;
                goto error_out;
            }
            return domid; /* caller gets success in parent */
        }

        rc = libxl_ctx_postfork(&ctx);
        if (rc) {
            LOG("failed to reinitialise context after fork");
            exit(-1);
        }

        if (asprintf(&name, "xl-%s", info1.name) < 0) {
            LOG("Failed to allocate memory in asprintf");
            exit(1);
        }
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

        CHK_ERRNO(daemon(0, 1) < 0);
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

error_out:
    if (domid)
        libxl_domain_destroy(&ctx, domid, 0);
    return ret;
}

void help(char *command)
{
    int i;

    if (!command || !strcmp(command, "help")) {
        printf("Usage xl <subcommand> [args]\n\n");
        printf("xl full list of subcommands:\n\n");
        for (i = 0; i < cmdtable_len; i++)
            printf(" %-20s%s\n",
                   cmd_table[i].cmd_name, cmd_table[i].cmd_desc);
    } else {
        for (i = 0; i < cmdtable_len; i++)
            if (!strcmp(command, cmd_table[i].cmd_name))
                break;
        if (i == cmdtable_len) {
            printf("command not implemented\n");
        } else {
            printf("Usage: xl %s %s\n\n%s.\n\n",
                   cmd_table[i].cmd_name,
                   cmd_table[i].cmd_usage,
                   cmd_table[i].cmd_desc);
            if (cmd_table[i].cmd_option)
            printf("Options:\n\n%s\n", cmd_table[i].cmd_option);
        }
    }
}

static int64_t parse_mem_size_kb(char *mem)
{
    char *endptr;
    int64_t kbytes;

    kbytes = strtoll(mem, &endptr, 10);

    if (strlen(endptr) > 1)
        return -1;

    switch (tolower(*endptr)) {
    case 't':
        kbytes <<= 10;
    case 'g':
        kbytes <<= 10;
    case 'm':
        kbytes <<= 10;
    case '\0':
    case 'k':
        break;
    case 'b':
        kbytes >>= 10;
        break;
    default:
        return -1;
    }

    return kbytes;
}

int set_memory_max(char *p, char *mem)
{
    int64_t memorykb;
    int rc;

    find_domain(p);

    memorykb = parse_mem_size_kb(mem);
    if (memorykb == -1) {
        fprintf(stderr, "invalid memory size: %s\n", mem);
        exit(3);
    }

    rc = libxl_domain_setmaxmem(&ctx, domid, memorykb);

    return rc;
}

int main_memmax(int argc, char **argv)
{
    int opt = 0;
    char *p = NULL, *mem;
    int rc;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("mem-max");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }
    if (optind >= argc - 1) {
        help("mem-max");
        exit(2);
    }

    p = argv[optind];
    mem = argv[optind + 1];

    rc = set_memory_max(p, mem);
    if (rc) {
        fprintf(stderr, "cannot set domid %d static max memory to : %s\n", domid, mem);
        exit(1);
    }

    printf("setting domid %d static max memory to : %s\n", domid, mem);
    exit(0);
}

void set_memory_target(char *p, char *mem)
{
    long long int memorykb;

    find_domain(p);

    memorykb = parse_mem_size_kb(mem);
    if (memorykb == -1)  {
        fprintf(stderr, "invalid memory size: %s\n", mem);
        exit(3);
    }

    printf("setting domid %d memory to : %lld\n", domid, memorykb);
    libxl_set_memory_target(&ctx, domid, memorykb, /* enforce */ 1);
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

    CHK_ERRNO(libxl_domain_suspend(&ctx, NULL, domid, fd));
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
        if (asprintf(&away_domname, "%s--migratedaway", common_domname) < 0)
            goto failed_resume;
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
    struct domain_create dom_info;

    signal(SIGPIPE, SIG_IGN);
    /* if we get SIGPIPE we'd rather just have it as an error */

    fprintf(stderr, "migration target: Ready to receive domain.\n");

    CHK_ERRNO( libxl_write_exactly(&ctx, 1,
                                   migrate_receiver_banner,
                                   sizeof(migrate_receiver_banner)-1,
                                   "migration ack stream",
                                   "banner") );

    memset(&dom_info, 0, sizeof(dom_info));
    dom_info.debug = debug;
    dom_info.daemonize = daemonize;
    dom_info.paused = 1;
    dom_info.restore_file = "incoming migration stream";
    dom_info.migration_domname_r = &migration_domname;

    rc = create_domain(&dom_info);
    if (rc < 0) {
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
    struct domain_create dom_info;
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

    memset(&dom_info, 0, sizeof(dom_info));
    dom_info.debug = debug;
    dom_info.daemonize = daemonize;
    dom_info.paused = paused;
    dom_info.config_file = config_file;
    dom_info.restore_file = checkpoint_file;
    dom_info.migrate_fd = -1;

    rc = create_domain(&dom_info);
    if (rc < 0)
        exit(-rc);

    exit(0);
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
        if (asprintf(&rune, "exec %s %s xl migrate-receive%s%s",
                     ssh_command, host,
                     daemonize ? "" : " -e",
                     debug ? " -d" : "") < 0)
            exit(1);
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
    char *p, extra_config[1024];
    struct domain_create dom_info;
    char dom[10]; /* long enough */
    int paused = 0, debug = 0, daemonize = 1, console_autoconnect = 0;
    int opt, rc;

    while ((opt = getopt(argc, argv, "hpcde")) != -1) {
        switch (opt) {
        case 'p':
            paused = 1;
            break;
        case 'c':
            console_autoconnect = 1;
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

    memset(extra_config, 0, sizeof(extra_config));
    while (optind < argc) {
        if ((p = strchr(argv[optind], '='))) {
            if (strlen(extra_config) + 1 < sizeof(extra_config)) {
                if (strlen(extra_config))
                    strcat(extra_config, "\n");
                strcat(extra_config, argv[optind]);
            }
        } else if (!filename) {
            filename = argv[optind];
        } else {
            help("create");
            exit(2);
        }
        optind++;
    }

    memset(&dom_info, 0, sizeof(dom_info));
    dom_info.debug = debug;
    dom_info.daemonize = daemonize;
    dom_info.paused = paused;
    dom_info.config_file = filename;
    dom_info.extra_config = extra_config;
    dom_info.migrate_fd = -1;

    rc = create_domain(&dom_info);
    if (rc < 0)
        exit(-rc);

    if (console_autoconnect) {
        snprintf(dom, sizeof(dom), "%d", rc);
        console(dom, 0);
    }

    exit(0);
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

int main_vcpulist(int argc, char **argv)
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

    if (!(info = libxl_get_version_info(&ctx))) {
        fprintf(stderr, "libxl_get_version_info failed.\n");
        return;
    }

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

    if (uname(&utsbuf) < 0)
        return;

    printf("host                   : %s\n", utsbuf.nodename);
    printf("release                : %s\n", utsbuf.release);
    printf("version                : %s\n", utsbuf.version);
    printf("machine                : %s\n", utsbuf.machine);
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
    if (vinfo) {
        i = (1 << 20) / vinfo->pagesize;
        printf("total_memory           : %"PRIu64"\n", info.total_pages / i);
        printf("free_memory            : %"PRIu64"\n", info.free_pages / i);
    }

    return;
}

static void info(void)
{
    output_nodeinfo();

    output_physinfo();

    output_xeninfo();

    printf("xend_config_format     : 4\n");

    return;
}

int main_info(int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("info");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    info();
    exit(0);
}

static int sched_credit_domain_get(
    int domid, struct libxl_sched_credit *scinfo)
{
    int rc;

    rc = libxl_sched_credit_domain_get(&ctx, domid, scinfo);
    if (rc)
        fprintf(stderr, "libxl_sched_credit_domain_get failed.\n");
    
    return rc;
}

static int sched_credit_domain_set(
    int domid, struct libxl_sched_credit *scinfo)
{
    int rc;

    rc = libxl_sched_credit_domain_set(&ctx, domid, scinfo);
    if (rc)
        fprintf(stderr, "libxl_sched_credit_domain_set failed.\n");

    return rc;
}

static void sched_credit_domain_output(
    int domid, struct libxl_sched_credit *scinfo)
{
    printf("%-33s %4d %6d %4d\n",
        libxl_domid_to_name(&ctx, domid),
        domid,
        scinfo->weight,
        scinfo->cap);
}

int main_sched_credit(int argc, char **argv)
{
    struct libxl_dominfo *info;
    struct libxl_sched_credit scinfo;
    int nb_domain, i;
    char *dom = NULL;
    int weight = 256, cap = 0, opt_w = 0, opt_c = 0;
    int opt, rc;

    while ((opt = getopt(argc, argv, "hd:w:c:")) != -1) {
        switch (opt) {
        case 'd':
            dom = optarg;
            break;
        case 'w':
            weight = strtol(optarg, NULL, 10);
            opt_w = 1;
            break;
        case 'c':
            cap = strtol(optarg, NULL, 10);
            opt_c = 1;
            break;
        case 'h':
            help("sched-credit");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    if (!dom && (opt_w || opt_c)) {
        fprintf(stderr, "Must specify a domain.\n");
        exit(1);
    }

    if (!dom) { /* list all domain's credit scheduler info */
        info = libxl_list_domain(&ctx, &nb_domain);
        if (!info) {
            fprintf(stderr, "libxl_domain_infolist failed.\n");
            exit(1);
        }

        printf("%-33s %4s %6s %4s\n", "Name", "ID", "Weight", "Cap");
        for (i = 0; i < nb_domain; i++) {
            rc = sched_credit_domain_get(info[i].domid, &scinfo);
            if (rc)
                exit(-rc);
            sched_credit_domain_output(info[i].domid, &scinfo);
        }
    } else {
        find_domain(dom);

        rc = sched_credit_domain_get(domid, &scinfo);
        if (rc)
            exit(-rc);

        if (!opt_w && !opt_c) { /* output credit scheduler info */
            printf("%-33s %4s %6s %4s\n", "Name", "ID", "Weight", "Cap");
            sched_credit_domain_output(domid, &scinfo);
        } else { /* set credit scheduler paramaters */
            if (opt_w)
                scinfo.weight = weight;
            if (opt_c)
                scinfo.cap = cap;
            rc = sched_credit_domain_set(domid, &scinfo);
            if (rc)
                exit(-rc);
        }
    }

    exit(0);
}

int main_domid(int argc, char **argv)
{
    int opt;
    char *domname = NULL;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("domid");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    domname = argv[optind];
    if (!domname) {
        fprintf(stderr, "Must specify a domain name.\n\n");
        help("domid");
        exit(1);
    }

    if (libxl_name_to_domid(&ctx, domname, &domid)) {
        fprintf(stderr, "Can't get domid of domain name '%s', maybe this domain does not exist.\n", domname);
        exit(1);
    }

    printf("%d\n", domid);

    exit(0);
}

int main_domname(int argc, char **argv)
{
    int opt;
    char *domname = NULL;
    char *endptr = NULL;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("domname");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    if (!argv[optind]) {
        fprintf(stderr, "Must specify a domain id.\n\n");
        help("domname");
        exit(1);
    }
    domid = strtol(argv[optind], &endptr, 10);
    if (domid == 0 && !strcmp(endptr, argv[optind])) {
        /*no digits at all*/
        fprintf(stderr, "Invalid domain id.\n\n");
        exit(1);
    }

    domname = libxl_domid_to_name(&ctx, domid);
    if (!domname) {
        fprintf(stderr, "Can't get domain name of domain id '%d', maybe this domain does not exist.\n", domid);
        exit(1);
    }

    printf("%s\n", domname);

    exit(0);
}

int main_rename(int argc, char **argv)
{
    int opt;
    char *dom;
    char *new_name;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("rename");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    dom = argv[optind++];
    if (!dom || !argv[optind]) {
        fprintf(stderr, "'xl rename' requires 2 arguments.\n\n");
        help("rename");
        exit(1);
    }

    find_domain(dom);
    new_name = argv[optind];

    if (libxl_domain_rename(&ctx, domid, common_domname, new_name, 0)) {
        fprintf(stderr, "Can't rename domain '%s'.\n", dom);
        exit(1);
    }

    exit(0);
}

int main_trigger(int argc, char **argv)
{
    int opt;
    char *trigger_name = NULL;
    char *endptr = NULL;
    char *dom = NULL;
    int vcpuid = 0;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("trigger");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    dom = argv[optind++];
    if (!dom || !argv[optind]) {
        fprintf(stderr, "'xl trigger' requires between 2 and 3 arguments.\n\n");
        help("trigger");
        exit(1);
    }

    find_domain(dom);

    trigger_name = argv[optind++];

    if (argv[optind]) {
        vcpuid = strtol(argv[optind], &endptr, 10);
        if (vcpuid == 0 && !strcmp(endptr, argv[optind])) {
            fprintf(stderr, "Invalid vcpuid, using default vcpuid=0.\n\n");
        }
    }

    libxl_send_trigger(&ctx, domid, trigger_name, vcpuid);

    exit(0);
}


int main_sysrq(int argc, char **argv)
{
    int opt;
    char *sysrq = NULL;
    char *dom = NULL;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("sysrq");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    dom = argv[optind++];
    if (!dom || !argv[optind]) {
        fprintf(stderr, "'xl sysrq' requires 2 arguments.\n\n");
        help("sysrq");
        exit(1);
    }

    find_domain(dom);

    sysrq = argv[optind];

    if (sysrq[1] != '\0') {
        fprintf(stderr, "Invalid sysrq.\n\n");
        help("sysrq");
        exit(1);
    }

    libxl_send_sysrq(&ctx, domid, sysrq[0]);

    exit(0);
}

int main_top(int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("top");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    system("xentop");

    exit(0);
}

int main_networkattach(int argc, char **argv)
{
    int opt;
    libxl_device_nic nic;
    char *endptr, *tok;
    int i;
    unsigned int val;

    if ((argc < 2) || (argc > 11)) {
        help("network-attach");
        exit(0);
    }
    while ((opt = getopt(argc, argv, "hl")) != -1) {
        switch (opt) {
        case 'h':
            help("network-attach");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    if (domain_qualifier_to_domid(argv[1], &domid, 0) < 0) {
        fprintf(stderr, "%s is an invalid domain identifier\n", argv[1]);
        exit(1);
    }
    init_nic_info(&nic, -1);
    for (argv += 2, argc -= 2; argc > 0; ++argv, --argc) {
        if (!strncmp("type=", *argv, 5)) {
            if (!strncmp("vif", (*argv) + 5, 4)) {
                nic.nictype = NICTYPE_VIF;
            } else if (!strncmp("ioemu", (*argv) + 5, 5)) {
                nic.nictype = NICTYPE_IOEMU;
            } else {
                fprintf(stderr, "Invalid parameter `type'.\n");
                exit(1);
            }
        } else if (!strncmp("mac=", *argv, 4)) {
            tok = strtok((*argv) + 4, ":");
            for (i = 0; tok && i < 6; tok = strtok(NULL, ":"), ++i) {
                val = strtoul(tok, &endptr, 16);
                if ((tok == endptr) || (val > 255)) {
                    fprintf(stderr, "Invalid parameter `mac'.\n");
                    exit(1);
                }
                nic.mac[i] = val;
            }
        } else if (!strncmp("bridge=", *argv, 7)) {
            nic.bridge = (*argv) + 7;
        } else if (!strncmp("ip=", *argv, 3)) {
            if (!inet_aton((*argv) + 3, &(nic.ip))) {
                fprintf(stderr, "Invalid parameter `ip'.\n");
                exit(1);
            }
        } else if (!strncmp("script=", *argv, 6)) {
            nic.script = (*argv) + 6;
        } else if (!strncmp("backend=", *argv, 8)) {
            val = strtoul((*argv) + 8, &endptr, 10);
            if (((*argv) + 8) == endptr) {
                fprintf(stderr, "Invalid parameter `backend'.\n");
                exit(1);
            }
            nic.backend_domid = val;
        } else if (!strncmp("vifname=", *argv, 8)) {
            nic.ifname = (*argv) + 8;
        } else if (!strncmp("model=", *argv, 6)) {
            nic.model = (*argv) + 6;
        } else if (!strncmp("rate=", *argv, 5)) {
        } else if (!strncmp("accel=", *argv, 6)) {
        } else {
            fprintf(stderr, "unrecognized argument `%s'\n", *argv);
            exit(1);
        }
    }
    nic.domid = domid;
    if (libxl_device_nic_add(&ctx, domid, &nic)) {
        fprintf(stderr, "libxl_device_nic_add failed.\n");
        exit(1);
    }
    exit(0);
}

int main_networklist(int argc, char **argv)
{
    int opt;
    libxl_nicinfo *nics;
    unsigned int nb;

    if (argc < 2) {
        help("network-list");
        exit(1);
    }
    while ((opt = getopt(argc, argv, "hl")) != -1) {
        switch (opt) {
            case 'h':
                help("network-list");
                exit(0);
            default:
                fprintf(stderr, "option `%c' not supported.\n", opt);
                break;
        }
    }

    /*      Idx  BE   MAC   Hdl  Sta  evch txr/rxr  BE-path */
    printf("%-3s %-2s %-17s %-6s %-5s %-6s %5s/%-5s %-30s\n",
           "Idx", "BE", "Mac Addr.", "handle", "state", "evt-ch", "tx-", "rx-ring-ref", "BE-path");
    for (++argv, --argc; argc > 0; --argc, ++argv) {
        if (domain_qualifier_to_domid(*argv, &domid, 0) < 0) {
            fprintf(stderr, "%s is an invalid domain identifier\n", *argv);
            continue;
        }
        if (!(nics = libxl_list_nics(&ctx, domid, &nb))) {
            continue;
        }
        for (; nb > 0; --nb, ++nics) {
            /* Idx BE */
            printf("%-3d %-2d ", nics->devid, nics->backend_id);
            /* MAC */
            printf("%02x:%02x:%02x:%02x:%02x:%02x ",
                   nics->mac[0], nics->mac[1], nics->mac[2],
                   nics->mac[3], nics->mac[4], nics->mac[5]);
            /* Hdl  Sta  evch txr/rxr  BE-path */
            printf("%6d %5d %6d %5d/%-11d %-30s\n",
                   nics->devid, nics->state, nics->evtch,
                   nics->rref_tx, nics->rref_rx, nics->backend);
        }
    }
    exit(0);
}

int main_networkdetach(int argc, char **argv)
{
    int opt;
    libxl_device_nic nic;

    if (argc != 3) {
        help("network-detach");
        exit(0);
    }
    while ((opt = getopt(argc, argv, "hl")) != -1) {
        switch (opt) {
        case 'h':
            help("network-detach");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    if (domain_qualifier_to_domid(argv[1], &domid, 0) < 0) {
        fprintf(stderr, "%s is an invalid domain identifier\n", argv[1]);
        exit(1);
    }

    if (!strchr(argv[2], ':')) {
        if (libxl_devid_to_device_nic(&ctx, domid, argv[2], &nic)) {
            fprintf(stderr, "Unknown device %s.\n", argv[2]);
            exit(1);
        }
    } else {
        if (libxl_mac_to_device_nic(&ctx, domid, argv[2], &nic)) {
            fprintf(stderr, "Unknown device %s.\n", argv[2]);
            exit(1);
        }
    }
    if (libxl_device_nic_del(&ctx, &nic, 1)) {
        fprintf(stderr, "libxl_device_nic_del failed.\n");
    }
    exit(0);
}

int main_blockattach(int argc, char **argv)
{
    int opt;
    char *tok;
    uint32_t fe_domid, be_domid = 0;
    libxl_device_disk disk = { 0 };

    if ((argc < 3) || (argc > 6)) {
        help("block-attach");
        exit(0);
    }
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("block-attach");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    tok = strtok(argv[2], ":");
    if (!strcmp(tok, "phy")) {
        disk.phystype = PHYSTYPE_PHY;
    } else if (!strcmp(tok, "file")) {
        disk.phystype = PHYSTYPE_FILE;
    } else if (!strcmp(tok, "tap")) {
        tok = strtok(NULL, ":");
        if (!strcmp(tok, "aio")) {
            disk.phystype = PHYSTYPE_AIO;
        } else if (!strcmp(tok, "vhd")) {
            disk.phystype = PHYSTYPE_VHD;
        } else if (!strcmp(tok, "qcow")) {
            disk.phystype = PHYSTYPE_QCOW;
        } else if (!strcmp(tok, "qcow2")) {
            disk.phystype = PHYSTYPE_QCOW2;
        } else {
            fprintf(stderr, "Error: `%s' is not a valid disk image.\n", tok);
            exit(1);
        }
    } else {
        fprintf(stderr, "Error: `%s' is not a valid block device.\n", tok);
        exit(1);
    }
    disk.physpath = strtok(NULL, "\0");
    if (!disk.physpath) {
        fprintf(stderr, "Error: missing path to disk image.\n");
        exit(1);
    }
    disk.virtpath = argv[3];
    disk.unpluggable = 1;
    disk.readwrite = (argv[4][0] == 'w') ? 1 : 0;

    if (domain_qualifier_to_domid(argv[1], &fe_domid, 0) < 0) {
        fprintf(stderr, "%s is an invalid domain identifier\n", argv[1]);
        exit(1);
    }
    if (argc == 6) {
        if (domain_qualifier_to_domid(argv[5], &be_domid, 0) < 0) {
            fprintf(stderr, "%s is an invalid domain identifier\n", argv[5]);
            exit(1);
        }
    }
    disk.domid = fe_domid;
    disk.backend_domid = be_domid;
    if (libxl_device_disk_add(&ctx, fe_domid, &disk)) {
        fprintf(stderr, "libxl_device_disk_add failed.\n");
    }
    exit(0);
}

int main_blocklist(int argc, char **argv)
{
    int opt;
    int nb;
    libxl_device_disk *disks;
    libxl_diskinfo diskinfo;

    if (argc < 2) {
        help("block-list");
        exit(0);
    }
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("block-list");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    printf("%-5s %-3s %-6s %-5s %-6s %-8s %-30s\n",
           "Vdev", "BE", "handle", "state", "evt-ch", "ring-ref", "BE-path");
    for (++argv, --argc; argc > 0; --argc, ++argv) {
        if (domain_qualifier_to_domid(*argv, &domid, 0) < 0) {
            fprintf(stderr, "%s is an invalid domain identifier\n", *argv);
            continue;
        }
        disks = libxl_device_disk_list(&ctx, domid, &nb);
        if (!disks) {
            continue;
        }
        for (; nb > 0; --nb, ++disks) {
            if (!libxl_device_disk_getinfo(&ctx, domid, disks, &diskinfo)) {
                /*      Vdev BE   hdl  st   evch rref BE-path*/
                printf("%-5d %-3d %-6d %-5d %-6d %-8d %-30s\n",
                       diskinfo.devid, diskinfo.backend_id, diskinfo.frontend_id,
                       diskinfo.state, diskinfo.evtch, diskinfo.rref, diskinfo.backend);
            }
        }
    }
    exit(0);
}

int main_blockdetach(int argc, char **argv)
{
    int opt;
    libxl_device_disk disk;

    if (argc != 3) {
        help("block-detach");
        exit(0);
    }
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("block-detach");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    if (domain_qualifier_to_domid(argv[1], &domid, 0) < 0) {
        fprintf(stderr, "%s is an invalid domain identifier\n", argv[1]);
        exit(1);
    }
    if (libxl_devid_to_device_disk(&ctx, domid, argv[2], &disk)) {
        fprintf(stderr, "Error: Device %s not connected.\n", argv[2]);
        exit(1);
    }
    if (libxl_device_disk_del(&ctx, &disk, 1)) {
        fprintf(stderr, "libxl_device_del failed.\n");
    }
    exit(0);
}

static char *uptime_to_string(unsigned long time, int short_mode)
{
    int sec, min, hour, day;
    char *time_string;

    day = (int)(time / 86400);
    time -= (day * 86400);
    hour = (int)(time / 3600);
    time -= (hour * 3600);
    min = (int)(time / 60);
    time -= (min * 60);
    sec = time;

    if (short_mode)
        if (day > 1)
            asprintf(&time_string, "%d days, %2d:%02d", day, hour, min);
        else if (day == 1)
            asprintf(&time_string, "%d day, %2d:%02d", day, hour, min);
        else
            asprintf(&time_string, "%2d:%02d", hour, min);
    else
        if (day > 1)
            asprintf(&time_string, "%d days, %2d:%02d:%02d", day, hour, min, sec);
        else if (day == 1)
            asprintf(&time_string, "%d day, %2d:%02d:%02d", day, hour, min, sec);
        else
            asprintf(&time_string, "%2d:%02d:%02d", hour, min, sec);

    return time_string;
}

static char *current_time_to_string(time_t now)
{
    char now_str[100];
    struct tm *tmp;

    tmp = localtime(&now);
    if (tmp == NULL) {
        fprintf(stderr, "Get localtime error");
        exit(-1);
    }
    if (strftime(now_str, sizeof(now_str), "%H:%M:%S", tmp) == 0) {
        fprintf(stderr, "strftime returned 0");
        exit(-1);
    }
    return strdup(now_str);
}

static void print_dom0_uptime(int short_mode, time_t now)
{
    int fd;
    char buf[512];
    uint32_t uptime = 0;

    fd = open("/proc/uptime", 'r');
    if (fd == -1)
        goto err;

    if (read(fd, buf, sizeof(buf)) == -1) {
        close(fd);
        goto err;
    }
    close(fd);

    strtok(buf, " ");
    uptime = strtoul(buf, NULL, 10);

    if (short_mode)
        printf(" %s up %s, %s (%d)\n", current_time_to_string(now),
               uptime_to_string(uptime, 1), libxl_domid_to_name(&ctx, 0), 0);
    else
        printf("%-33s %4d %s\n", libxl_domid_to_name(&ctx, 0),
               0, uptime_to_string(uptime, 0));

    return;
err:
    fprintf(stderr, "Can not get Dom0 uptime.\n");
    exit(-1);
}

static void print_domU_uptime(uint32_t domuid, int short_mode, time_t now)
{
    uint32_t s_time = 0;
    uint32_t uptime = 0;

    s_time = libxl_vm_get_start_time(&ctx, domuid);
    if (s_time == -1)
        return;
    uptime = now - s_time;
    if (short_mode)
        printf(" %s up %s, %s (%d)\n", current_time_to_string(now),
               uptime_to_string(uptime, 1),
               libxl_domid_to_name(&ctx, domuid),
               domuid);
    else
        printf("%-33s %4d %s\n", libxl_domid_to_name(&ctx, domuid),
               domuid, uptime_to_string(uptime, 0));
}

static void print_uptime(int short_mode, uint32_t doms[], int nb_doms)
{
    struct libxl_vminfo *info;
    time_t now;
    int nb_vm, i;

    now = time(NULL);

    if (!short_mode)
        printf("%-33s %4s %s\n", "Name", "ID", "Uptime");

    if (nb_doms == 0) {
        print_dom0_uptime(short_mode, now);
        info = libxl_list_vm(&ctx, &nb_vm);
        for (i = 0; i < nb_vm; i++)
            print_domU_uptime(info[i].domid, short_mode, now);
    } else {
        for (i = 0; i < nb_doms; i++) {
            if (doms[i] == 0)
                print_dom0_uptime(short_mode, now);
            else
                print_domU_uptime(doms[i], short_mode, now);
        }
    }
}

int main_uptime(int argc, char **argv)
{
    char *dom = NULL;
    int short_mode = 0;
    uint32_t domains[100];
    int nb_doms = 0;
    int opt;

    while ((opt = getopt(argc, argv, "hs")) != -1) {
        switch (opt) {
        case 's':
            short_mode = 1;
            break;
        case 'h':
            help("uptime");
            exit(0);
        default:
            fprintf(stderr, "option `%c' not supported.\n", opt);
            break;
        }
    }

    for (;(dom = argv[optind]) != NULL; nb_doms++,optind++) {
        find_domain(dom);
        domains[nb_doms] = domid;
    }

    print_uptime(short_mode, domains, nb_doms);

    exit(0);
}
