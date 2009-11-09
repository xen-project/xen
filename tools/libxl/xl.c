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

#include "libxl.h"
#include "libxl_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>
#include <libconfig.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <xenctrl.h>

void log_callback(void *userdata, int loglevel, const char *file, int line, const char *func, char *s)
{
    fprintf(stderr, "[%d] %s:%d:%s: %s\n", loglevel, file, line, func, s);
}

static void printf_info(libxl_domain_create_info *c_info,
                        libxl_domain_build_info *b_info,
                        libxl_device_disk *disks,
                        int num_disks,
                        libxl_device_nic *vifs,
                        int num_vifs,
                        libxl_device_model_info *dm_info)
{
    int i;
    printf("*** domain_create_info ***\n");
    printf("hvm: %d\n", c_info->hvm);
    printf("hap: %d\n", c_info->hap);
    printf("ssidref: %d\n", c_info->ssidref);
    printf("name: %s\n", c_info->name);
    printf("uuid: " UUID_FMT "\n", c_info->uuid[0], c_info->uuid[1], c_info->uuid[2], c_info->uuid[3],
           c_info->uuid[4], c_info->uuid[5], c_info->uuid[6], c_info->uuid[7],
           c_info->uuid[8], c_info->uuid[9], c_info->uuid[10], c_info->uuid[11],
           c_info->uuid[12], c_info->uuid[13], c_info->uuid[14], c_info->uuid[15]);
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
    printf("max_memkb: %d\n", b_info->max_memkb);
    printf("video_memkb: %d\n", b_info->video_memkb);
    printf("shadow_memkb: %d\n", b_info->shadow_memkb);
    printf("kernel: %s\n", b_info->kernel);
    printf("hvm: %d\n", b_info->hvm);

    if (b_info->hvm) {
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
        printf("smac %s\n", vifs[i].mac);
    }

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

static char* compat_config_file(const char *filename)
{
    char t;
    char *newfile = (char*) malloc(strlen(filename) + 4);
    char *buf = (char *) malloc(2048);
    int size = 2048, i;
    FILE *s;
    FILE *d;

    sprintf(newfile, "%s.xl", filename);

    s = fopen(filename, "r");
    if (!s) {
        perror("cannot open file for reading");
        return NULL;
    }
    d = fopen(newfile, "w");
    if (!d) {
        fclose(s);
        perror("cannot open file for writting");
        return NULL;
    }

    while (!feof(s)) {
        fgets(buf, size, s);
        while (buf[strlen(buf) - 1] != '\n' && !feof(s)) {
            size += 1024;
            buf = realloc(buf, size + 1024);
            fgets(buf + (size - 1025), 1025, s);
        }
        for (i = 0; i < strlen(buf); i++)
            if (buf[i] == '\'')
                buf[i] = '\"';
        if (strchr(buf, '=') != NULL) {
            if ((buf[strlen(buf) - 1] == '\n' && buf[strlen(buf) - 2] == ';') ||
                    buf[strlen(buf) - 1] == ';') {
                fputs(buf, d);
            } else {
                t = buf[strlen(buf) - 1];
                buf[strlen(buf) - 1] = ';';
                fputs(buf, d);
                fputc(t, d);
            }
        } else if (buf[0] == '#' || buf[0] == ' ' || buf[0] == '\n') {
            fputs(buf, d);
        }
    }

    fclose(s);
    fclose(d);

    free(buf);

    return newfile;
}

void init_create_info(libxl_domain_create_info *c_info)
{
    memset(c_info, '\0', sizeof(*c_info));
    c_info->xsdata = NULL;
    c_info->platformdata = NULL;
    c_info->hvm = 1;
    c_info->ssidref = 0;
}

void init_build_info(libxl_domain_build_info *b_info, libxl_domain_create_info *c_info)
{
    memset(b_info, '\0', sizeof(*b_info));
    b_info->timer_mode = -1;
    b_info->hpet = 1;
    b_info->vpt_align = -1;
    b_info->max_vcpus = 1;
    b_info->max_memkb = 32 * 1024;
    b_info->shadow_memkb = libxl_get_required_shadow_memory(b_info->max_memkb, b_info->max_vcpus);
    b_info->video_memkb = 8 * 1024;
    b_info->kernel = "/usr/lib/xen/boot/hvmloader";
    if (c_info->hvm) {
        b_info->hvm = 1;
        b_info->u.hvm.pae = 1;
        b_info->u.hvm.apic = 1;
        b_info->u.hvm.acpi = 1;
        b_info->u.hvm.nx = 1;
        b_info->u.hvm.viridian = 0;
    }
}

void init_dm_info(libxl_device_model_info *dm_info,
        libxl_domain_create_info *c_info, libxl_domain_build_info *b_info)
{
    memset(dm_info, '\0', sizeof(*dm_info));

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

void init_nic_info(libxl_device_nic *nic_info, int devnum)
{
    memset(nic_info, '\0', sizeof(*nic_info));


    nic_info->backend_domid = 0;
    nic_info->domid = 0;
    nic_info->devid = devnum;
    nic_info->mtu = 1492;
    nic_info->model = "e1000";
    srand(time(0));
    nic_info->mac[0] = 0x00;
    nic_info->mac[1] = 0x16;
    nic_info->mac[2] = 0x3e;
    nic_info->mac[3] = 1 + (int) (0x7f * (rand() / (RAND_MAX + 1.0)));
    nic_info->mac[4] = 1 + (int) (0xff * (rand() / (RAND_MAX + 1.0)));
    nic_info->mac[5] = 1 + (int) (0xff * (rand() / (RAND_MAX + 1.0)));
    asprintf(&(nic_info->smac), "%02x:%02x:%02x:%02x:%02x:%02x", nic_info->mac[0], nic_info->mac[1], nic_info->mac[2], nic_info->mac[3], nic_info->mac[4], nic_info->mac[5]);
    nic_info->ifname = NULL;
    nic_info->bridge = "xenbr0";
    nic_info->script = "/etc/xen/scripts/vif-bridge";
    nic_info->nictype = NICTYPE_IOEMU;
}

void nic_info_domid_fixup(libxl_device_nic *nic_info, int domid)
{
    nic_info->domid = domid;
    if (!nic_info->ifname)
        asprintf(&(nic_info->ifname), "tap%d.%d", domid, nic_info->devid - 1);
}

void disk_info_domid_fixup(libxl_device_disk *disk_info, int domid)
{
    disk_info->domid = domid;
}

void device_model_info_domid_fixup(libxl_device_model_info *dm_info, int domid)
{
    dm_info->domid = domid;
}

static void parse_config_file(const char *filename,
                              libxl_domain_create_info *c_info,
                              libxl_domain_build_info *b_info,
                              libxl_device_disk **disks,
                              int *num_disks,
                              libxl_device_nic **vifs,
                              int *num_vifs,
                              libxl_device_model_info *dm_info)
{
    const char *buf;
    uint8_t uuid[16];
    long l;
    struct config_t config;
    struct config_setting_t *vbds, *nics;

    config_init (&config);

    if (!config_read_file(&config, filename)) {
        char *newfilename;
        config_destroy(&config);
        newfilename = compat_config_file(filename);
        config_init (&config);
        if (!config_read_file(&config, newfilename)) {
            fprintf(stderr, "Failed to parse config file %s, try removing any embedded python code\n", config_error_text(&config));
            exit(1);
        }
        free(newfilename);
    }

    init_create_info(c_info);

    if (config_lookup_string (&config, "builder", &buf) == CONFIG_TRUE) {
        if (!strncmp(buf, "hvm", strlen(buf)))
            c_info->hvm = 1;
        else
            c_info->hvm = 0;
    }

    /* hap is missing */
    if (config_lookup_string (&config, "name", &buf) == CONFIG_TRUE)
        c_info->name = strdup(buf);
    else
        c_info->name = "test";
    uuid_generate(uuid);
    c_info->uuid = uuid;

    init_build_info(b_info, c_info);

    /* the following is the actual config parsing with overriding values in the structures */
    if (config_lookup_int (&config, "vcpus", &l) == CONFIG_TRUE)
        b_info->max_vcpus = l;

    if (config_lookup_int (&config, "memory", &l) == CONFIG_TRUE)
        b_info->max_memkb = l * 1024;

    if (config_lookup_int (&config, "shadow_memory", &l) == CONFIG_TRUE)
        b_info->shadow_memkb = l * 1024;

    if (config_lookup_int (&config, "videoram", &l) == CONFIG_TRUE)
        b_info->video_memkb = l * 1024;

    if (config_lookup_string (&config, "kernel", &buf) == CONFIG_TRUE)
        b_info->kernel = strdup(buf);

    if (c_info->hvm == 1) {
        if (config_lookup_int (&config, "pae", &l) == CONFIG_TRUE)
            b_info->u.hvm.pae = l;
        if (config_lookup_int (&config, "apic", &l) == CONFIG_TRUE)
            b_info->u.hvm.apic = l;
        if (config_lookup_int (&config, "acpi", &l) == CONFIG_TRUE)
            b_info->u.hvm.acpi = l;
        if (config_lookup_int (&config, "nx", &l) == CONFIG_TRUE)
            b_info->u.hvm.nx = l;
        if (config_lookup_int (&config, "viridian", &l) == CONFIG_TRUE)
            b_info->u.hvm.viridian = l;
    } else {
        if (config_lookup_string (&config, "cmdline", &buf) == CONFIG_TRUE)
            b_info->u.pv.cmdline = buf;
        if (config_lookup_string (&config, "ramdisk", &buf) == CONFIG_TRUE)
            b_info->u.pv.ramdisk = buf;
    }

    if ((vbds = config_lookup (&config, "disk")) != NULL) {
        *num_disks = 0;
        *disks = NULL;
        while ((buf = config_setting_get_string_elem (vbds, *num_disks)) != NULL) {
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
            } else {
                *p2 = '\0';
                (*disks)[*num_disks].virtpath = strdup(p);
                if (!strcmp(p2 + 1, "cdrom"))
                    (*disks)[*num_disks].is_cdrom = 1;
                else
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

    if ((nics = config_lookup (&config, "vif")) != NULL) {
        *num_vifs = 0;
        *vifs = NULL;
        while ((buf = config_setting_get_string_elem (nics, *num_vifs)) != NULL) {
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
                    (*vifs)[*num_vifs].smac = strdup(p3);
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

    /* init dm from c and b */
    init_dm_info(dm_info, c_info, b_info);

    /* then process config related to dm */
    if (config_lookup_string (&config, "device_model", &buf) == CONFIG_TRUE)
        dm_info->device_model = strdup(buf);
    if (config_lookup_int (&config, "stdvga", &l) == CONFIG_TRUE)
        dm_info->stdvga = l;
    if (config_lookup_int (&config, "vnc", &l) == CONFIG_TRUE)
        dm_info->vnc = l;
    if (config_lookup_string (&config, "vnclisten", &buf) == CONFIG_TRUE)
        dm_info->vnclisten = strdup(buf);
    if (config_lookup_int (&config, "vncdisplay", &l) == CONFIG_TRUE)
        dm_info->vncdisplay = l;
    if (config_lookup_int (&config, "vncunused", &l) == CONFIG_TRUE)
        dm_info->vncunused = l;
    if (config_lookup_string (&config, "keymap", &buf) == CONFIG_TRUE)
        dm_info->keymap = strdup(buf);
    if (config_lookup_int (&config, "sdl", &l) == CONFIG_TRUE)
        dm_info->sdl = l;
    if (config_lookup_int (&config, "opengl", &l) == CONFIG_TRUE)
        dm_info->opengl = l;
    if (config_lookup_int (&config, "nographic", &l) == CONFIG_TRUE)
        dm_info->nographic = l;
    if (config_lookup_string (&config, "serial", &buf) == CONFIG_TRUE)
        dm_info->serial = strdup(buf);
    if (config_lookup_string (&config, "boot", &buf) == CONFIG_TRUE)
        dm_info->boot = strdup(buf);
    if (config_lookup_int (&config, "usb", &l) == CONFIG_TRUE)
        dm_info->usb = l;
    if (config_lookup_string (&config, "usbdevice", &buf) == CONFIG_TRUE)
        dm_info->usbdevice = strdup(buf);

    config_destroy(&config);
}

static void create_domain(int debug, const char *filename)
{
    struct libxl_ctx ctx;
    uint32_t domid;
    libxl_domain_create_info info1;
    libxl_domain_build_info info2;
    libxl_device_model_info dm_info;
    libxl_device_disk *disks = NULL;
    libxl_device_nic *vifs = NULL;
    int num_disks = 0, num_vifs = 0;
    int i;

    printf("Parsing config file %s\n", filename);
    parse_config_file(filename, &info1, &info2, &disks, &num_disks, &vifs, &num_vifs, &dm_info);
    if (debug)
        printf_info(&info1, &info2, disks, num_disks, vifs, num_vifs, &dm_info);

    libxl_ctx_init(&ctx);
    libxl_ctx_set_log(&ctx, log_callback, NULL);
    libxl_domain_make(&ctx, &info1, &domid);
    libxl_domain_build(&ctx, &info2, domid);

    device_model_info_domid_fixup(&dm_info, domid);

    for (i = 0; i < num_disks; i++) {
        disk_info_domid_fixup(disks + i, domid);
        libxl_device_disk_add(&ctx, domid, &disks[i]);
    }
    for (i = 0; i < num_vifs; i++) {
        nic_info_domid_fixup(vifs + i, domid);
        libxl_device_nic_add(&ctx, domid, &vifs[i]);
    }
    libxl_create_device_model(&ctx, &dm_info, vifs, num_vifs);
    libxl_domain_unpause(&ctx, domid);

}

static void help(char *command)
{
    if (!command || !strcmp(command, "help")) {
        printf("Usage xl <subcommand> [args]\n\n");
        printf("xl full list of subcommands:\n\n");
        printf(" create                                create a domain from config file <filename>\n\n");
        printf(" list                          list information about all domains\n\n");
        printf(" destroy                       terminate a domain immediately\n\n");
    } else if(!strcmp(command, "create")) {
        printf("Usage: xl create <ConfigFile> [options] [vars]\n\n");
        printf("Create a domain based on <ConfigFile>.\n\n");
        printf("Options:\n\n");
        printf("-h                     Print this help.\n");
        printf("-d                     Enable debug messages.\n");
    } else if(!strcmp(command, "list")) {
        printf("Usage: xl list [Domain]\n\n");
        printf("List information about all/some domains.\n\n");
    } else if(!strcmp(command, "destroy")) {
        printf("Usage: xl destroy <Domain>\n\n");
        printf("Terminate a domain immediately.\n\n");
    }
}

void destroy_domain(char *p)
{
    struct libxl_ctx ctx;
    uint32_t domid;

    libxl_ctx_init(&ctx);
    libxl_ctx_set_log(&ctx, log_callback, NULL);

    if (libxl_param_to_domid(&ctx, p, &domid) < 0) {
        fprintf(stderr, "%s is an invalid domain identifier\n", p);
        exit(2);
    }
    libxl_domain_destroy(&ctx, domid, 0);
}

void list_domains(void)
{
    struct libxl_ctx ctx;
    xc_dominfo_t *info;
    int nb_domain, i;

    libxl_ctx_init(&ctx);
    libxl_ctx_set_log(&ctx, log_callback, NULL);

    info = libxl_domain_infolist(&ctx, &nb_domain);

    if (info < 0) {
        fprintf(stderr, "libxl_domain_infolist failed.\n");
        exit(1);
    }
    printf("Name                                        ID   Mem VCPUs\tState\tTime(s)\n");
    for (i = 0; i < nb_domain; i++) {
        printf("%-40s %5d %5lu %5d     %c%c%c%c%c%c %8.1f\n",
                libxl_domid_to_name(&ctx, info[i].domid),
                info[i].domid,
                info[i].nr_pages * XC_PAGE_SIZE/(1024*1024),
                info[i].nr_online_vcpus,
                info[i].running ? 'r' : '-',
                info[i].blocked ? 'b' : '-',
                info[i].paused ? 'p' : '-',
                info[i].shutdown ? 's' : '-',
                info[i].crashed ? 'c' : '-',
                info[i].dying ? 'd' : '-',
                ((float)info[i].cpu_time / 1e9));
    }
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
    int opt;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            help("list");
            exit(0);
        default:
            fprintf(stderr, "option not supported\n");
            break;
        }
    }

    list_domains();
    exit(0);
}

int main_create(int argc, char **argv)
{
    char *filename = NULL;
    int debug = 0;
    int opt;

    while ((opt = getopt(argc, argv, "hd")) != -1) {
        switch (opt) {
        case 'd':
            debug = 1;
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
    create_domain(debug, filename);
    exit(0);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        help(NULL);
        exit(1);
    }

    if (!strcmp(argv[1], "create")) {
        main_create(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "list")) {
        main_list(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "destroy")) {
        main_destroy(argc - 1, argv + 1);
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

