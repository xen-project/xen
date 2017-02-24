/*
 * Copyright 2009-2017 Citrix Ltd and other contributors
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

#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

#ifndef LIBXL_HAVE_NO_SUSPEND_RESUME

void save_domain_core_begin(uint32_t domid,
                            const char *override_config_file,
                            uint8_t **config_data_r,
                            int *config_len_r)
{
    int rc;
    libxl_domain_config d_config;
    char *config_c = 0;

    /* configuration file in optional data: */

    libxl_domain_config_init(&d_config);

    if (override_config_file) {
        void *config_v = 0;
        rc = libxl_read_file_contents(ctx, override_config_file,
                                      &config_v, config_len_r);
        if (rc) {
            fprintf(stderr, "unable to read overridden config file\n");
            exit(EXIT_FAILURE);
        }
        parse_config_data(override_config_file, config_v, *config_len_r,
                          &d_config);
        free(config_v);
    } else {
        rc = libxl_retrieve_domain_configuration(ctx, domid, &d_config);
        if (rc) {
            fprintf(stderr, "unable to retrieve domain configuration\n");
            exit(EXIT_FAILURE);
        }
    }

    config_c = libxl_domain_config_to_json(ctx, &d_config);
    if (!config_c) {
        fprintf(stderr, "unable to convert config file to JSON\n");
        exit(EXIT_FAILURE);
    }
    *config_data_r = (uint8_t *)config_c;
    *config_len_r = strlen(config_c) + 1; /* including trailing '\0' */

    libxl_domain_config_dispose(&d_config);
}

void save_domain_core_writeconfig(int fd, const char *source,
                                  const uint8_t *config_data, int config_len)
{
    struct save_file_header hdr;
    uint8_t *optdata_begin;
    union { uint32_t u32; char b[4]; } u32buf;

    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, savefileheader_magic, sizeof(hdr.magic));
    hdr.byteorder = SAVEFILE_BYTEORDER_VALUE;
    hdr.mandatory_flags = XL_MANDATORY_FLAG_STREAMv2;

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
    if (config_len)
        hdr.mandatory_flags |= XL_MANDATORY_FLAG_JSON;

    /* that's the optional data */

    CHK_ERRNOVAL(libxl_write_exactly(
                     ctx, fd, &hdr, sizeof(hdr), source, "header"));
    CHK_ERRNOVAL(libxl_write_exactly(
                     ctx, fd, optdata_begin, hdr.optional_data_len,
                     source, "header"));

    free(optdata_begin);

    fprintf(stderr, "Saving to %s new xl format (info"
            " 0x%"PRIx32"/0x%"PRIx32"/%"PRIu32")\n",
            source, hdr.mandatory_flags, hdr.optional_flags,
            hdr.optional_data_len);
}

static int save_domain(uint32_t domid, const char *filename, int checkpoint,
                            int leavepaused, const char *override_config_file)
{
    int fd;
    uint8_t *config_data;
    int config_len;

    save_domain_core_begin(domid, override_config_file,
                           &config_data, &config_len);

    if (!config_len) {
        fputs(" Savefile will not contain xl domain config\n", stderr);
    }

    fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "Failed to open temp file %s for writing\n", filename);
        exit(EXIT_FAILURE);
    }

    save_domain_core_writeconfig(fd, filename, config_data, config_len);

    int rc = libxl_domain_suspend(ctx, domid, fd, 0, NULL);
    close(fd);

    if (rc < 0) {
        fprintf(stderr, "Failed to save domain, resuming domain\n");
        libxl_domain_resume(ctx, domid, 1, 0);
    }
    else if (leavepaused || checkpoint) {
        if (leavepaused)
            libxl_domain_pause(ctx, domid);
        libxl_domain_resume(ctx, domid, 1, 0);
    }
    else
        libxl_domain_destroy(ctx, domid, 0);

    exit(rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main_restore(int argc, char **argv)
{
    const char *checkpoint_file = NULL;
    const char *config_file = NULL;
    struct domain_create dom_info;
    int paused = 0, debug = 0, daemonize = 1, monitor = 1,
        console_autoconnect = 0, vnc = 0, vncautopass = 0;
    int opt, rc;
    static struct option opts[] = {
        {"vncviewer", 0, 0, 'V'},
        {"vncviewer-autopass", 0, 0, 'A'},
        COMMON_LONG_OPTS
    };

    SWITCH_FOREACH_OPT(opt, "FcpdeVA", opts, "restore", 1) {
    case 'c':
        console_autoconnect = 1;
        break;
    case 'p':
        paused = 1;
        break;
    case 'd':
        debug = 1;
        break;
    case 'F':
        daemonize = 0;
        break;
    case 'e':
        daemonize = 0;
        monitor = 0;
        break;
    case 'V':
        vnc = 1;
        break;
    case 'A':
        vnc = vncautopass = 1;
        break;
    }

    if (argc-optind == 1) {
        checkpoint_file = argv[optind];
    } else if (argc-optind == 2) {
        config_file = argv[optind];
        checkpoint_file = argv[optind + 1];
    } else {
        help("restore");
        return EXIT_FAILURE;
    }

    memset(&dom_info, 0, sizeof(dom_info));
    dom_info.debug = debug;
    dom_info.daemonize = daemonize;
    dom_info.monitor = monitor;
    dom_info.paused = paused;
    dom_info.config_file = config_file;
    dom_info.restore_file = checkpoint_file;
    dom_info.migrate_fd = -1;
    dom_info.send_back_fd = -1;
    dom_info.vnc = vnc;
    dom_info.vncautopass = vncautopass;
    dom_info.console_autoconnect = console_autoconnect;

    rc = create_domain(&dom_info);
    if (rc < 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int main_save(int argc, char **argv)
{
    uint32_t domid;
    const char *filename;
    const char *config_filename = NULL;
    int checkpoint = 0;
    int leavepaused = 0;
    int opt;

    SWITCH_FOREACH_OPT(opt, "cp", NULL, "save", 2) {
    case 'c':
        checkpoint = 1;
        break;
    case 'p':
        leavepaused = 1;
        break;
    }

    if (argc-optind > 3) {
        help("save");
        return EXIT_FAILURE;
    }

    domid = find_domain(argv[optind]);
    filename = argv[optind + 1];
    if ( argc - optind >= 3 )
        config_filename = argv[optind + 2];

    save_domain(domid, filename, checkpoint, leavepaused, config_filename);
    return EXIT_SUCCESS;
}

#endif /* LIBXL_HAVE_NO_SUSPEND_RESUME */



/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
