/*
 * Copyright (C) 2016 EPAM Systems Inc.
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

#include <stdlib.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include <xen/io/sndif.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

int main_vsndattach(int argc, char **argv)
{
    int opt;
    int rc;
    uint32_t domid;
    libxl_device_vsnd vsnd;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vsnd-attach", 2) {
        /* No options */
    }

    libxl_device_vsnd_init(&vsnd);
    domid = find_domain(argv[optind++]);

    for (argv += optind, argc -= optind; argc > 0; ++argv, --argc) {
        rc = parse_vsnd_item(&vsnd, *argv);
        if (rc) goto out;
    }

    if (dryrun_only) {
        char *json = libxl_device_vsnd_to_json(ctx, &vsnd);
        printf("vsnd: %s\n", json);
        rc = 0;
        free(json);
        goto out;
    }

    if (libxl_device_vsnd_add(ctx, domid, &vsnd, 0)) {
        fprintf(stderr, "libxl_device_vsnd_add failed.\n");
        rc = ERROR_FAIL; goto out;
    }

    rc = 0;

out:
    libxl_device_vsnd_dispose(&vsnd);
    return rc;
}

static void print_params(libxl_vsnd_params *params)
{
    int i;

    if (params->channels_min) {
        printf(", "XENSND_FIELD_CHANNELS_MIN": %u", params->channels_min);
    }

    if (params->channels_max) {
        printf(", "XENSND_FIELD_CHANNELS_MAX": %u", params->channels_max);
    }

    if (params->buffer_size) {
        printf(", "XENSND_FIELD_BUFFER_SIZE": %u", params->buffer_size);
    }

    if (params->num_sample_rates) {
        printf(", "XENSND_FIELD_SAMPLE_RATES": ");
        for (i = 0; i < params->num_sample_rates - 1; i++) {
            printf("%u;", params->sample_rates[i]);
        }
        printf("%u", params->sample_rates[i]);
    }

    if (params->num_sample_formats) {
        printf(", "XENSND_FIELD_SAMPLE_RATES": ");
        for (i = 0; i < params->num_sample_formats - 1; i++) {
            printf("%s;", libxl_vsnd_pcm_format_to_string(params->sample_formats[i]));
        }
        printf("%s", libxl_vsnd_pcm_format_to_string(params->sample_formats[i]));
    }

    printf("\n");
}

int main_vsndlist(int argc, char **argv)
{
   int opt;
   int i, j, k, n;
   libxl_device_vsnd *vsnds;
   libxl_vsndinfo vsndinfo;

   SWITCH_FOREACH_OPT(opt, "", NULL, "vsnd-list", 1) {
       /* No options */
   }

   for (argv += optind, argc -= optind; argc > 0; --argc, ++argv) {
       uint32_t domid;

       if (libxl_domain_qualifier_to_domid(ctx, *argv, &domid) < 0) {
           fprintf(stderr, "%s is an invalid domain identifier\n", *argv);
           continue;
       }

       vsnds = libxl_device_vsnd_list(ctx, domid, &n);

       if (!vsnds) continue;

       for (i = 0; i < n; i++) {
           libxl_vsndinfo_init(&vsndinfo);
           if (libxl_device_vsnd_getinfo(ctx, domid, &vsnds[i],
                                         &vsndinfo) == 0) {
               printf("\ndevid: %d, be-domid: %d, handle: %d, state: %d, "
                      "be-path: %s, fe-path: %s\n",
                      vsndinfo.devid, vsndinfo.backend_id,
                      vsndinfo.frontend_id, vsndinfo.state,
                      vsndinfo.backend, vsndinfo.frontend);

               printf(XENSND_FIELD_VCARD_SHORT_NAME": \"%s\", "
                      XENSND_FIELD_VCARD_LONG_NAME": \"%s\"",
                      vsnds[i].short_name, vsnds[i].long_name);
               print_params(&vsnds[i].params);

               for (j = 0; j < vsndinfo.num_vsnd_pcms; j++) {
                   libxl_vsnd_pcm *pcm = &vsnds[i].pcms[j];

                   printf("\tpcm: %d, "XENSND_FIELD_DEVICE_NAME": \"%s\"", j, pcm->name);
                   print_params(&pcm->params);

                   for(k = 0; k < vsnds[i].pcms[j].num_vsnd_streams; k++) {
                       libxl_vsnd_stream *stream = &vsnds[i].pcms[j].streams[k];
                       libxl_streaminfo *info = &vsndinfo.pcms[j].streams[k];

                       printf("\t\tstream: %d, "XENSND_FIELD_STREAM_UNIQUE_ID": \"%s\", "
                              XENSND_FIELD_TYPE": %s", k, stream->unique_id,
                              libxl_vsnd_stream_type_to_string(stream->type));
                       print_params(&stream->params);
                       printf("\t\t\t"XENSND_FIELD_EVT_CHNL": %d, "XENSND_FIELD_RING_REF": %d\n",
                              info->req_evtch, info->req_rref);
                   }
               }
           }
           libxl_vsndinfo_dispose(&vsndinfo);
       }
       libxl_device_vsnd_list_free(vsnds, n);
   }
   return 0;
}

int main_vsnddetach(int argc, char **argv)
{
    uint32_t domid, devid;
    int opt, rc;
    libxl_device_vsnd vsnd;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vsnd-detach", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind++]);
    devid = atoi(argv[optind++]);

    libxl_device_vsnd_init(&vsnd);

    if (libxl_devid_to_device_vsnd(ctx, domid, devid, &vsnd)) {
        fprintf(stderr, "Error: Device %d not connected.\n", devid);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl_device_vsnd_remove(ctx, domid, &vsnd, 0);
    if (rc) {
        fprintf(stderr, "libxl_device_vsnd_remove failed.\n");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;

out:
    libxl_device_vsnd_dispose(&vsnd);
    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
