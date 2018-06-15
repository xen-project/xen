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

#include "libxl_internal.h"

#include <xen/io/sndif.h>

static int libxl__device_vsnd_setdefault(libxl__gc *gc, uint32_t domid,
                                         libxl_device_vsnd *vsnd,
                                         bool hotplug)
{
    return libxl__resolve_domid(gc, vsnd->backend_domname,
                                &vsnd->backend_domid);
}

static int libxl__device_from_vsnd(libxl__gc *gc, uint32_t domid,
                                   libxl_device_vsnd *vsnd,
                                   libxl__device *device)
{
   device->backend_devid   = vsnd->devid;
   device->backend_domid   = vsnd->backend_domid;
   device->backend_kind    = LIBXL__DEVICE_KIND_VSND;
   device->devid           = vsnd->devid;
   device->domid           = domid;
   device->kind            = LIBXL__DEVICE_KIND_VSND;

   return 0;
}

static int libxl__vsnd_from_xenstore(libxl__gc *gc, const char *libxl_path,
                                     libxl_devid devid,
                                     libxl_device_vsnd *vsnd)
{
    const char *be_path;
    int rc;

    vsnd->devid = devid;
    rc = libxl__xs_read_mandatory(gc, XBT_NULL,
                                  GCSPRINTF("%s/backend", libxl_path),
                                  &be_path);
    if (rc) goto out;

    rc = libxl__backendpath_parse_domid(gc, be_path, &vsnd->backend_domid);
    if (rc) goto out;

    rc = 0;

out:
    return rc;
}

static void libxl__update_config_vsnd(libxl__gc *gc,
                                      libxl_device_vsnd *dst,
                                      libxl_device_vsnd *src)
{
    dst->devid = src->devid;
}

static int libxl_device_vsnd_compare(libxl_device_vsnd *d1,
                                     libxl_device_vsnd *d2)
{
    return COMPARE_DEVID(d1, d2);
}

static void libxl__device_vsnd_add(libxl__egc *egc, uint32_t domid,
                                   libxl_device_vsnd *vsnd,
                                   libxl__ao_device *aodev)
{
    libxl__device_add_async(egc, domid, &libxl__vsnd_devtype, vsnd, aodev);
}

static unsigned int libxl__rates_to_str_vsnd(char *str, uint32_t *sample_rates,
                                             int num_sample_rates)
{
    unsigned int len;
    int i;

    len = 0;

    if (num_sample_rates == 0) goto out;

    for (i = 0; i < num_sample_rates - 1; i++) {
        if (str) {
            len += sprintf(&str[len], "%u,", sample_rates[i]);
        } else {
            len += snprintf(NULL, 0, "%u,", sample_rates[i]);
        }
    }

    if (str) {
        len += sprintf(&str[len], "%u", sample_rates[i]);
    } else {
        len += snprintf(NULL, 0, "%u", sample_rates[i]);
    }

out:
    return len;
}

static unsigned int libxl__formats_to_str_vsnd(char *str,
                                               libxl_vsnd_pcm_format *sample_formats,
                                               int num_sample_formats)
{
    unsigned int len;
    int i;

    len = 0;

    if (num_sample_formats == 0) goto out;

    for (i = 0; i < num_sample_formats - 1; i++) {
        if (str) {
            len += sprintf(&str[len], "%s,",
                           libxl_vsnd_pcm_format_to_string(sample_formats[i]));
        } else {
            len += snprintf(NULL, 0, "%s,",
                            libxl_vsnd_pcm_format_to_string(sample_formats[i]));
        }
    }

    if (str) {
        len += sprintf(&str[len], "%s",
                       libxl_vsnd_pcm_format_to_string(sample_formats[i]));
    } else {
        len += snprintf(NULL, 0, "%s",
                        libxl_vsnd_pcm_format_to_string(sample_formats[i]));
    }

out:
    return len;
}

static int libxl__set_params_vsnd(libxl__gc *gc, char *path,
                                  libxl_vsnd_params *params, flexarray_t *front)
{
    char *buffer;
    int len;
    int rc;

    if (params->sample_rates) {
        /* calculate required string size */
        len = libxl__rates_to_str_vsnd(NULL, params->sample_rates,
                                       params->num_sample_rates);

        if (len) {
            buffer = libxl__malloc(gc, len + 1);

            libxl__rates_to_str_vsnd(buffer, params->sample_rates,
                                     params->num_sample_rates);
            rc = flexarray_append_pair(front,
                                       GCSPRINTF("%s"XENSND_FIELD_SAMPLE_RATES,
                                                 path), buffer);
            if (rc) goto out;
        }
    }

    if (params->sample_formats) {
        /* calculate required string size */
        len = libxl__formats_to_str_vsnd(NULL, params->sample_formats,
                                         params->num_sample_formats);

        if (len) {
            buffer = libxl__malloc(gc, len + 1);

            libxl__formats_to_str_vsnd(buffer, params->sample_formats,
                                     params->num_sample_formats);
            rc = flexarray_append_pair(front,
                                       GCSPRINTF("%s"XENSND_FIELD_SAMPLE_FORMATS,
                                                 path), buffer);
            if (rc) goto out;
        }
    }

    if (params->channels_min) {
        rc = flexarray_append_pair(front,
                                   GCSPRINTF("%s"XENSND_FIELD_CHANNELS_MIN, path),
                                   GCSPRINTF("%u", params->channels_min));
        if (rc) goto out;
    }

    if (params->channels_max) {
        rc = flexarray_append_pair(front,
                                   GCSPRINTF("%s"XENSND_FIELD_CHANNELS_MAX, path),
                                   GCSPRINTF("%u", params->channels_max));
        if (rc) goto out;
    }

    if (params->buffer_size) {
        rc = flexarray_append_pair(front,
                                   GCSPRINTF("%s"XENSND_FIELD_BUFFER_SIZE, path),
                                   GCSPRINTF("%u", params->buffer_size));
        if (rc) goto out;
    }

    rc = 0;

out:
    return rc;
}

static int libxl__set_streams_vsnd(libxl__gc *gc, char *path,
                                   libxl_vsnd_stream *streams,
                                   int num_streams, flexarray_t *front)
{
    int i;
    int rc;

    for (i = 0; i < num_streams; i++) {
        rc = flexarray_append_pair(front,
                 GCSPRINTF("%s%d/"XENSND_FIELD_STREAM_UNIQUE_ID, path, i),
                 streams[i].unique_id);
        if (rc) goto out;

        const char *type = libxl_vsnd_stream_type_to_string(streams[i].type);

        if (type) {
            rc = flexarray_append_pair(front,
                     GCSPRINTF("%s%d/"XENSND_FIELD_TYPE, path, i),
                     (char *)type);
            if (rc) goto out;
        }

        rc = libxl__set_params_vsnd(gc, GCSPRINTF("%s%d/", path, i),
                                    &streams[i].params, front);
        if (rc) goto out;
    }

    rc = 0;

out:
    return rc;
}

static int libxl__set_pcms_vsnd(libxl__gc *gc, libxl_vsnd_pcm *pcms,
                                int num_pcms, flexarray_t *front)
{
    int i;
    int rc;

    for (i = 0; i < num_pcms; i++) {
        if (pcms[i].name) {
            rc = flexarray_append_pair(front,
                                       GCSPRINTF("%d/"XENSND_FIELD_DEVICE_NAME, i),
                                       pcms[i].name);
            if (rc) goto out;
        }

        char *path = GCSPRINTF("%d/", i);

        rc = libxl__set_params_vsnd(gc, path, &pcms[i].params, front);
        if (rc) goto out;

        rc = libxl__set_streams_vsnd(gc, path, pcms[i].streams,
                                     pcms[i].num_vsnd_streams, front);
        if (rc) goto out;
    }

    rc = 0;

out:
    return rc;
}

static int libxl__set_xenstore_vsnd(libxl__gc *gc, uint32_t domid,
                                    libxl_device_vsnd *vsnd,
                                    flexarray_t *back, flexarray_t *front,
                                    flexarray_t *ro_front)
{
    int rc;

    if (vsnd->long_name) {
        rc = flexarray_append_pair(front, XENSND_FIELD_VCARD_LONG_NAME,
                                   vsnd->long_name);
        if (rc) goto out;
    }

    if (vsnd->short_name) {
        rc = flexarray_append_pair(front, XENSND_FIELD_VCARD_SHORT_NAME,
                                   vsnd->short_name);
        if (rc) goto out;
    }

    rc = libxl__set_params_vsnd(gc, "", &vsnd->params, front);
    if (rc) goto out;

    rc = libxl__set_pcms_vsnd(gc, vsnd->pcms, vsnd->num_vsnd_pcms, front);
    if (rc) goto out;

    rc = 0;

out:
    return rc;
}

static LIBXL_DEFINE_UPDATE_DEVID(vsnd)
static LIBXL_DEFINE_DEVICES_ADD(vsnd)

LIBXL_DEFINE_DEVICE_ADD(vsnd)
LIBXL_DEFINE_DEVICE_REMOVE(vsnd)

DEFINE_DEVICE_TYPE_STRUCT(vsnd, VSND,
    .update_config = (device_update_config_fn_t) libxl__update_config_vsnd,
    .from_xenstore = (device_from_xenstore_fn_t) libxl__vsnd_from_xenstore,
    .set_xenstore_config = (device_set_xenstore_config_fn_t)
                           libxl__set_xenstore_vsnd
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
