/******************************************************************************
 * sndif.h
 *
 * Unified sound-device I/O interface for Xen guest OSes.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2013-2015 GlobalLogic Inc.
 * Copyright (C) 2016 EPAM Systems Inc.
 *
 * Authors: Oleksandr Andrushchenko <Oleksandr_Andrushchenko@epam.com>
 *          Oleksandr Grytsov <Oleksandr_Grytsov@epam.com>
 *          Oleksandr Dmytryshyn <oleksandr.dmytryshyn@globallogic.com>
 *          Iurii Konovalenko <iurii.konovalenko@globallogic.com>
 */

#ifndef __XEN_PUBLIC_IO_SNDIF_H__
#define __XEN_PUBLIC_IO_SNDIF_H__

#include "ring.h"
#include "../grant_table.h"

/*
 * Front->back notifications: When enqueuing a new request, sending a
 * notification can be made conditional on req_event (i.e., the generic
 * hold-off mechanism provided by the ring macros). Backends must set
 * req_event appropriately (e.g., using RING_FINAL_CHECK_FOR_REQUESTS()).
 *
 * Back->front notifications: When enqueuing a new response, sending a
 * notification can be made conditional on rsp_event (i.e., the generic
 * hold-off mechanism provided by the ring macros). Frontends must set
 * rsp_event appropriately (e.g., using RING_FINAL_CHECK_FOR_RESPONSES()).
 */

/*
 * Feature and Parameter Negotiation
 * =================================
 * The two halves of a Para-virtual sound card driver utilize nodes within the
 * XenStore to communicate capabilities and to negotiate operating parameters.
 * This section enumerates these nodes which reside in the respective front and
 * backend portions of the XenStore, following the XenBus convention.
 *
 * All data in the XenStore is stored as strings.  Nodes specifying numeric
 * values are encoded in decimal.  Integer value ranges listed below are
 * expressed as fixed sized integer types capable of storing the conversion
 * of a properly formated node string, without loss of information.
 *
 *****************************************************************************
 *                            Backend XenBus Nodes
 *****************************************************************************
 *
 *-------------------------------- Addressing ---------------------------------
 *
 * Indices used to address frontends, driver instances, cards,
 * devices and streams.
 *
 * frontend_id
 *      Values:         <uint>
 *
 *      Domain ID of the sound frontend.
 *
 * drv_idx
 *      Values:         <uint>
 *
 *      Zero based contiguous index of the virtualized sound driver instance in
 *      this domain. Multiple PV drivers are allowed in the domain
 *      at the same time.
 *
 * dev_id
 *      Values:         <uint>
 *
 *      Unique device ID.
 *      Doesn't have to be zero based and/or to be contiguous.
 *
 * stream_idx
 *      Values:         <uint>
 *
 *      Zero based contiguous index of the stream of the device.
 *
 * Example for the frontend running in domain 5, instance of the driver
 * in the front is 0 (single or first PV driver), device id 2,
 * first stream (0):
 * /local/domain/<frontend_id>/device/vsnd/<drv_idx>/
 *         device/<dev_id>/stream/<stream_idx>/type = "p"
 * /local/domain/5/device/vsnd/0/device/2/stream/0/type = "p"
 *
 *------------------------------- PCM settings --------------------------------
 *
 * Every virtualized sound frontend has set of devices and streams, each
 * is individually configured. Part of the PCM configuration can be defined at
 * higher level and be fully or partially re-used by the underlying layers.
 * These configuration values are:
 *  o number of channels (min/max)
 *  o supported sample rates
 *  o supported sample formats.
 * E.g. one can define these values for the whole driver, device or stream.
 * Every underlying layer in turn can re-define some or all of them to better
 * fit its needs. For example, driver may define number of channels to be
 * in [1; 8] range, and some particular stream may be limited to [1; 2] only.
 * The rule is that the underlying layer must be a subset of the upper layer
 * range.
 *
 * Note: if any of the values are not defined then PV driver should use
 * its default values instead.
 *
 * channels-min
 *      Values:         <uint>
 *
 *      The minimum amount of channels that is supported.
 *      Must be at least 1. If not defined then use frontend's default.
 *
 * channels-max
 *      Values:         <uint>
 *
 *      The maximum amount of channels that is supported.
 *      Must be at least <channels-min>. If not defined then use frontend's
 *      default.
 *
 * sample-rates
 *      Values:         <list of uints>
 *
 *      List of supported sample rates separated by XENSND_LIST_SEPARATOR.
 *      If not defined then use frontend's default. Sample rates are expressed
 *      as a list of decimal values w/o any ordering requirement.
 *
 * sample-formats
 *      Values:         <list of XENSND_PCM_FORMAT_XXX_STR>
 *
 *      List of supported sample formats separated by XENSND_LIST_SEPARATOR.
 *      If not defined then use frontend's default.
 *
 * buffer-size
 *      Values:         <uint>
 *
 *      The maximum size in octets of the buffer to allocate per stream.
 *
 * Example configuration:
 *
 * Driver configuration used by all streams:
 * /local/domain/5/device/vsnd/0/sample-formats = "s8;u8;s16_le;s16_be"
 * Stream overrides sample rates supported:
 * /local/domain/5/device/vsnd/0/device/2/stream/0/sample-rates =
 *        "8000;22050;44100;48000"
 *
 *----------------------- Virtual sound card settings --------------------------
 * short-name
 *      Values:         <char[32]>
 *
 *      Short name of the virtual sound card. Optional.
 *
 * long-name
 *      Values:         <char[80]>
 *
 *      Long name of the virtual sound card. Optional.
 *
 * For example,
 * /local/domain/5/device/vsnd/0/short-name = "Virtual audio"
 * /local/domain/5/device/vsnd/0/long-name =
 *         "Virtual audio at center stack"
 *
 *----------------------------- Device settings --------------------------------
 * name
 *      Values:         <char[80]>
 *
 *      Name of the sound device within the virtual sound card. Optional.
 *
 * For example,
 * /local/domain/5/device/vsnd/0/device/0/name = "General analog"
 *
 *----------------------------- Stream settings -------------------------------
 *
 * type
 *      Values:         "p", "c"
 *
 *      Stream type: "p" - playback stream, "c" - capture stream
 *
 *      If both capture and playback are needed then two streams need to be
 *      defined under the same device. For example,
 *      /local/domain/5/device/vsnd/0/device/0/stream/0/type = "p"
 *      /local/domain/5/device/vsnd/0/device/0/stream/1/type = "c"
 *
 *****************************************************************************
 *                            Frontend XenBus Nodes
 *****************************************************************************
 *
 *----------------------- Request Transport Parameters -----------------------
 *
 * These are per stream.
 *
 * event-channel
 *      Values:         <uint>
 *
 *      The identifier of the Xen event channel used to signal activity
 *      in the ring buffer.
 *
 * ring-ref
 *      Values:         <uint>
 *
 *      The Xen grant reference granting permission for the backend to map
 *      a sole page in a single page sized ring buffer.
 *
 * index
 *      Values:         <uint>
 *
 *      After stream initialization it is assigned a unique ID (within the front
 *      driver), so every stream of the frontend can be identified by the
 *      backend by this ID. This is not equal to stream_idx as the later is
 *      zero based within a device, but this index is contiguous within the
 *      driver.
 */

/*
 * STATE DIAGRAMS
 *
 *****************************************************************************
 *                                   Startup                                 *
 *****************************************************************************
 *
 * Tool stack creates front and back state nodes with initial state
 * XenbusStateInitialising.
 * Tool stack creates and sets up frontend sound configuration nodes per domain.
 *
 * Front                                Back
 * =================================    =====================================
 * XenbusStateInitialising              XenbusStateInitialising
 *                                       o Query backend device identification
 *                                         data.
 *                                       o Open and validate backend device.
 *                                                      |
 *                                                      |
 *                                                      V
 *                                      XenbusStateInitWait
 *
 * o Query frontend configuration
 * o Allocate and initialize
 *   event channels per configured
 *   playback/capture stream.
 * o Publish transport parameters
 *   that will be in effect during
 *   this connection.
 *              |
 *              |
 *              V
 * XenbusStateInitialised
 *
 *                                       o Query frontend transport parameters.
 *                                       o Connect to the event channels.
 *                                                      |
 *                                                      |
 *                                                      V
 *                                      XenbusStateConnected
 *
 *  o Create and initialize OS
 *  virtual sound device instances
 *  as per configuration.
 *              |
 *              |
 *              V
 * XenbusStateConnected
 *
 *                                      XenbusStateUnknown
 *                                      XenbusStateClosed
 *                                      XenbusStateClosing
 * o Remove virtual sound device
 * o Remove event channels
 *              |
 *              |
 *              V
 * XenbusStateClosed
 *
 */

/*
 * PCM FORMATS
 *
 * XENSND_PCM_FORMAT_<format>[_<endian>]
 *
 * format: <S/U/F><bits> or <name>
 *     S - signed, U - unsigned, F - float
 *     bits - 8, 16, 24, 32
 *     name - MU_LAW, GSM, etc.
 *
 * endian: <LE/BE>, may be absent
 *     LE - Little endian, BE - Big endian
 */
#define XENSND_PCM_FORMAT_S8            0
#define XENSND_PCM_FORMAT_U8            1
#define XENSND_PCM_FORMAT_S16_LE        2
#define XENSND_PCM_FORMAT_S16_BE        3
#define XENSND_PCM_FORMAT_U16_LE        4
#define XENSND_PCM_FORMAT_U16_BE        5
#define XENSND_PCM_FORMAT_S24_LE        6
#define XENSND_PCM_FORMAT_S24_BE        7
#define XENSND_PCM_FORMAT_U24_LE        8
#define XENSND_PCM_FORMAT_U24_BE        9
#define XENSND_PCM_FORMAT_S32_LE        10
#define XENSND_PCM_FORMAT_S32_BE        11
#define XENSND_PCM_FORMAT_U32_LE        12
#define XENSND_PCM_FORMAT_U32_BE        13
#define XENSND_PCM_FORMAT_F32_LE        14 /* 4-byte float, IEEE-754 32-bit, */
#define XENSND_PCM_FORMAT_F32_BE        15 /* range -1.0 to 1.0              */
#define XENSND_PCM_FORMAT_F64_LE        16 /* 8-byte float, IEEE-754 64-bit, */
#define XENSND_PCM_FORMAT_F64_BE        17 /* range -1.0 to 1.0              */
#define XENSND_PCM_FORMAT_IEC958_SUBFRAME_LE 18
#define XENSND_PCM_FORMAT_IEC958_SUBFRAME_BE 19
#define XENSND_PCM_FORMAT_MU_LAW        20
#define XENSND_PCM_FORMAT_A_LAW         21
#define XENSND_PCM_FORMAT_IMA_ADPCM     22
#define XENSND_PCM_FORMAT_MPEG          23
#define XENSND_PCM_FORMAT_GSM           24

/*
 * REQUEST CODES.
 */
#define XENSND_OP_OPEN                  0
#define XENSND_OP_CLOSE                 1
#define XENSND_OP_READ                  2
#define XENSND_OP_WRITE                 3
#define XENSND_OP_SET_VOLUME            4
#define XENSND_OP_GET_VOLUME            5
#define XENSND_OP_MUTE                  6
#define XENSND_OP_UNMUTE                7

/*
 * XENSTORE FIELD AND PATH NAME STRINGS, HELPERS.
 */
#define XENSND_DRIVER_NAME              "vsnd"

#define XENSND_LIST_SEPARATOR           ";"
/* Path entries */
#define XENSND_PATH_DEVICE              "device"
#define XENSND_PATH_STREAM              "stream"
/* Field names */
#define XENSND_FIELD_VCARD_SHORT_NAME   "short-name"
#define XENSND_FIELD_VCARD_LONG_NAME    "long-name"
#define XENSND_FIELD_RING_REF           "ring-ref"
#define XENSND_FIELD_EVT_CHNL           "event-channel"
#define XENSND_FIELD_DEVICE_NAME        "name"
#define XENSND_FIELD_TYPE               "type"
#define XENSND_FIELD_STREAM_INDEX       "index"
#define XENSND_FIELD_CHANNELS_MIN       "channels-min"
#define XENSND_FIELD_CHANNELS_MAX       "channels-max"
#define XENSND_FIELD_SAMPLE_RATES       "sample-rates"
#define XENSND_FIELD_SAMPLE_FORMATS     "sample-formats"
#define XENSND_FIELD_BUFFER_SIZE        "buffer-size"

/* Stream type field values. */
#define XENSND_STREAM_TYPE_PLAYBACK     "p"
#define XENSND_STREAM_TYPE_CAPTURE      "c"
/* Sample rate max string length */
#define XENSND_SAMPLE_RATE_MAX_LEN      6
/* Sample format field values */
#define XENSND_SAMPLE_FORMAT_MAX_LEN    24

#define XENSND_PCM_FORMAT_S8_STR                 "s8"
#define XENSND_PCM_FORMAT_U8_STR                 "u8"
#define XENSND_PCM_FORMAT_S16_LE_STR             "s16_le"
#define XENSND_PCM_FORMAT_S16_BE_STR             "s16_be"
#define XENSND_PCM_FORMAT_U16_LE_STR             "u16_le"
#define XENSND_PCM_FORMAT_U16_BE_STR             "u16_be"
#define XENSND_PCM_FORMAT_S24_LE_STR             "s24_le"
#define XENSND_PCM_FORMAT_S24_BE_STR             "s24_be"
#define XENSND_PCM_FORMAT_U24_LE_STR             "u24_le"
#define XENSND_PCM_FORMAT_U24_BE_STR             "u24_be"
#define XENSND_PCM_FORMAT_S32_LE_STR             "s32_le"
#define XENSND_PCM_FORMAT_S32_BE_STR             "s32_be"
#define XENSND_PCM_FORMAT_U32_LE_STR             "u32_le"
#define XENSND_PCM_FORMAT_U32_BE_STR             "u32_be"
#define XENSND_PCM_FORMAT_F32_LE_STR             "float_le"
#define XENSND_PCM_FORMAT_F32_BE_STR             "float_be"
#define XENSND_PCM_FORMAT_F64_LE_STR             "float64_le"
#define XENSND_PCM_FORMAT_F64_BE_STR             "float64_be"
#define XENSND_PCM_FORMAT_IEC958_SUBFRAME_LE_STR "iec958_subframe_le"
#define XENSND_PCM_FORMAT_IEC958_SUBFRAME_BE_STR "iec958_subframe_be"
#define XENSND_PCM_FORMAT_MU_LAW_STR             "mu_law"
#define XENSND_PCM_FORMAT_A_LAW_STR              "a_law"
#define XENSND_PCM_FORMAT_IMA_ADPCM_STR          "ima_adpcm"
#define XENSND_PCM_FORMAT_MPEG_STR               "mpeg"
#define XENSND_PCM_FORMAT_GSM_STR                "gsm"

/*
 * STATUS RETURN CODES.
 */
/* Operation not supported. */
#define XENSND_RSP_NOTSUPP              (-2)
/* Operation failed for some unspecified reason (e. g. -EIO). */
#define XENSND_RSP_ERROR                (-1)
/* Operation completed successfully. */
#define XENSND_RSP_OKAY                 0

/*
 * Description of the protocol between frontend and backend driver.
 *
 * The two halves of a Para-virtual sound driver communicates with
 * each other using a shared page and an event channel.
 * Shared page contains a ring with request/response packets.
 *
 * All reserved and padding fields in the structures below must be 0.
 *
 * All request packets have the same length (32 octets)
 * All request packets have common header:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                |    operation    |     stream_idx  |
 * +-----------------+-----------------+-----------------+-----------------+
 *   id - uint16_t, private guest value, echoed in response
 *   operation - uint8_t, operation code
 *   stream_idx - uint8_t, index of the stream ("streams_idx" XenStore entry
 *     of the stream)
 *
 *
 * Request open - open a PCM stream for playback or capture:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                | XENSND_OP_OPEN  |     stream_idx  |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                padding                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                pcm_rate                               |
 * +-----------------+-----------------+-----------------+-----------------+
 * |  pcm_format     |  pcm_channels   |             reserved              |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               buffer_sz                               |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                         gref_directory_start                          |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * pcm_rate - uint32_t, stream data rate, Hz
 * pcm_format - uint8_t, XENSND_PCM_FORMAT_XXX value
 * pcm_channels - uint8_t, number of channels of this stream
 * buffer_sz - uint32_t, buffer size to be allocated in octets
 * gref_directory_start - grant_ref_t, a reference to the first shared page
 *   describing shared buffer references. At least one page exists. If shared
 *   buffer size exceeds what can be addressed by this single page, then
 *   reference to the next page must be supplied (see gref_dir_next_page below)
 */

struct xensnd_open_req {
    uint32_t pcm_rate; /* in Hz */
    uint8_t pcm_format;
    uint8_t pcm_channels;
    uint16_t reserved;
    uint32_t buffer_sz;
    grant_ref_t gref_directory_start;
};

/*
 * Shared page for XENSND_OP_OPEN buffer descriptor (gref_directory in the
 *   request) employs a list of pages, describing all pages of the shared data
 *   buffer:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                          gref_dir_next_page                           |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                gref[0]                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                gref[i]                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                gref[N -1]                             |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * gref_dir_next_page - grant_ref_t, reference to the next page describing
 *   page directory. Must be 0 if no more pages in the list.
 * gref[i] - grant_ref_t, reference to a shared page of the buffer
 *   allocated at XENSND_OP_OPEN
 *
 * Number of grant_ref_t entries in the whole page directory is not
 * passed, but instead can be calculated as:
 *   num_grefs_total = DIV_ROUND_UP(XENSND_OP_OPEN.buffer_sz, PAGE_SIZE);
 */

struct xensnd_page_directory {
    grant_ref_t gref_dir_next_page;
    grant_ref_t gref[1]; /* Variable length */
};

/*
 *  Request close - close an opened pcm stream:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                | XENSND_OP_CLOSE |     stream_idx  |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                padding                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 */

struct xensnd_close_req {
    /* place holder, remove if changing the structure */
    uint8_t placeholder;
};

/*
 * Request read/write - used for read (for capture) or write (for playback):
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                |    operation    |     stream_idx  |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                padding                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                offset                                 |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                length                                 |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * operation - XENSND_OP_READ for read or XENSND_OP_WRITE for write
 * offset - uint32_t, read or write data offset within the shared buffer
 *   passed with XENSND_OP_OPEN request
 * length - uint32_t, read or write data length
 */

struct xensnd_rw_req {
    uint32_t offset;
    uint32_t len;
};

/*
 * Request set/get volume - set/get channels' volume of the stream given:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                |    operation    |     stream_idx  |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                padding                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * operation - XENSND_OP_SET_VOLUME for volume set
 *   or XENSND_OP_GET_VOLUME for volume get
 * Buffer passed with XENSND_OP_OPEN is used to exchange volume
 * values:
 *
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               channel[0]                              |
 * +-----------------+-----------------+-----------------+-----------------+
 * +/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               channel[i]                              |
 * +-----------------+-----------------+-----------------+-----------------+
 * +/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 *                  channel[XENSND_OP_OPEN.pcm_channels - 1]               |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * channel[i] - sint32_t, volume of i-th channel
 * Volume is expressed as a signed value in steps of 0.001 dB,
 * while 0 being 0 dB.
 */

struct xensnd_get_vol_req {
    /* place holder, remove if changing the structure */
    uint8_t placeholder;
};

struct xensnd_set_vol_req {
    /* place holder, remove if changing the structure */
    uint8_t placeholder;
};

/*
 * Request mute/unmute - mute/unmute stream:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                |    operation    |     stream_idx  |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                padding                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * operation - XENSND_OP_MUTE for mute or XENSND_OP_UNMUTE for unmute
 * Buffer passed with XENSND_OP_OPEN is used to exchange mute/unmute
 * values:
 *
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |   channel[0]    |   channel[1]    |   channel[2]    |   channel[3]    |
 * +-----------------+-----------------+-----------------+-----------------+
 * +/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |   channel[i]    |   channel[i+1]  |   channel[i+2]  |   channel[i+3]  |
 * +-----------------+-----------------+-----------------+-----------------+
 * +/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 *
 * channel[i] - uint8_t, non-zero if i-th channel needs to be muted/unmuted
 * Number of channels passed is equal to XENSND_OP_OPEN request pcm_channels
 * field
 */

struct xensnd_mute_req {
    /* place holder, remove if changing the structure */
    uint8_t placeholder;
};

struct xensnd_unmute_req {
    /* place holder, remove if changing the structure */
    uint8_t placeholder;
};

/*
 * All response packets have the same length (32 octets)
 *
 * Response for all requests:
 *          0                 1                  2                3        octet
 * +-----------------+-----------------+-----------------+-----------------+
 * |                 id                |    operation    |     stream_idx  |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                                padding                                |
 * +-----------------+-----------------+-----------------+-----------------+
 * |      status     |                      reserved                       |
 * +-----------------+-----------------+-----------------+-----------------+
 * |                              reserved                                 |
 * +-----------------+-----------------+-----------------+-----------------+
 * |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
 * +-----------------+-----------------+-----------------+-----------------+
 * |                               reserved                                |
 * +-----------------+-----------------+-----------------+-----------------+
 *   id - uint16_t, copied from the request
 *   stream_idx - uint8_t, copied from request
 *   operation - uint8_t, XENSND_OP_XXX - copied from request
 *   status - int8_t, response status (XENSND_RSP_???)
 */

struct xensnd_req {
    uint16_t id;
    uint8_t operation;
    uint8_t stream_idx;
    uint32_t reserved;
    union {
        struct xensnd_open_req open;
        struct xensnd_close_req close;
        struct xensnd_rw_req write;
        struct xensnd_rw_req read;
        struct xensnd_get_vol_req get_vol;
        struct xensnd_set_vol_req set_vol;
        struct xensnd_mute_req mute;
        struct xensnd_unmute_req unmute;
        uint8_t padding[24];
    } op;
};

struct xensnd_resp {
    uint16_t id;
    uint8_t operation;
    uint8_t stream_idx;
    int8_t status;
    uint8_t padding[26];
};

DEFINE_RING_TYPES(xen_sndif, struct xensnd_req, struct xensnd_resp);

#endif /* __XEN_PUBLIC_IO_SNDIF_H__ */
