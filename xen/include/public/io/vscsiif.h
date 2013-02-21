/******************************************************************************
 * vscsiif.h
 * 
 * Based on the blkif.h code.
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
 * Copyright(c) FUJITSU Limited 2008.
 */

#ifndef __XEN__PUBLIC_IO_SCSI_H__
#define __XEN__PUBLIC_IO_SCSI_H__

#include "ring.h"
#include "../grant_table.h"

/* commands between backend and frontend */
#define VSCSIIF_ACT_SCSI_CDB         1    /* SCSI CDB command */
#define VSCSIIF_ACT_SCSI_ABORT       2    /* SCSI Device(Lun) Abort*/
#define VSCSIIF_ACT_SCSI_RESET       3    /* SCSI Device(Lun) Reset*/
#define VSCSIIF_ACT_SCSI_SG_PRESET   4    /* Preset SG elements */

/*
 * Maximum scatter/gather segments per request.
 *
 * Considering balance between allocating at least 16 "vscsiif_request"
 * structures on one page (4096 bytes) and the number of scatter/gather
 * elements needed, we decided to use 26 as a magic number.
 */
#define VSCSIIF_SG_TABLESIZE             26

/*
 * based on Linux kernel 2.6.18
 */
#define VSCSIIF_MAX_COMMAND_SIZE         16
#define VSCSIIF_SENSE_BUFFERSIZE         96

struct scsiif_request_segment {
    grant_ref_t gref;
    uint16_t offset;
    uint16_t length;
};
typedef struct scsiif_request_segment vscsiif_segment_t;

struct vscsiif_request {
    uint16_t rqid;          /* private guest value, echoed in resp  */
    uint8_t act;            /* command between backend and frontend */
    uint8_t cmd_len;

    uint8_t cmnd[VSCSIIF_MAX_COMMAND_SIZE];
    uint16_t timeout_per_command;     /* The command is issued by twice 
                                         the value in Backend. */
    uint16_t channel, id, lun;
    uint16_t padding;
    uint8_t sc_data_direction;        /* for DMA_TO_DEVICE(1)
                                         DMA_FROM_DEVICE(2)
                                         DMA_NONE(3) requests  */
    uint8_t nr_segments;              /* Number of pieces of scatter-gather */

    vscsiif_segment_t seg[VSCSIIF_SG_TABLESIZE];
    uint32_t reserved[3];
};
typedef struct vscsiif_request vscsiif_request_t;

#define VSCSIIF_SG_LIST_SIZE ((sizeof(vscsiif_request_t) - 4) \
                              / sizeof(vscsiif_segment_t))

struct vscsiif_sg_list {
    /* First two fields must match struct vscsiif_request! */
    uint16_t rqid;          /* private guest value, must match main req */
    uint8_t act;            /* VSCSIIF_ACT_SCSI_SG_PRESET */
    uint8_t nr_segments;    /* Number of pieces of scatter-gather */
    vscsiif_segment_t seg[VSCSIIF_SG_LIST_SIZE];
};
typedef struct vscsiif_sg_list vscsiif_sg_list_t;

struct vscsiif_response {
    uint16_t rqid;
    uint8_t act;               /* valid only when backend supports SG_PRESET */
    uint8_t sense_len;
    uint8_t sense_buffer[VSCSIIF_SENSE_BUFFERSIZE];
    int32_t rslt;
    uint32_t residual_len;     /* request bufflen - 
                                  return the value from physical device */
    uint32_t reserved[36];
};
typedef struct vscsiif_response vscsiif_response_t;

DEFINE_RING_TYPES(vscsiif, struct vscsiif_request, struct vscsiif_response);


#endif  /*__XEN__PUBLIC_IO_SCSI_H__*/
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
