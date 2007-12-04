/*
 * tboot.h: shared data structure with MLE and kernel and functions
 *          used by kernel for runtime support
 *
 * Copyright (c) 2006-2007, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __TBOOT_H__
#define __TBOOT_H__

typedef struct __attribute__ ((__packed__)) {
  uint32_t    data1;
  uint16_t    data2;
  uint16_t    data3;
  uint16_t    data4;
  uint8_t     data5[6];
} uuid_t;

/* used to communicate between tboot and the launched kernel (i.e. Xen) */
#define MAX_TB_ACPI_SINFO_SIZE   64

typedef struct __attribute__ ((__packed__)) {
    /* version 0x01+ fields: */
    uuid_t    uuid;              /* {663C8DFF-E8B3-4b82-AABF-19EA4D057A08} */
    uint32_t  version;           /* Version number: 0x01, 0x02, ... */
    uint32_t  log_addr;          /* physical addr of tb_log_t log */
    uint32_t  shutdown_entry32;  /* entry point for tboot shutdown from 32b */
    uint32_t  shutdown_entry64;  /* entry point for tboot shutdown from 64b */
    uint32_t  shutdown_type;     /* type of shutdown (TB_SHUTDOWN_*) */
    uint32_t  s3_tb_wakeup_entry;/* entry point for tboot s3 wake up */
    uint32_t  s3_k_wakeup_entry; /* entry point for xen s3 wake up */
    uint8_t   acpi_sinfo[MAX_TB_ACPI_SINFO_SIZE];
                                 /* where kernel put acpi sleep info in Sx */
    /* version 0x02+ fields: */
    uint32_t  tboot_base;        /* starting addr for tboot */
    uint32_t  tboot_size;        /* size of tboot */
} tboot_shared_t;

#define TB_SHUTDOWN_REBOOT      0
#define TB_SHUTDOWN_S5          1
#define TB_SHUTDOWN_S4          2
#define TB_SHUTDOWN_S3          3
#define TB_SHUTDOWN_HALT        4

/* {663C8DFF-E8B3-4b82-AABF-19EA4D057A08} */
#define TBOOT_SHARED_UUID    { 0x663c8dff, 0xe8b3, 0x4b82, 0xaabf, \
                               { 0x19, 0xea, 0x4d, 0x5, 0x7a, 0x8 } };

extern tboot_shared_t *g_tboot_shared;

void tboot_probe(void);
void tboot_shutdown(uint32_t shutdown_type);
int tboot_in_measured_env(void);

#endif /* __TBOOT_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
