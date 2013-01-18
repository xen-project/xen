/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * THIS SOFTWARE AND ITS DOCUMENTATION ARE PROVIDED AS IS AND WITHOUT
 * ANY EXPRESS OR IMPLIED WARRANTIES WHATSOEVER. ALL WARRANTIES
 * INCLUDING, BUT NOT LIMITED TO, PERFORMANCE, MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR  PURPOSE, AND NONINFRINGEMENT ARE HEREBY
 * DISCLAIMED. USERS ASSUME THE ENTIRE RISK AND LIABILITY OF USING THE
 * SOFTWARE.
 */

#ifndef NVM_H
#define NVM_H
#include <mini-os/types.h>
#include <xen/xen.h>
#include <tpmfront.h>

#define NVMKEYSZ 32
#define HASHSZ 20
#define HASHKEYSZ (NVMKEYSZ + HASHSZ)

int init_vtpmblk(struct tpmfront_dev* tpmfront_dev);
void shutdown_vtpmblk(void);

/* Encrypts and writes data to blk device */
int write_vtpmblk(struct tpmfront_dev* tpmfront_dev, uint8_t *data, size_t data_length);
/* Reads, Decrypts, and returns data from blk device */
int read_vtpmblk(struct tpmfront_dev* tpmfront_dev, uint8_t **data, size_t *data_length);

#endif
