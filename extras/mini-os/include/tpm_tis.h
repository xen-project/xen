/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * This code has been derived from drivers/char/tpm.c
 * from the linux kernel
 *
 * Copyright (C) 2004 IBM Corporation
 *
 * This code has also been derived from drivers/char/tpm/tpm_tis.c
 * from the linux kernel
 *
 * Copyright (C) 2005, 2006 IBM Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the License
 */
#ifndef TPM_TIS_H
#define TPM_TIS_H

#include <mini-os/types.h>
#include <mini-os/byteorder.h>

#define TPM_TIS_EN_LOCL0 1
#define TPM_TIS_EN_LOCL1 (1 << 1)
#define TPM_TIS_EN_LOCL2 (1 << 2)
#define TPM_TIS_EN_LOCL3 (1 << 3)
#define TPM_TIS_EN_LOCL4 (1 << 4)
#define TPM_TIS_EN_LOCLALL (TPM_TIS_EN_LOCL0 | TPM_TIS_EN_LOCL1  | TPM_TIS_EN_LOCL2 | TPM_TIS_EN_LOCL3 | TPM_TIS_EN_LOCL4)
#define TPM_TIS_LOCL_INT_TO_FLAG(x) (1 << x)
#define TPM_BASEADDR 0xFED40000
#define TPM_PROBE_IRQ 0xFFFF

struct tpm_chip;

struct tpm_chip* init_tpm_tis(unsigned long baseaddr, int localities, unsigned int irq);
void shutdown_tpm_tis(struct tpm_chip* tpm);

int tpm_tis_request_locality(struct tpm_chip* tpm, int locality);
int tpm_tis_cmd(struct tpm_chip* tpm, uint8_t* req, size_t reqlen, uint8_t** resp, size_t* resplen);

#ifdef HAVE_LIBC
#include <sys/stat.h>
#include <fcntl.h>
/* POSIX IO functions:
 * use tpm_tis_open() to get a file descriptor to the tpm device
 * use write() on the fd to send a command to the backend. You must
 * include the entire command in a single call to write().
 * use read() on the fd to read the response. You can use
 * fstat() to get the size of the response and lseek() to seek on it.
 */
int tpm_tis_open(struct tpm_chip* tpm);
int tpm_tis_posix_read(int fd, uint8_t* buf, size_t count);
int tpm_tis_posix_write(int fd, const uint8_t* buf, size_t count);
int tpm_tis_posix_fstat(int fd, struct stat* buf);
#endif

#endif
