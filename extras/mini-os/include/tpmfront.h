/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * This code has been derived from drivers/char/tpm_vtpm.c
 * from the xen 2.6.18 linux kernel
 *
 * Copyright (C) 2006 IBM Corporation
 *
 * This code has also been derived from drivers/char/tpm_xen.c
 * from the xen 2.6.18 linux kernel
 *
 * Copyright (c) 2005, IBM Corporation
 *
 * which was itself derived from drivers/xen/netfront/netfront.c
 * from the linux kernel
 *
 * Copyright (c) 2002-2004, K A Fraser
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */
#ifndef TPMFRONT_H
#define TPMFRONT_H

#include <mini-os/types.h>
#include <mini-os/os.h>
#include <mini-os/events.h>
#include <mini-os/wait.h>
#include <xen/xen.h>
#include <xen/io/xenbus.h>
#include <xen/io/tpmif.h>

struct tpmfront_dev {
   grant_ref_t ring_ref;
   evtchn_port_t evtchn;

   tpmif_shared_page_t *page;

   domid_t bedomid;
   char* nodename;
   char* bepath;

   XenbusState state;

   uint8_t waiting;
   struct wait_queue_head waitq;

   uint8_t* respbuf;
   size_t resplen;

#ifdef HAVE_LIBC
   int fd;
#endif

};


/*Initialize frontend */
struct tpmfront_dev* init_tpmfront(const char* nodename);
/*Shutdown frontend */
void shutdown_tpmfront(struct tpmfront_dev* dev);

/* Send a tpm command to the backend and wait for the response
 *
 * @dev - frontend device
 * @req - request buffer
 * @reqlen - length of request buffer
 * @resp - *resp will be set to internal response buffer, don't free it! Value is undefined on error
 * @resplen - *resplen will be set to the length of the response. Value is undefined on error
 *
 * returns 0 on success, non zero on failure.
 * */
int tpmfront_cmd(struct tpmfront_dev* dev, uint8_t* req, size_t reqlen, uint8_t** resp, size_t* resplen);

/* Set the locality used for communicating with a vTPM */
int tpmfront_set_locality(struct tpmfront_dev* dev, int locality);

#ifdef HAVE_LIBC
#include <sys/stat.h>
/* POSIX IO functions:
 * use tpmfront_open() to get a file descriptor to the tpm device
 * use write() on the fd to send a command to the backend. You must
 * include the entire command in a single call to write().
 * use read() on the fd to read the response. You can use
 * fstat() to get the size of the response and lseek() to seek on it.
 */
int tpmfront_open(struct tpmfront_dev* dev);
int tpmfront_posix_read(int fd, uint8_t* buf, size_t count);
int tpmfront_posix_write(int fd, const uint8_t* buf, size_t count);
int tpmfront_posix_fstat(int fd, struct stat* buf);
#endif


#endif
