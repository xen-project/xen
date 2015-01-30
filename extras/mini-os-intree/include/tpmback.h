/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * This code has been derived from drivers/xen/tpmback/tpmback.c
 * from the xen 2.6.18 linux kernel
 *
 * Copyright (c) 2005, IBM Corporation
 *
 * which was itself derived from drivers/xen/netback/netback.c
 * from the xen 2.6.18 linux kernel
 *
 * Copyright (c) 2002-2004, K A Fraser
 *
 * This code has also been derived from drivers/xen/tpmback/xenbus.c
 * from the xen 2.6.18 linux kernel
 *
 * Copyright (C) 2005 IBM Corporation
 * Copyright (C) 2005 Rusty Russell <rusty@rustcorp.com.au>
 *
 * This code has also been derived from drivers/xen/tpmback/interface.c
 * from the xen 2.6.18 linux kernel
 *
 * Copyright (c) 2005, IBM Corporation
 *
 * which was itself also derived from drvivers/xen/netback/interface.c
 * from the xen 2.6.18 linux kernel
 *
 * Copyright (c) 2004, Keir Fraser
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the License
 */

#include <xen/io/tpmif.h>
#include <xen/io/xenbus.h>
#include <mini-os/types.h>
#include <xen/xen.h>
#ifndef TPMBACK_H
#define TPMBACK_H

struct tpmcmd {
   domid_t domid;		/* Domid of the frontend */
   uint8_t locality;    /* Locality requested by the frontend */
   unsigned int handle;	/* Handle of the frontend */
   void *opaque;        /* Opaque pointer taken from the tpmback instance */

   uint8_t* req;			/* tpm command bits, allocated by driver, DON'T FREE IT */
   unsigned int req_len;		/* Size of the command in buf - set by tpmback driver */
   unsigned int resp_len;	/* Size of the outgoing command,
				   you set this before passing the cmd object to tpmback_resp */
   uint8_t* resp;		/* Buffer for response - YOU MUST ALLOCATE IT, YOU MUST ALSO FREE IT */
};
typedef struct tpmcmd tpmcmd_t;

/* Initialize the tpm backend driver */
void init_tpmback(void (*open_cb)(domid_t, unsigned int), void (*close_cb)(domid_t, unsigned int));

/* Shutdown tpm backend driver */
void shutdown_tpmback(void);

/* Blocks until a tpm command is sent from any front end.
 * Returns a pointer to the tpm command to handle.
 * Do not try to free this pointer or the req buffer
 * This function will return NULL if the tpm backend driver
 * is shutdown or any other error occurs */
tpmcmd_t* tpmback_req_any(void);

/* Blocks until a tpm command from the frontend at domid/handle
 * is sent.
 * Returns NULL if domid/handle is not connected, tpmback is
 * shutdown or shutting down, or if there is an error
 */
tpmcmd_t* tpmback_req(domid_t domid, unsigned int handle);

/* Send the response to the tpm command back to the frontend
 * This function will free the tpmcmd object, but you must free the resp
 * buffer yourself */
void tpmback_resp(tpmcmd_t* tpmcmd);

/* Waits for the first frontend to connect and then sets domid and handle appropriately.
 * If one or more frontends are already connected, this will set domid and handle to one
 * of them arbitrarily. The main use for this function is to wait until a single
 * frontend connection has occured.
 * returns 0 on success, non-zero on failure */
int tpmback_wait_for_frontend_connect(domid_t *domid, unsigned int *handle);

/* returns the number of frontends connected */
int tpmback_num_frontends(void);

/* Returns the uuid of the specified frontend, NULL on error.
 * The return value is internally allocated, so don't free it */
unsigned char* tpmback_get_uuid(domid_t domid, unsigned int handle);

/* Get and set the opaque pointer for a tpmback instance */
void* tpmback_get_opaque(domid_t domid, unsigned int handle);
/* Returns zero if successful, nonzero on failure (no such frontend) */
int tpmback_set_opaque(domid_t domid, unsigned int handle, void* opaque);

/* Get the XSM context of the given domain (using the tpmback event channel) */
int tpmback_get_peercontext(domid_t domid, unsigned int handle, void* buffer, int buflen);
#endif
