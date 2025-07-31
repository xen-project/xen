/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2024 SUSE Software Solutions Germany GmbH
 *
 * Interfaces of libxenmanage.
 *
 * libxenmanage provides management functions for the host using stable
 * hypercall interfaces.
 */
#ifndef XENMANAGE_H
#define XENMANAGE_H

#include <stdint.h>

/* Avoid the need to #include <xentoollog.h> */
struct xentoollog_logger;

typedef struct xenmanage_handle xenmanage_handle;

/*
 * Open libxenmanage.
 *
 * Get a handle of the xenmanage library. The handle is required for all
 * further operations of the library.
 * Parameters:
 *   logger:     Logging function to use. If NULL logging is done to stderr.
 *   open_flags: Only 0 supported.
 * Return value: Handle or NULL if error.
 */
xenmanage_handle *xenmanage_open(struct xentoollog_logger *logger,
                                 unsigned int open_flags);

/*
 * Close libxenmanage.
 *
 * Return a handle of the xenmanage library.
 * Parameters:
 *    hdl: Handle obtained by xenmanage_open().
 * Return value: always 0.
 */
int xenmanage_close(xenmanage_handle *hdl);

#define XENMANAGE_GETDOMSTATE_STATE_EXIST     0x0001  /* Domain is existing. */
#define XENMANAGE_GETDOMSTATE_STATE_SHUTDOWN  0x0002  /* Shutdown finished. */
#define XENMANAGE_GETDOMSTATE_STATE_DYING     0x0004  /* Domain dying. */
#define XENMANAGE_GETDOMSTATE_STATE_DEAD      0x0008  /* Domain dead. */

/* Control Domain capability. */
#define XENMANAGE_GETDOMSTATE_CAP_CONTROL     0x0001
/* Hardware Domain capability. */
#define XENMANAGE_GETDOMSTATE_CAP_HARDWARE    0x0002
/* Xenstore Domain capability. */
#define XENMANAGE_GETDOMSTATE_CAP_XENSTORE    0x0004
/*
 * Return state information of an existing domain.
 *
 * Returns the domain state and unique id of the given domain.
 * Parameters:
 *   hdl:       handle returned by xenmanage_open()
 *   domid:     domain id of the domain to get the information for
 *   state:     where to store the state (XENMANAGE_GETDOMSTATE_STATE_ flags,
 *              nothing stored if NULL)
 *   unique_id: where to store the unique id of the domain (nothing stored if
 *              NULL)
 * Return value: 0 if information was stored, -1 else (errno is set)
 */
int xenmanage_get_domain_info(xenmanage_handle *hdl, unsigned int domid,
                              unsigned int *state, unsigned int *caps,
                              uint64_t *unique_id);

/*
 * Return information of a domain having changed state recently.
 *
 * Returns the domain id, state and unique id of a domain having changed
 * state (any of the state bits was modified) since the last time information
 * for that domain was returned by this function. Only usable by callers who
 * have registered the VIRQ_DOM_EXC event (normally Xenstore).
 * Parameters:
 *   hdl:       handle returned by xenmanage_open()
 *   domid:     where to store the domid of the domain (not NULL)
 *   state:     where to store the state (XENMANAGE_GETDOMSTATE_STATE_ flags,
 *              nothing stored if NULL)
 *   caps:      where to store the capabilities (XENMANAGE_GETDOMSTATE_CAP_
 *              flags, nothing stored if NULL)
 *   unique_id: where to store the unique id of the domain (nothing stored if
 *              NULL)
 * Return value: 0 if information was stored, -1 else (errno is set)
 */
int xenmanage_poll_changed_domain(xenmanage_handle *hdl, unsigned int *domid,
                                  unsigned int *state, unsigned int *caps,
                                  uint64_t *unique_id);
#endif /* XENMANAGE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
