/******************************************************************************
 * xc_physdev.c
 *
 * API for manipulating physical-device access permissions.
 *
 * Copyright (c) 2004, Rolf Neugebauer (Intel Research Cambridge)
 * Copyright (c) 2004, K A Fraser (University of Cambridge)
 */

#include "xc_private.h"

int xc_physdev_pci_access_modify(int xc_handle,
                                 uint32_t domid,
                                 int bus,
                                 int dev,
                                 int func,
                                 int enable)
{
    errno = ENOSYS;
    return -1;
}
