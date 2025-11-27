/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SHA1: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
 */
#ifndef XEN_SHA1_H
#define XEN_SHA1_H

#include <xen/types.h>

#define SHA1_DIGEST_SIZE  20

void sha1(uint8_t digest[SHA1_DIGEST_SIZE], const void *msg, size_t len);

#endif /* XEN_SHA1_H */
