/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SHA2-256: https://csrc.nist.gov/pubs/fips/180-2/upd1/final
 */
#ifndef XEN_SHA2_H
#define XEN_SHA2_H

#include <xen/types.h>

#define SHA2_256_DIGEST_SIZE 32

void sha2_256_digest(uint8_t digest[SHA2_256_DIGEST_SIZE],
                     const void *msg, size_t len);

#endif /* XEN_SHA2_H */
