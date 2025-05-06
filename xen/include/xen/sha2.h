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

struct sha2_256_state {
    uint32_t state[SHA2_256_DIGEST_SIZE / sizeof(uint32_t)];
    uint8_t buf[64];
    size_t count; /* Byte count. */
};

void sha2_256_init(struct sha2_256_state *s);
void sha2_256_update(struct sha2_256_state *s, const void *msg, size_t len);
void sha2_256_final(struct sha2_256_state *s,
                    uint8_t digest[SHA2_256_DIGEST_SIZE]);

#endif /* XEN_SHA2_H */
