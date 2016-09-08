#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stddef.h>

/**
 * md5_sum - MD5 hash for a data block
 * @addr: Pointers to the data area
 * @len: Lengths of the data block
 * @mac: Buffer for the hash
 */
void md5_sum(const uint8_t *addr, const size_t len, uint8_t *mac);

#endif
