/*
 * crc32.h for early Linux 2.4.19pre kernel inclusion
 * This defines ether_crc_le() and ether_crc() as inline functions
 * This is slated to change to using the library crc32 functions
 * as kernel 2.5.2 included at some future date.
 */
#ifndef _LINUX_CRC32_H
#define _LINUX_CRC32_H

#include <linux/types.h>

/* The little-endian AUTODIN II ethernet CRC calculation.
   N.B. Do not use for bulk data, use a table-based routine instead.
   This is common code and should be moved to net/core/crc.c */
static unsigned const ethernet_polynomial_le = 0xedb88320U;
static inline unsigned ether_crc_le(int length, unsigned char *data)
{
	unsigned int crc = 0xffffffff;	/* Initial value. */
	while(--length >= 0) {
		unsigned char current_octet = *data++;
		int bit;
		for (bit = 8; --bit >= 0; current_octet >>= 1) {
			if ((crc ^ current_octet) & 1) {
				crc >>= 1;
				crc ^= ethernet_polynomial_le;
			} else
				crc >>= 1;
		}
	}
	return crc;
}

static unsigned const ethernet_polynomial = 0x04c11db7U;
static inline u32 ether_crc(int length, unsigned char *data)
{
	int crc = -1;
	while (--length >= 0) {
		unsigned char current_octet = *data++;
		int bit;
		for (bit = 0; bit < 8; bit++, current_octet >>= 1) {
			crc = (crc << 1) ^
				((crc < 0) ^ (current_octet & 1) ?
				 ethernet_polynomial : 0);
		}
	}
	return crc;
}

#endif /* _LINUX_CRC32_H */
