/*
 *  Implementation of the TCG BIOS extension according to the specification
 *  described in
 *  https://www.trustedcomputinggroup.org/specs/PCClient/TCG_PCClientImplementationforBIOS_1-20_1-00.pdf
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */
#include "rombios_compat.h"
#include "util.h"

#include "tpm_drivers.h"
#include "tcgbios.h"

#define STS_VALID                    (1 << 7) /* 0x80 */
#define STS_COMMAND_READY            (1 << 6) /* 0x40 */
#define STS_TPM_GO                   (1 << 5) /* 0x20 */
#define STS_DATA_AVAILABLE           (1 << 4) /* 0x10 */
#define STS_EXPECT                   (1 << 3) /* 0x08 */
#define STS_RESPONSE_RETRY           (1 << 1) /* 0x02 */

#define ACCESS_TPM_REG_VALID_STS     (1 << 7) /* 0x80 */
#define ACCESS_ACTIVE_LOCALITY       (1 << 5) /* 0x20 */
#define ACCESS_BEEN_SEIZED           (1 << 4) /* 0x10 */
#define ACCESS_SEIZE                 (1 << 3) /* 0x08 */
#define ACCESS_PENDING_REQUEST       (1 << 2) /* 0x04 */
#define ACCESS_REQUEST_USE           (1 << 1) /* 0x02 */
#define ACCESS_TPM_ESTABLISHMENT     (1 << 0) /* 0x01 */

static uint32_t tis_wait_sts(uint8_t *addr, uint32_t time,
                             uint8_t mask, uint8_t expect)
{
	uint32_t rc = 0;
	while (time > 0) {
		uint8_t sts = mmio_readb(&addr[TPM_STS]);
		if ((sts & mask) == expect) {
			rc = 1;
			break;
		}
		mssleep(1);
		time--;
	}
	return rc;
}

static uint32_t tis_activate(uint32_t baseaddr)
{
	uint32_t rc = 1;
	uint8_t *tis_addr = (uint8_t*)baseaddr;
	uint8_t acc;
	/* request access to locality */
	tis_addr[TPM_ACCESS] = ACCESS_REQUEST_USE;

	acc = mmio_readb(&tis_addr[TPM_ACCESS]);
	if ((acc & ACCESS_ACTIVE_LOCALITY) != 0) {
		tis_addr[TPM_STS] = STS_COMMAND_READY;
		rc = tis_wait_sts(tis_addr, 100,
		                  STS_COMMAND_READY, STS_COMMAND_READY);
	}
	return rc;
}

static uint32_t tis_ready(uint32_t baseaddr)
{
	uint32_t rc = 0;
	uint8_t *tis_addr = (uint8_t*)baseaddr;

	tis_addr[TPM_STS] = STS_COMMAND_READY;
	rc = tis_wait_sts(tis_addr, 100, STS_COMMAND_READY, STS_COMMAND_READY);

	return rc;
}

static uint32_t tis_senddata(uint32_t baseaddr, unsigned char *data, uint32_t len)
{
	uint32_t rc = 0;
	uint8_t *tis_addr = (uint8_t*)baseaddr;
	uint32_t offset = 0;
	uint32_t end = 0;

	do {
		uint16_t burst = 0;
		uint32_t ctr = 0;
		while (burst == 0 && ctr < 2000) {
			burst = mmio_readw((uint16_t *)&tis_addr[TPM_STS+1]);
			if (burst == 0) {
				mssleep(1);
				ctr++;
			}
		}

		if (burst == 0) {
			rc = TCG_RESPONSE_TIMEOUT;
			break;
		}

		while (1) {
			tis_addr[TPM_DATA_FIFO] = data[offset];
			offset++;
			burst--;

			if (burst == 0 || offset == len) {
				break;
			}
		}

		if (offset == len) {
			end = 1;
		}
	} while (end == 0);

	return rc;
}

static uint32_t tis_readresp(uint32_t baseaddr, unsigned char *buffer, uint32_t len)
{
	uint32_t rc = 0;
	uint32_t offset = 0;
	uint8_t *tis_addr = (uint8_t*)baseaddr;
	uint32_t sts;

	while (offset < len) {
		buffer[offset] = mmio_readb(&tis_addr[TPM_DATA_FIFO]);
		offset++;
		sts = mmio_readb(&tis_addr[TPM_STS]);
		/* data left ? */
		if ((sts & STS_DATA_AVAILABLE) == 0) {
			break;
		}
	}
	return rc;
}


static uint32_t tis_waitdatavalid(uint32_t baseaddr)
{
	uint8_t *tis_addr = (uint8_t*)baseaddr;
	uint32_t rc = 0;
	if (tis_wait_sts(tis_addr, 1000, STS_VALID, STS_VALID) == 0) {
		rc = TCG_NO_RESPONSE;
	}
	return rc;
}

static uint32_t tis_waitrespready(uint32_t baseaddr, uint32_t timeout)
{
	uint32_t rc = 0;
	uint8_t *tis_addr = (uint8_t*)baseaddr;
	tis_addr[TPM_STS] = STS_TPM_GO;
	if (tis_wait_sts(tis_addr, timeout,
	                 STS_DATA_AVAILABLE, STS_DATA_AVAILABLE) == 0) {
		rc = TCG_NO_RESPONSE;
	}
	return rc;
}

/* if device is not there, return '0', '1' otherwise */
static uint32_t tis_probe(uint32_t baseaddr)
{
	uint32_t rc = 0;
	uint8_t *tis_addr = (uint8_t*)baseaddr;
	uint32_t didvid = mmio_readl((uint32_t *)&tis_addr[TPM_DID_VID]);
	if ((didvid != 0) && (didvid != 0xffffffff)) {
		rc = 1;
	}
	return rc;
}


struct tpm_driver tpm_drivers[TPM_NUM_DRIVERS] = {
	{
		.baseaddr      = TPM_TIS_BASE_ADDRESS,
		.activate      = tis_activate,
		.ready         = tis_ready,
		.senddata      = tis_senddata,
		.readresp      = tis_readresp,
		.waitdatavalid = tis_waitdatavalid,
		.waitrespready = tis_waitrespready,
		.probe         = tis_probe,
	},
};
