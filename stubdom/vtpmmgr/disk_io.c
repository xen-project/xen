#include <blkfront.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mini-os/byteorder.h>

#include "vtpm_manager.h"
#include "log.h"
#include "uuid.h"

#include "vtpmmgr.h"
#include "vtpm_disk.h"
#include "disk_tpm.h"
#include "disk_io.h"

static uint8_t disk_staging_buf[4096] __attribute__((aligned(4096)));

static struct blkfront_dev* blkdev;
static int blkfront_fd = -1;

int vtpm_storage_init(void) {
	struct blkfront_info info;
	blkdev = init_blkfront(NULL, &info);
	if (blkdev == NULL)
		return -1;
	blkfront_fd = blkfront_open(blkdev);
	if (blkfront_fd < 0)
		return -1;
	return 0;
}

void* disk_read_sector(sector_t sector)
{
	uint32_t pos = be32_native(sector);
	int rc;
	vtpmloginfo(VTPM_LOG_VTPM, "disk_read_sector %x\n", pos);
	lseek(blkfront_fd, pos * 4096, SEEK_SET);
	rc = read(blkfront_fd, disk_staging_buf, 4096);
	if (rc != 4096)
		abort();
	return disk_staging_buf;
}

void* disk_write_buf(void) { return disk_staging_buf; }

void disk_write_sector(sector_t sector, void* buf, size_t siz)
{
	int rc;
	uint32_t pos = be32_native(sector);
	lseek(blkfront_fd, pos * 4096, SEEK_SET);
	if (siz < 4096) {
		if (buf != disk_staging_buf)
			memcpy(disk_staging_buf, buf, siz);
		memset(disk_staging_buf + siz, 0, 4096 - siz);
		buf = disk_staging_buf;
	} else if (siz > 4096)
		abort();

	rc = write(blkfront_fd, buf, 4096);
	if (rc != 4096)
		abort();
}

void disk_write_barrier(void)
{
	blkfront_sync(blkdev);
}

enum inuse_value {
	UNUSED,
	SLOT_1,
	SLOT_2,
	SHARED
};

/* TODO make this dynamic to support using more than 2MB of disk */
#define DISK_MAX_SECTOR 0x200

/* The first 4 sectors are statically allocated:
 *  0 - disk header (copy 1)
 *  1 - disk header (copy 2)
 *  2 - root sector (copy 1)
 *  3 - root sector (copy 2)
 */
#define FIRST_DYNAMIC_SECTOR 4

static uint8_t sector_inuse_map[DISK_MAX_SECTOR];

static int active_slot(const struct mem_tpm_mgr *mgr)
{
	return 1 + mgr->active_root;
}

void disk_set_used(sector_t loc, const struct mem_tpm_mgr *mgr)
{
	uint32_t s = be32_native(loc);
	if (s > DISK_MAX_SECTOR) {
		printk("Attempted disk_set_used %x\n", s);
		return;
	}
	sector_inuse_map[s] |= active_slot(mgr);
}

void disk_flush_slot(const struct mem_tpm_mgr *mgr)
{
	int i;
	for(i = FIRST_DYNAMIC_SECTOR; i < DISK_MAX_SECTOR; i++)
		sector_inuse_map[i] &= ~active_slot(mgr);
}

sector_t disk_find_free(const struct mem_tpm_mgr *mgr)
{
	int i;
	for(i = FIRST_DYNAMIC_SECTOR; i < DISK_MAX_SECTOR; i++) {
		if (sector_inuse_map[i])
			continue;
		sector_inuse_map[i] = active_slot(mgr);
		return native_be32(i);
	}
	// TODO more graceful error handling (in callers)
	abort();
}
