#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include "tapdisk.h"
#include "blk.h"

int blk_getimagesize(int fd, uint64_t *size)
{
	int rc;

	*size = 0;
	rc = ioctl(fd, BLKGETSIZE, size);
	if (rc) {
		DPRINTF("ERR: BLKGETSIZE failed, couldn't stat image");
		return -EINVAL;
	}

	return 0;
}

int blk_getsectorsize(int fd, uint64_t *sector_size)
{
#if defined(BLKSSZGET)
	int rc;

	*sector_size = DEFAULT_SECTOR_SIZE;
	rc = ioctl(fd, BLKSSZGET, sector_size);
	if (rc) {
		DPRINTF("ERR: BLKSSZGET failed. Falling back to use default sector size");
		*sector_size = DEFAULT_SECTOR_SIZE;
	}

	if (*sector_size != DEFAULT_SECTOR_SIZE)
		DPRINTF("Note: sector size is %"PRIu64" (not %u)\n",
			*sector_size, DEFAULT_SECTOR_SIZE);
#else
	*sector_size = DEFAULT_SECTOR_SIZE;
#endif

	return 0;
}

