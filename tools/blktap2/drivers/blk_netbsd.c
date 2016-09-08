#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/disklabel.h>
#include <errno.h>
#include <inttypes.h>
#include "tapdisk.h"
#include "blk.h"

int blk_getimagesize(int fd, uint64_t *size)
{
	int rc;
	struct disklabel dl;

	*size = 0;
	rc = ioctl(fd, DIOCGDINFO, &dl);
	if (rc) {
		DPRINTF("ERR: DIOCGDINFO failed, couldn't stat image");
		return -EINVAL;
	}

	*size = dl.d_secsize * dl.d_secpercyl;

	return 0;
}

int blk_getsectorsize(int fd, uint64_t *sector_size)
{
	int rc;
	struct disklabel dl;

	*sector_size = DEV_BSIZE;
	rc = ioctl(fd, DIOCGDINFO, &dl);
	if (rc) {
		DPRINTF("ERR: DIOCGDINFO failed, couldn't stat image");
		return 0; /* fallback to DEV_BSIZE */
	}

	*sector_size = dl.d_secsize;
	return 0;
}

