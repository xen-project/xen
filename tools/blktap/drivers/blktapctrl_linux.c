
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "tapdisk.h"
#include "blktaplib.h"
#include "blktapctrl.h"

static void make_blktap_dev(char *devname, int major, int minor)
{
	struct stat st;
 
	if (lstat(devname, &st) != 0) {
		/*Need to create device*/
		if (mkdir(BLKTAP_DEV_DIR, 0755) == 0)
			DPRINTF("Created %s directory\n",BLKTAP_DEV_DIR);
		if (mknod(devname, S_IFCHR|0600,
			makedev(major, minor)) == 0)
			DPRINTF("Created %s device\n",devname);
	} else {
		DPRINTF("%s device already exists\n",devname); 
		/* it already exists, but is it the same major number */
		if (((st.st_rdev>>8) & 0xff) != major) {
			DPRINTF("%s has old major %d\n",
				devname,
				(unsigned int)((st.st_rdev >> 8) & 0xff));
			/* only try again if we succed in deleting it */
			if (!unlink(devname))
				make_blktap_dev(devname, major, minor);
		}
	}
}

int blktap_interface_create(int ctlfd, int *major, int *minor, blkif_t *blkif)
{       
        domid_translate_t tr;
        domid_translate_ext_t tr_ext;
        int ret; 
        char *devname;

        if (blkif->be_id >= (1<<28)) {
                /* new-style backend-id, so use the extended structure */
                tr_ext.domid = blkif->domid;
                tr_ext.busid = blkif->be_id;
                ret = ioctl(ctlfd, BLKTAP_IOCTL_NEWINTF_EXT, &tr_ext);
                DPRINTF("Sent domid %d and be_id %d\n", tr_ext.domid,
                        tr_ext.busid);
        }
        else {
                /* old-style backend-id; use the old structure */
                tr.domid = blkif->domid;
                tr.busid = (unsigned short)blkif->be_id;
                ret = ioctl(ctlfd, BLKTAP_IOCTL_NEWINTF, tr);
                DPRINTF("Sent domid %d and be_id %d\n", tr.domid, tr.busid);
        }

        if ( (ret <= 0)||(ret > MAX_TAP_DEV) ) {
                DPRINTF("Incorrect Dev ID [%d]\n",ret);
                return -1;
        }

        *minor = ret;
        *major = ioctl(ctlfd, BLKTAP_IOCTL_MAJOR, ret );
        if (*major < 0) {
                DPRINTF("Incorrect Major ID [%d]\n",*major);
                return -1;
        }

        if (asprintf(&devname,"%s/%s%d",BLKTAP_DEV_DIR, BLKTAP_DEV_NAME, *minor) == -1)
                return -1;
        make_blktap_dev(devname,*major,*minor);
        DPRINTF("Received device id %d and major %d\n",
                *minor, *major);
        return 0;
}


int blktap_interface_open(void)
{
	char *devname;
	int ret;
	int ctlfd;

	/* Attach to blktap0 */
	if (asprintf(&devname,"%s/%s0", BLKTAP_DEV_DIR, BLKTAP_DEV_NAME) == -1)
		goto open_failed;

	ret = xc_find_device_number("blktap0");
	if (ret < 0) {
		DPRINTF("couldn't find device number for 'blktap0'\n");
		goto open_failed;
	}

	blktap_major = major(ret);
	make_blktap_dev(devname,blktap_major, 0);

	ctlfd = open(devname, O_RDWR);
	if (ctlfd == -1) {
		DPRINTF("blktap0 open failed\n");
		goto open_failed;
	}

	return ctlfd;

open_failed:
	return -1;
}
