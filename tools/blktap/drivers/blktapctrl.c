/*
 * blktapctrl.c
 * 
 * userspace controller for the blktap disks.
 * As requests for new block devices arrive,
 * the controller spawns off a separate process
 * per-disk.
 *
 *
 * Copyright (c) 2005 Julian Chesterfield and Andrew Warfield.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <xenstore.h>
#include <sys/time.h>
#include <syslog.h>
#ifdef MEMSHR
#include <memshr.h>
#endif
#include <sys/stat.h>
                                                                     
#include "blktaplib.h"
#include "blktapctrl.h"
#include "tapdisk.h"
#include "list.h"
#include "xs_api.h" /* for xs_fire_next_watch() */

#define PIDFILE "/var/run/blktapctrl.pid"

#define NUM_POLL_FDS 2
#define MSG_SIZE 4096
#define MAX_TIMEOUT 10
#define MAX_RAND_VAL 0xFFFF
#define MAX_ATTEMPTS 10

int run = 1;
int max_timeout = MAX_TIMEOUT;
int ctlfd = 0;

int blktap_major;

static int open_ctrl_socket(char *devname);
static int write_msg(int fd, int msgtype, void *ptr, void *ptr2);
static int read_msg(int fd, int msgtype, void *ptr);
static driver_list_entry_t *active_disks[MAX_DISK_TYPES];


static unsigned long long tapdisk_get_size(blkif_t *blkif)
{
	image_t *img = (image_t *)blkif->prv;
	return img->size;
}

static unsigned long tapdisk_get_secsize(blkif_t *blkif)
{
	image_t *img = (image_t *)blkif->prv;
	return img->secsize;
}

static unsigned int tapdisk_get_info(blkif_t *blkif)
{
	image_t *img = (image_t *)blkif->prv;
	return img->info;
}

struct blkif_ops tapdisk_ops = {
	.get_size = tapdisk_get_size,
	.get_secsize = tapdisk_get_secsize,
	.get_info = tapdisk_get_info,
};


static void init_driver_list(void)
{
	int i;

	for (i = 0; i < MAX_DISK_TYPES; i++)
		active_disks[i] = NULL;
	return;
}

static void init_rng(void)
{
	static uint32_t seed;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	seed = tv.tv_usec;
	srand48(seed);
	return;
}

static int get_tapdisk_pid(blkif_t *blkif)
{
	int ret;

	if ((ret = write_msg(blkif->fds[WRITE], CTLMSG_PID, blkif, NULL)) 
	    <= 0) {
		DPRINTF("Write_msg failed - CTLMSG_PID(%d)\n", ret);
		return -EINVAL;
	}

	if ((ret = read_msg(blkif->fds[READ], CTLMSG_PID_RSP, blkif))
	     <= 0) {
		DPRINTF("Read_msg failure - CTLMSG_PID(%d)\n", ret);
		return -EINVAL;
	}	
	return 1;
}

/* Look up the disk specified by path: 
 *   if found, dev points to the device string in the path
 *             type is the tapdisk driver type id
 *             blkif is the existing interface if this is a shared driver
 *             and NULL otherwise.
 *   return 0 on success, -1 on error.
 */

static int test_path(char *path, char **dev, int *type, blkif_t **blkif,
	int* use_ioemu)
{
	char *ptr, handle[10];
	int i, size, found = 0;
	size_t handle_len;

	size = sizeof(dtypes)/sizeof(disk_info_t *);
	*type = MAX_DISK_TYPES + 1;
        *blkif = NULL;

	if (!strncmp(path, "tapdisk:", strlen("tapdisk:"))) {
		*use_ioemu = 0;
		path += strlen("tapdisk:");
	} else if (!strncmp(path, "ioemu:", strlen("ioemu:"))) {
		*use_ioemu = 1;
		path += strlen("ioemu:");
	} else {
		// Use the default for the image type
		*use_ioemu = -1;
	}

	if ( (ptr = strstr(path, ":"))!=NULL) {
		handle_len = (ptr - path);
		memcpy(handle, path, handle_len);
		*dev = ptr + 1;
		ptr = handle + handle_len;
		*ptr = '\0';
		DPRINTF("Detected handle: [%s]\n",handle);

		for (i = 0; i < size; i++) {
			if ((strlen(dtypes[i]->handle) == handle_len) &&
					strncmp(handle, dtypes[i]->handle,
					handle_len) == 0) {
                                found = 1;
                        }

			if (found) {
				if (*use_ioemu == -1)
					*use_ioemu = dtypes[i]->use_ioemu;
				*type = dtypes[i]->idnum;
                        
                        if (dtypes[i]->single_handler == 1) {
                                /* Check whether tapdisk process 
                                   already exists */
                                if (active_disks[dtypes[i]->idnum] == NULL) 
                                        *blkif = NULL;
                                else 
                                        *blkif = active_disks[dtypes[i]
                                                             ->idnum]->blkif;
                        }

                        return 0;
                }
            }
        }

        /* Fall-through case, we didn't find a disk driver. */
        DPRINTF("Unknown blktap disk type [%s]!\n",handle);
        *dev = NULL;
        return -1;
}


static void add_disktype(blkif_t *blkif, int type)
{
	driver_list_entry_t *entry, **pprev;

	if (type > MAX_DISK_TYPES)
		return;

	entry = malloc(sizeof(driver_list_entry_t));
	entry->blkif = blkif;
	entry->next  = NULL;

	pprev = &active_disks[type];
	while (*pprev != NULL)
		pprev = &(*pprev)->next;

	*pprev = entry;
	entry->pprev = pprev;
}

static int qemu_instance_has_disks(pid_t pid)
{
	int i;
	int count = 0;
	driver_list_entry_t *entry;

	for (i = 0; i < MAX_DISK_TYPES; i++) {
		entry = active_disks[i];
		while (entry) {
			if ((entry->blkif->tappid == pid) && dtypes[i]->use_ioemu)
				count++;
			entry = entry->next;
		}
	}

	return (count != 0);
}

static int del_disktype(blkif_t *blkif)
{
	driver_list_entry_t *entry, **pprev;
	int type = blkif->drivertype, count = 0, close = 0;

	if (type > MAX_DISK_TYPES)
		return 1;

	pprev = &active_disks[type];
	while ((*pprev != NULL) && ((*pprev)->blkif != blkif))
		pprev = &(*pprev)->next;

	if ((entry = *pprev) == NULL) {
		DPRINTF("DEL_DISKTYPE: No match\n");
		return 1;
	}

	*pprev = entry->next;
	if (entry->next)
		entry->next->pprev = pprev;

	DPRINTF("DEL_DISKTYPE: Freeing entry\n");
	free(entry);

	/*
	 * When using ioemu, all disks of one VM are connected to the same
	 * qemu-dm instance. We may close the file handle only if there is
	 * no other disk left for this domain.
	 */
	if (dtypes[type]->use_ioemu)
		return !qemu_instance_has_disks(blkif->tappid);

	/* Caller should close() if no single controller, or list is empty. */
	return (!dtypes[type]->single_handler || (active_disks[type] == NULL));
}

static int write_msg(int fd, int msgtype, void *ptr, void *ptr2)
{
	blkif_t *blkif;
	blkif_info_t *blk;
	msg_hdr_t *msg;
	msg_newdev_t *msg_dev;
	char *p, *buf, *path;
	int msglen, len, ret;
	fd_set writefds;
	struct timeval timeout;
	image_t *image, *img;
	uint32_t seed;

	blkif = (blkif_t *)ptr;
	blk = blkif->info;
	image = blkif->prv;
	len = 0;

	switch (msgtype)
	{
	case CTLMSG_PARAMS:
		path = (char *)ptr2;
		DPRINTF("Write_msg called: CTLMSG_PARAMS, sending [%s, %s]\n",
			blk->params, path);

		msglen = sizeof(msg_hdr_t) + strlen(path) + 1;
		buf = malloc(msglen);

		/*Assign header fields*/
		msg = (msg_hdr_t *)buf;
		msg->type = CTLMSG_PARAMS;
		msg->len = msglen;
		msg->drivertype = blkif->drivertype;
		msg->readonly = blkif->readonly;

		gettimeofday(&timeout, NULL);
		msg->cookie = blkif->cookie;
		DPRINTF("Generated cookie, %d\n",blkif->cookie);

		/*Copy blk->params to msg*/
		p = buf + sizeof(msg_hdr_t);
		memcpy(p, path, strlen(path) + 1);

		break;

	case CTLMSG_NEWDEV:
		DPRINTF("Write_msg called: CTLMSG_NEWDEV\n");

		msglen = sizeof(msg_hdr_t) + sizeof(msg_newdev_t);
		buf = malloc(msglen);
		
		/*Assign header fields*/
		msg = (msg_hdr_t *)buf;
		msg->type = CTLMSG_NEWDEV;
		msg->len = msglen;
		msg->drivertype = blkif->drivertype;
		msg->cookie = blkif->cookie;
		
		msg_dev = (msg_newdev_t *)(buf + sizeof(msg_hdr_t));
		msg_dev->devnum = blkif->minor;
		msg_dev->domid = blkif->domid;

		break;

	case CTLMSG_CLOSE:
		DPRINTF("Write_msg called: CTLMSG_CLOSE\n");

		msglen = sizeof(msg_hdr_t);
		buf = malloc(msglen);
		
		/*Assign header fields*/
		msg = (msg_hdr_t *)buf;
		msg->type = CTLMSG_CLOSE;
		msg->len = msglen;
		msg->drivertype = blkif->drivertype;
		msg->cookie = blkif->cookie;
		
		break;

	case CTLMSG_PID:
		DPRINTF("Write_msg called: CTLMSG_PID\n");

		msglen = sizeof(msg_hdr_t);
		buf = malloc(msglen);
		
		/*Assign header fields*/
		msg = (msg_hdr_t *)buf;
		msg->type = CTLMSG_PID;
		msg->len = msglen;
		msg->drivertype = blkif->drivertype;
		msg->cookie = blkif->cookie;
		
		break;
		
	default:
		return -1;
	}

	/*Now send the message*/
	ret = 0;
	FD_ZERO(&writefds);
	FD_SET(fd,&writefds);
	timeout.tv_sec = max_timeout; /*Wait for up to max_timeout seconds*/
	timeout.tv_usec = 0;
	if (select(fd+1, (fd_set *) 0, &writefds, 
		  (fd_set *) 0, &timeout) > 0) {
		len = write(fd, buf, msglen);
		if (len == -1) DPRINTF("Write failed: (%d)\n",errno);
	}
	free(buf);

	return len;
}

static int read_msg(int fd, int msgtype, void *ptr)
{
	blkif_t *blkif;
	blkif_info_t *blk;
	msg_hdr_t *msg;
	msg_pid_t *msg_pid;
	char *p, *buf;
	int msglen = MSG_SIZE, len, ret;
	fd_set readfds;
	struct timeval timeout;
	image_t *image, *img;


	blkif = (blkif_t *)ptr;
	blk = blkif->info;
	image = blkif->prv;

	buf = malloc(MSG_SIZE);

	ret = 0;
	FD_ZERO(&readfds);
	FD_SET(fd,&readfds);
	timeout.tv_sec = max_timeout; /*Wait for up to max_timeout seconds*/ 
	timeout.tv_usec = 0;
	if (select(fd+1, &readfds,  (fd_set *) 0,
		  (fd_set *) 0, &timeout) > 0) {
		ret = read(fd, buf, msglen);
	}			
	if (ret > 0) {
		msg = (msg_hdr_t *)buf;
		switch (msg->type)
		{
		case CTLMSG_IMG:
			img = (image_t *)(buf + sizeof(msg_hdr_t));
			image->size = img->size;
			image->secsize = img->secsize;
			image->info = img->info;

			DPRINTF("Received CTLMSG_IMG: %llu, %lu, %u\n",
				image->size, image->secsize, image->info);
			if(msgtype != CTLMSG_IMG) ret = 0;
			break;
			
		case CTLMSG_IMG_FAIL:
			DPRINTF("Received CTLMSG_IMG_FAIL, "
				"unable to open image\n");
			ret = 0;
			break;
				
		case CTLMSG_NEWDEV_RSP:
			DPRINTF("Received CTLMSG_NEWDEV_RSP\n");
			if(msgtype != CTLMSG_NEWDEV_RSP) ret = 0;
			break;
			
		case CTLMSG_NEWDEV_FAIL:
			DPRINTF("Received CTLMSG_NEWDEV_FAIL\n");
			ret = 0;
			break;
			
		case CTLMSG_CLOSE_RSP:
			DPRINTF("Received CTLMSG_CLOSE_RSP\n");
			if (msgtype != CTLMSG_CLOSE_RSP) ret = 0;
			break;

		case CTLMSG_PID_RSP:
			DPRINTF("Received CTLMSG_PID_RSP\n");
			if (msgtype != CTLMSG_PID_RSP) ret = 0;
			else {
				msg_pid = (msg_pid_t *)
					(buf + sizeof(msg_hdr_t));
				blkif->tappid = msg_pid->pid;
				DPRINTF("\tPID: [%d]\n",blkif->tappid);
			}
			break;
		default:
			DPRINTF("UNKNOWN MESSAGE TYPE RECEIVED\n");
			ret = 0;
			break;
		}
	} 
	
	free(buf);
	
	return ret;

}

static int launch_tapdisk_provider(char **argv)
{
	pid_t child;
	
	if ((child = fork()) < 0)
		return -1;

	if (!child) {
		int i;
		for (i = 0 ; i < sysconf(_SC_OPEN_MAX) ; i++)
			if (i != STDIN_FILENO &&
			    i != STDOUT_FILENO &&
			    i != STDERR_FILENO)
				close(i);

		execvp(argv[0], argv);
		DPRINTF("execvp failed: %d (%s)\n", errno, strerror(errno));
		DPRINTF("PATH = %s\n", getenv("PATH"));
		_exit(1);
	} else {
		pid_t got;
		do {
			got = waitpid(child, NULL, 0);
		} while (got != child);
	}
	return child;
}

static int launch_tapdisk(char *wrctldev, char *rdctldev)
{
	char *argv[] = { "tapdisk", wrctldev, rdctldev, NULL };

	if (launch_tapdisk_provider(argv) < 0)
		return -1;

	return 0;
}

static int launch_tapdisk_ioemu(void)
{
	char *argv[] = { "tapdisk-ioemu", NULL };
	return launch_tapdisk_provider(argv);
}

/* 
 * Connect to an ioemu based disk provider (qemu-dm or tapdisk-ioemu)
 *
 * If the domain has a device model, connect to qemu-dm through the
 * domain specific pipe. Otherwise use a single tapdisk-ioemu instance
 * which is represented by domid 0 and provides access for Dom0 and
 * all DomUs without device model.
 */
static int connect_qemu(blkif_t *blkif, int domid)
{
	char *rdctldev, *wrctldev;

	static int tapdisk_ioemu_pid = 0;
	static int dom0_readfd = 0;
	static int dom0_writefd = 0;
	int refresh_pid = 0;

	if (asprintf(&rdctldev, BLKTAP_CTRL_DIR "/qemu-read-%d", domid) < 0)
		return -1;

	if (asprintf(&wrctldev, BLKTAP_CTRL_DIR "/qemu-write-%d", domid) < 0) {
		free(rdctldev);
		return -1;
	}

	DPRINTF("Using qemu blktap pipe: %s\n", rdctldev);
	
	if (domid == 0) {
		/*
		 * tapdisk-ioemu exits as soon as the last image is 
		 * disconnected. Check if it is still running.
		 */
		if (tapdisk_ioemu_pid == 0 || kill(tapdisk_ioemu_pid, 0)) {
			/* No device model and tapdisk-ioemu doesn't run yet */
			DPRINTF("Launching tapdisk-ioemu\n");
			launch_tapdisk_ioemu();
			
			dom0_readfd = open_ctrl_socket(wrctldev);
			dom0_writefd = open_ctrl_socket(rdctldev);

			refresh_pid = 1;
		}

		DPRINTF("Using tapdisk-ioemu connection\n");
		blkif->fds[READ] = dom0_readfd;
		blkif->fds[WRITE] = dom0_writefd;

		if (refresh_pid) {
			get_tapdisk_pid(blkif);
			tapdisk_ioemu_pid = blkif->tappid;
		}

	} else if (access(rdctldev, R_OK | W_OK) == 0) {
		/* Use existing pipe to the device model */
		DPRINTF("Using qemu-dm connection\n");
		blkif->fds[READ] = open_ctrl_socket(wrctldev);
		blkif->fds[WRITE] = open_ctrl_socket(rdctldev);
	} else {
		/* No device model => try with tapdisk-ioemu */
		DPRINTF("No device model\n");
		connect_qemu(blkif, 0);
	}
	
	free(rdctldev);
	free(wrctldev);
	
	if (blkif->fds[READ] == -1 || blkif->fds[WRITE] == -1)
		return -1;

	DPRINTF("Attached to qemu blktap pipes\n");
	return 0;
}

/* Launch tapdisk instance */
static int connect_tapdisk(blkif_t *blkif, int minor)
{
	char *rdctldev = NULL, *wrctldev = NULL;
	int ret = -1;

	DPRINTF("tapdisk process does not exist:\n");

	if (asprintf(&rdctldev,
		     "%s/tapctrlread%d", BLKTAP_CTRL_DIR, minor) == -1)
		goto fail;

	if (asprintf(&wrctldev,
		     "%s/tapctrlwrite%d", BLKTAP_CTRL_DIR, minor) == -1)
		goto fail;
	
	blkif->fds[READ] = open_ctrl_socket(rdctldev);
	blkif->fds[WRITE] = open_ctrl_socket(wrctldev);
	
	if (blkif->fds[READ] == -1 || blkif->fds[WRITE] == -1)
		goto fail;

	/*launch the new process*/
	DPRINTF("Launching process, CMDLINE [tapdisk %s %s]\n",
			wrctldev, rdctldev);

	if (launch_tapdisk(wrctldev, rdctldev) == -1) {
		DPRINTF("Unable to fork, cmdline: [tapdisk %s %s]\n",
				wrctldev, rdctldev);
		goto fail;
	}

	ret = 0;
	
fail:
	if (rdctldev)
		free(rdctldev);

	if (wrctldev)
		free(wrctldev);

	return ret;
}

static int blktapctrl_new_blkif(blkif_t *blkif)
{
	blkif_info_t *blk;
	int major, minor, fd_read, fd_write, type, new;
	char *rdctldev, *wrctldev, *ptr;
	image_t *image;
	blkif_t *exist = NULL;
	static uint16_t next_cookie = 0;
	int use_ioemu;

	DPRINTF("Received a poll for a new vbd\n");
	if ( ((blk=blkif->info) != NULL) && (blk->params != NULL) ) {
		if (blktap_interface_create(ctlfd, &major, &minor, blkif) < 0)
			return -1;

		if (test_path(blk->params, &ptr, &type, &exist, &use_ioemu) != 0) {
                        DPRINTF("Error in blktap device string(%s).\n",
                                blk->params);
                        goto fail;
                }
		blkif->drivertype = type;
		blkif->cookie = next_cookie++;

		if (!exist) {
			if (use_ioemu) {
				if (connect_qemu(blkif, blkif->domid))
					goto fail;
			} else {
				if (connect_tapdisk(blkif, minor))
					goto fail;
			}

		} else {
			DPRINTF("Process exists!\n");
			blkif->fds[READ] = exist->fds[READ];
			blkif->fds[WRITE] = exist->fds[WRITE];
		}

		add_disktype(blkif, type);
		blkif->major = major;
		blkif->minor = minor;

		image = (image_t *)malloc(sizeof(image_t));
		blkif->prv = (void *)image;
		blkif->ops = &tapdisk_ops;

		/*Retrieve the PID of the new process*/
		if (get_tapdisk_pid(blkif) <= 0) {
			DPRINTF("Unable to contact disk process\n");
			goto fail;
		}

		/* Both of the following read and write calls will block up to 
		 * max_timeout val*/
		if (write_msg(blkif->fds[WRITE], CTLMSG_PARAMS, blkif, ptr) 
		    <= 0) {
			DPRINTF("Write_msg failed - CTLMSG_PARAMS\n");
			goto fail;
		}

		if (read_msg(blkif->fds[READ], CTLMSG_IMG, blkif) <= 0) {
			DPRINTF("Read_msg failure - CTLMSG_IMG\n");
			goto fail;
		}

	} else return -1;

	return 0;
fail:
	ioctl(ctlfd, BLKTAP_IOCTL_FREEINTF, minor);
	return -EINVAL;
}

static int map_new_blktapctrl(blkif_t *blkif)
{
	DPRINTF("Received a poll for a new devmap\n");
	if (write_msg(blkif->fds[WRITE], CTLMSG_NEWDEV, blkif, NULL) <= 0) {
		DPRINTF("Write_msg failed - CTLMSG_NEWDEV\n");
		return -EINVAL;
	}

	if (read_msg(blkif->fds[READ], CTLMSG_NEWDEV_RSP, blkif) <= 0) {
		DPRINTF("Read_msg failed - CTLMSG_NEWDEV_RSP\n");
		return -EINVAL;
	}
	DPRINTF("Exiting map_new_blktapctrl\n");

	return blkif->minor - 1;
}

static int unmap_blktapctrl(blkif_t *blkif)
{
	DPRINTF("Unmapping vbd\n");

	if (write_msg(blkif->fds[WRITE], CTLMSG_CLOSE, blkif, NULL) <= 0) {
		DPRINTF("Write_msg failed - CTLMSG_CLOSE\n");
		return -EINVAL;
	}

	if (del_disktype(blkif)) {
		DPRINTF("Closing communication pipe to pid %d\n", blkif->tappid);
		close(blkif->fds[WRITE]);
		close(blkif->fds[READ]);
	}

	return 0;
}

int open_ctrl_socket(char *devname)
{
	int ret;
	int ipc_fd;
	fd_set socks;
	struct timeval timeout;

	if (mkdir(BLKTAP_CTRL_DIR, 0755) == 0)
		DPRINTF("Created %s directory\n", BLKTAP_CTRL_DIR);
	ret = mkfifo(devname,S_IRWXU|S_IRWXG|S_IRWXO);
	if ( (ret != 0) && (errno != EEXIST) ) {
		DPRINTF("ERROR: pipe failed (%d)\n", errno);
		exit(0);
	}

	ipc_fd = open(devname,O_RDWR|O_NONBLOCK);

	if (ipc_fd < 0) {
		DPRINTF("FD open failed\n");
		return -1;
	}

	return ipc_fd;
}

static void print_drivers(void)
{
	int i, size;

	size = sizeof(dtypes)/sizeof(disk_info_t *);
	DPRINTF("blktapctrl: v1.0.0\n");
	for (i = 0; i < size; i++)
		DPRINTF("Found driver: [%s]\n",dtypes[i]->name);
} 

static void write_pidfile(long pid)
{
	char buf[100];
	int len;
	int fd;
	int flags;

	fd = open(PIDFILE, O_RDWR | O_CREAT, 0600);
	if (fd == -1) {
		DPRINTF("Opening pid file failed (%d)\n", errno);
		exit(1);
	}

	/* We exit silently if daemon already running. */
	if (lockf(fd, F_TLOCK, 0) == -1)
		exit(0);

	/* Set FD_CLOEXEC, so that tapdisk doesn't get this file
	   descriptor. */
	if ((flags = fcntl(fd, F_GETFD)) == -1) {
		DPRINTF("F_GETFD failed (%d)\n", errno);
		exit(1);
	}
	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flags) == -1) {
		DPRINTF("F_SETFD failed (%d)\n", errno);
		exit(1);
	}

	len = snprintf(buf, sizeof(buf), "%ld\n", pid);
	if (write(fd, buf, len) != len) {
		DPRINTF("Writing pid file failed (%d)\n", errno);
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	char *devname;
	tapdev_info_t *ctlinfo;
	int tap_pfd, store_pfd, xs_fd, ret, timeout, pfd_count, count=0;
	struct xs_handle *h;
	struct pollfd  pfd[NUM_POLL_FDS];
	pid_t process;
	char buf[128];

	__init_blkif();
	snprintf(buf, sizeof(buf), "BLKTAPCTRL[%d]", getpid());
	openlog(buf, LOG_CONS|LOG_ODELAY, LOG_DAEMON);
	if (daemon(0,0)) {
		DPRINTF("daemon failed (%d)\n", errno);
		goto open_failed;
	}

	print_drivers();
	init_driver_list();
	init_rng();

	register_new_blkif_hook(blktapctrl_new_blkif);
	register_new_devmap_hook(map_new_blktapctrl);
	register_new_unmap_hook(unmap_blktapctrl);

	ctlfd = blktap_interface_open();
	if (ctlfd < 0) {
		DPRINTF("couldn't open blktap interface\n");
		goto open_failed;
	}

#ifdef MEMSHR
	memshr_daemon_initialize();
#endif

 retry:
	/* Set up store connection and watch. */
	h = xs_daemon_open();
	if (h == NULL) {
		DPRINTF("xs_daemon_open failed -- "
			"is xenstore running?\n");
                if (count < MAX_ATTEMPTS) {
                        count++;
                        sleep(2);
                        goto retry;
                } else goto open_failed;
	}
	
	ret = setup_probe_watch(h);
	if (ret != 0) {
		DPRINTF("Failed adding device probewatch\n");
		xs_daemon_close(h);
		goto open_failed;
	}

	ioctl(ctlfd, BLKTAP_IOCTL_SETMODE, BLKTAP_MODE_INTERPOSE );

	process = getpid();
	write_pidfile(process);
	ret = ioctl(ctlfd, BLKTAP_IOCTL_SENDPID, process );

	/*Static pollhooks*/
	pfd_count = 0;
	tap_pfd = pfd_count++;
	pfd[tap_pfd].fd = ctlfd;
	pfd[tap_pfd].events = POLLIN;
	
	store_pfd = pfd_count++;
	pfd[store_pfd].fd = xs_fileno(h);
	pfd[store_pfd].events = POLLIN;

	while (run) {
		timeout = 1000; /*Milliseconds*/
                ret = poll(pfd, pfd_count, timeout);

		if (ret > 0) {
			if (pfd[store_pfd].revents) {
				ret = xs_fire_next_watch(h);
			}
		}
	}

	xs_daemon_close(h);
	ioctl(ctlfd, BLKTAP_IOCTL_SETMODE, BLKTAP_MODE_PASSTHROUGH );
	close(ctlfd);
	closelog();

	return 0;
	
 open_failed:
	DPRINTF("Unable to start blktapctrl\n");
	closelog();
	return -1;
}

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
