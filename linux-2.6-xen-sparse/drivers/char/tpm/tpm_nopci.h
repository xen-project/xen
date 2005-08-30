/*
 * Copyright (C) 2004 IBM Corporation
 *
 * Authors:
 * Leendert van Doorn <leendert@watson.ibm.com>
 * Dave Safford <safford@watson.ibm.com>
 * Reiner Sailer <sailer@watson.ibm.com>
 * Kylene Hall <kjhall@us.ibm.com>
 *
 * Maintained by: <tpmdd_devel@lists.sourceforge.net>
 *
 * Device driver for TCG/TCPA TPM (trusted platform module).
 * Specifications at www.trustedcomputinggroup.org
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/miscdevice.h>

enum {
	TPM_TIMEOUT = 5,	/* msecs */
	TPM_NUM_ATTR = 4
};

/* TPM addresses */
enum {
	TPM_ADDR = 0x4E,
	TPM_DATA = 0x4F
};

/*
 * Chip num is this value or a valid tpm idx in lower two bytes of chip_id
 */
enum tpm_chip_num {
	TPM_ANY_NUM = 0xFFFF,
};

#define TPM_CHIP_NUM_MASK	0x0000ffff

extern ssize_t tpm_show_pubek(struct device *, char *);
extern ssize_t tpm_show_pcrs(struct device *, char *);
extern ssize_t tpm_show_caps(struct device *, char *);
extern ssize_t tpm_store_cancel(struct device *, const char *, size_t);

#define TPM_DEVICE_ATTRS { \
	__ATTR(pubek, S_IRUGO, tpm_show_pubek, NULL), \
	__ATTR(pcrs, S_IRUGO, tpm_show_pcrs, NULL), \
	__ATTR(caps, S_IRUGO, tpm_show_caps, NULL), \
	__ATTR(cancel, S_IWUSR | S_IWGRP, NULL, tpm_store_cancel) }

struct tpm_chip;

struct tpm_vendor_specific {
	u8 req_complete_mask;
	u8 req_complete_val;
	u8 req_canceled;
	u16 base;		/* TPM base address */

	int (*recv) (struct tpm_chip *, u8 *, size_t);
	int (*send) (struct tpm_chip *, u8 *, size_t);
	void (*cancel) (struct tpm_chip *);
	 u8(*status) (struct tpm_chip *);
	struct miscdevice miscdev;
	struct device_attribute attr[TPM_NUM_ATTR];
};

struct tpm_chip {
	struct device *dev;	/* PCI device stuff */

	int dev_num;		/* /dev/tpm# */
	int num_opens;		/* only one allowed */
	int time_expired;

	/* Data passed to and from the tpm via the read/write calls */
	u8 *data_buffer;
	atomic_t data_pending;
	atomic_t data_position;
	struct semaphore buffer_mutex;

	struct timer_list user_read_timer;	/* user needs to claim result */
	struct semaphore tpm_mutex;	/* tpm is processing */

	struct tpm_vendor_specific *vendor;

	struct list_head list;
};

static inline int tpm_read_index(int index)
{
	outb(index, TPM_ADDR);
	return inb(TPM_DATA) & 0xFF;
}

static inline void tpm_write_index(int index, int value)
{
	outb(index, TPM_ADDR);
	outb(value & 0xFF, TPM_DATA);
}

extern void tpm_time_expired(unsigned long);
extern int tpm_lpc_bus_init(struct pci_dev *, u16);

extern int tpm_register_hardware_nopci(struct device *,
				       struct tpm_vendor_specific *);
extern void tpm_remove_hardware(struct device *);
extern int tpm_open(struct inode *, struct file *);
extern int tpm_release(struct inode *, struct file *);
extern ssize_t tpm_write(struct file *, const char __user *, size_t,
			 loff_t *);
extern ssize_t tpm_read(struct file *, char __user *, size_t, loff_t *);
extern int tpm_pcr_extend(u32 chip_id, int pcr_idx, const u8* hash);
extern int tpm_pcr_read( u32 chip_id, int pcr_idx, u8* res_buf, int res_buf_size );

extern int tpm_pm_suspend(struct pci_dev *, u32);
extern int tpm_pm_resume(struct pci_dev *);

/* internal kernel interface */
extern ssize_t tpm_transmit(struct tpm_chip *chip, const char *buf,
			    size_t bufsiz);
extern struct tpm_chip *tpm_chip_lookup(int chip_num);
