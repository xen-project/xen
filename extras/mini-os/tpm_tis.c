/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * This code has been derived from drivers/char/tpm.c
 * from the linux kernel
 *
 * Copyright (C) 2004 IBM Corporation
 *
 * This code has also been derived from drivers/char/tpm/tpm_tis.c
 * from the linux kernel
 *
 * Copyright (C) 2005, 2006 IBM Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the License
 */
#include <mini-os/ioremap.h>
#include <mini-os/iorw.h>
#include <mini-os/tpm_tis.h>
#include <mini-os/os.h>
#include <mini-os/sched.h>
#include <mini-os/byteorder.h>
#include <mini-os/events.h>
#include <mini-os/wait.h>
#include <mini-os/xmalloc.h>
#include <errno.h>
#include <stdbool.h>

#ifndef min
	#define min( a, b ) ( ((a) < (b)) ? (a) : (b) )
#endif

#define TPM_HEADER_SIZE 10

#define TPM_BUFSIZE 2048

struct tpm_input_header {
        uint16_t  tag;
        uint32_t  length;
        uint32_t  ordinal;
}__attribute__((packed));

struct tpm_output_header {
        uint16_t  tag;
        uint32_t  length;
        uint32_t  return_code;
}__attribute__((packed));

struct  stclear_flags_t {
        uint16_t  tag;
        uint8_t      deactivated;
        uint8_t      disableForceClear;
        uint8_t      physicalPresence;
        uint8_t      physicalPresenceLock;
        uint8_t      bGlobalLock;
}__attribute__((packed));

struct  tpm_version_t {
        uint8_t      Major;
        uint8_t      Minor;
        uint8_t      revMajor;
        uint8_t      revMinor;
}__attribute__((packed));

struct  tpm_version_1_2_t {
        uint16_t  tag;
        uint8_t      Major;
        uint8_t      Minor;
        uint8_t      revMajor;
        uint8_t      revMinor;
}__attribute__((packed));

struct  timeout_t {
        uint32_t  a;
        uint32_t  b;
        uint32_t  c;
        uint32_t  d;
}__attribute__((packed));

struct duration_t {
        uint32_t  tpm_short;
        uint32_t  tpm_medium;
        uint32_t  tpm_long;
}__attribute__((packed));

struct permanent_flags_t {
        uint16_t  tag;
        uint8_t      disable;
        uint8_t      ownership;
        uint8_t      deactivated;
        uint8_t      readPubek;
        uint8_t      disableOwnerClear;
        uint8_t      allowMaintenance;
        uint8_t      physicalPresenceLifetimeLock;
        uint8_t      physicalPresenceHWEnable;
        uint8_t      physicalPresenceCMDEnable;
        uint8_t      CEKPUsed;
        uint8_t      TPMpost;
        uint8_t      TPMpostLock;
        uint8_t      FIPS;
        uint8_t      operator;
        uint8_t      enableRevokeEK;
        uint8_t      nvLocked;
        uint8_t      readSRKPub;
        uint8_t      tpmEstablished;
        uint8_t      maintenanceDone;
        uint8_t      disableFullDALogicInfo;
}__attribute__((packed));

typedef union {
        struct  permanent_flags_t perm_flags;
        struct  stclear_flags_t stclear_flags;
        bool    owned;
        uint32_t  num_pcrs;
        struct  tpm_version_t   tpm_version;
        struct  tpm_version_1_2_t tpm_version_1_2;
        uint32_t  manufacturer_id;
        struct timeout_t  timeout;
        struct duration_t duration;
} cap_t;

struct  tpm_getcap_params_in {
        uint32_t  cap;
        uint32_t  subcap_size;
        uint32_t  subcap;
}__attribute__((packed));

struct  tpm_getcap_params_out {
        uint32_t  cap_size;
        cap_t   cap;
}__attribute__((packed));

struct  tpm_readpubek_params_out {
        uint8_t      algorithm[4];
        uint8_t      encscheme[2];
        uint8_t      sigscheme[2];
        uint32_t  paramsize;
        uint8_t      parameters[12]; /*assuming RSA*/
        uint32_t  keysize;
        uint8_t      modulus[256];
        uint8_t      checksum[20];
}__attribute__((packed));

typedef union {
        struct  tpm_input_header in;
        struct  tpm_output_header out;
} tpm_cmd_header;

#define TPM_DIGEST_SIZE 20
struct tpm_pcrread_out {
        uint8_t      pcr_result[TPM_DIGEST_SIZE];
}__attribute__((packed));

struct tpm_pcrread_in {
        uint32_t  pcr_idx;
}__attribute__((packed));

struct tpm_pcrextend_in {
        uint32_t  pcr_idx;
        uint8_t      hash[TPM_DIGEST_SIZE];
}__attribute__((packed));

typedef union {
        struct  tpm_getcap_params_out getcap_out;
        struct  tpm_readpubek_params_out readpubek_out;
        uint8_t      readpubek_out_buffer[sizeof(struct tpm_readpubek_params_out)];
        struct  tpm_getcap_params_in getcap_in;
        struct  tpm_pcrread_in  pcrread_in;
        struct  tpm_pcrread_out pcrread_out;
        struct  tpm_pcrextend_in pcrextend_in;
} tpm_cmd_params;

struct tpm_cmd_t {
        tpm_cmd_header  header;
        tpm_cmd_params  params;
}__attribute__((packed));


enum tpm_duration {
   TPM_SHORT = 0,
   TPM_MEDIUM = 1,
   TPM_LONG = 2,
   TPM_UNDEFINED,
};

#define TPM_MAX_ORDINAL 243
#define TPM_MAX_PROTECTED_ORDINAL 12
#define TPM_PROTECTED_ORDINAL_MASK 0xFF

extern const uint8_t tpm_protected_ordinal_duration[TPM_MAX_PROTECTED_ORDINAL];
extern const uint8_t tpm_ordinal_duration[TPM_MAX_ORDINAL];

#define TPM_DIGEST_SIZE 20
#define TPM_ERROR_SIZE 10
#define TPM_RET_CODE_IDX 6

/* tpm_capabilities */
#define TPM_CAP_FLAG cpu_to_be32(4)
#define TPM_CAP_PROP cpu_to_be32(5)
#define CAP_VERSION_1_1 cpu_to_be32(0x06)
#define CAP_VERSION_1_2 cpu_to_be32(0x1A)

/* tpm_sub_capabilities */
#define TPM_CAP_PROP_PCR cpu_to_be32(0x101)
#define TPM_CAP_PROP_MANUFACTURER cpu_to_be32(0x103)
#define TPM_CAP_FLAG_PERM cpu_to_be32(0x108)
#define TPM_CAP_FLAG_VOL cpu_to_be32(0x109)
#define TPM_CAP_PROP_OWNER cpu_to_be32(0x111)
#define TPM_CAP_PROP_TIS_TIMEOUT cpu_to_be32(0x115)
#define TPM_CAP_PROP_TIS_DURATION cpu_to_be32(0x120)


#define TPM_INTERNAL_RESULT_SIZE 200
#define TPM_TAG_RQU_COMMAND cpu_to_be16(193)
#define TPM_ORD_GET_CAP cpu_to_be32(101)

extern const struct tpm_input_header tpm_getcap_header;



const uint8_t tpm_protected_ordinal_duration[TPM_MAX_PROTECTED_ORDINAL] = {
   TPM_UNDEFINED,          /* 0 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,          /* 5 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_SHORT,              /* 10 */
   TPM_SHORT,
};

const uint8_t tpm_ordinal_duration[TPM_MAX_ORDINAL] = {
   TPM_UNDEFINED,          /* 0 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,          /* 5 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_SHORT,              /* 10 */
   TPM_SHORT,
   TPM_MEDIUM,
   TPM_LONG,
   TPM_LONG,
   TPM_MEDIUM,             /* 15 */
   TPM_SHORT,
   TPM_SHORT,
   TPM_MEDIUM,
   TPM_LONG,
   TPM_SHORT,              /* 20 */
   TPM_SHORT,
   TPM_MEDIUM,
   TPM_MEDIUM,
   TPM_MEDIUM,
   TPM_SHORT,              /* 25 */
   TPM_SHORT,
   TPM_MEDIUM,
   TPM_SHORT,
   TPM_SHORT,
   TPM_MEDIUM,             /* 30 */
   TPM_LONG,
   TPM_MEDIUM,
   TPM_SHORT,
   TPM_SHORT,
   TPM_SHORT,              /* 35 */
   TPM_MEDIUM,
   TPM_MEDIUM,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_MEDIUM,             /* 40 */
   TPM_LONG,
   TPM_MEDIUM,
   TPM_SHORT,
   TPM_SHORT,
   TPM_SHORT,              /* 45 */
   TPM_SHORT,
   TPM_SHORT,
   TPM_SHORT,
   TPM_LONG,
   TPM_MEDIUM,             /* 50 */
   TPM_MEDIUM,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,          /* 55 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_MEDIUM,             /* 60 */
   TPM_MEDIUM,
   TPM_MEDIUM,
   TPM_SHORT,
   TPM_SHORT,
   TPM_MEDIUM,             /* 65 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_SHORT,              /* 70 */
   TPM_SHORT,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,          /* 75 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_LONG,               /* 80 */
   TPM_UNDEFINED,
   TPM_MEDIUM,
   TPM_LONG,
   TPM_SHORT,
   TPM_UNDEFINED,          /* 85 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_SHORT,              /* 90 */
   TPM_SHORT,
   TPM_SHORT,
   TPM_SHORT,
   TPM_SHORT,
   TPM_UNDEFINED,          /* 95 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_MEDIUM,             /* 100 */
   TPM_SHORT,
   TPM_SHORT,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,          /* 105 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_SHORT,              /* 110 */
   TPM_SHORT,
   TPM_SHORT,
   TPM_SHORT,
   TPM_SHORT,
   TPM_SHORT,              /* 115 */
   TPM_SHORT,
   TPM_SHORT,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_LONG,               /* 120 */
   TPM_LONG,
   TPM_MEDIUM,
   TPM_UNDEFINED,
   TPM_SHORT,
   TPM_SHORT,              /* 125 */
   TPM_SHORT,
   TPM_LONG,
   TPM_SHORT,
   TPM_SHORT,
   TPM_SHORT,              /* 130 */
   TPM_MEDIUM,
   TPM_UNDEFINED,
   TPM_SHORT,
   TPM_MEDIUM,
   TPM_UNDEFINED,          /* 135 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_SHORT,              /* 140 */
   TPM_SHORT,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,          /* 145 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_SHORT,              /* 150 */
   TPM_MEDIUM,
   TPM_MEDIUM,
   TPM_SHORT,
   TPM_SHORT,
   TPM_UNDEFINED,          /* 155 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_SHORT,              /* 160 */
   TPM_SHORT,
   TPM_SHORT,
   TPM_SHORT,
   TPM_UNDEFINED,
   TPM_UNDEFINED,          /* 165 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_LONG,               /* 170 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,          /* 175 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_MEDIUM,             /* 180 */
   TPM_SHORT,
   TPM_MEDIUM,
   TPM_MEDIUM,
   TPM_MEDIUM,
   TPM_MEDIUM,             /* 185 */
   TPM_SHORT,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,          /* 190 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,          /* 195 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_SHORT,              /* 200 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_SHORT,
   TPM_SHORT,              /* 205 */
   TPM_SHORT,
   TPM_SHORT,
   TPM_SHORT,
   TPM_SHORT,
   TPM_MEDIUM,             /* 210 */
   TPM_UNDEFINED,
   TPM_MEDIUM,
   TPM_MEDIUM,
   TPM_MEDIUM,
   TPM_UNDEFINED,          /* 215 */
   TPM_MEDIUM,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_SHORT,
   TPM_SHORT,              /* 220 */
   TPM_SHORT,
   TPM_SHORT,
   TPM_SHORT,
   TPM_SHORT,
   TPM_UNDEFINED,          /* 225 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_SHORT,              /* 230 */
   TPM_LONG,
   TPM_MEDIUM,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,          /* 235 */
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_UNDEFINED,
   TPM_SHORT,              /* 240 */
   TPM_UNDEFINED,
   TPM_MEDIUM,
};

const struct tpm_input_header tpm_getcap_header = {
        .tag = TPM_TAG_RQU_COMMAND,
        .length = cpu_to_be32(22),
        .ordinal = TPM_ORD_GET_CAP
};


enum tis_access {
   TPM_ACCESS_VALID = 0x80,
   TPM_ACCESS_ACTIVE_LOCALITY = 0x20,	/* (R) */
   TPM_ACCESS_RELINQUISH_LOCALITY = 0x20,/* (W) */
   TPM_ACCESS_REQUEST_PENDING = 0x04,	/* (W) */
   TPM_ACCESS_REQUEST_USE = 0x02,	/* (W) */
};

enum tis_status {
   TPM_STS_VALID = 0x80,		/* (R) */
   TPM_STS_COMMAND_READY = 0x40,	/* (R) */
   TPM_STS_DATA_AVAIL = 0x10,		/* (R) */
   TPM_STS_DATA_EXPECT = 0x08,		/* (R) */
   TPM_STS_GO = 0x20,			/* (W) */
};

enum tis_int_flags {
   TPM_GLOBAL_INT_ENABLE = 0x80000000,
   TPM_INTF_BURST_COUNT_STATIC = 0x100,
   TPM_INTF_CMD_READY_INT = 0x080,
   TPM_INTF_INT_EDGE_FALLING = 0x040,
   TPM_INTF_INT_EDGE_RISING = 0x020,
   TPM_INTF_INT_LEVEL_LOW = 0x010,
   TPM_INTF_INT_LEVEL_HIGH = 0x008,
   TPM_INTF_LOCALITY_CHANGE_INT = 0x004,
   TPM_INTF_STS_VALID_INT = 0x002,
   TPM_INTF_DATA_AVAIL_INT = 0x001,
};

enum tis_defaults {
   TIS_MEM_BASE = 0xFED40000,
   TIS_MEM_LEN  = 0x5000,
   TIS_SHORT_TIMEOUT = 750, /*ms*/
   TIS_LONG_TIMEOUT = 2000, /*2 sec */
};

#define TPM_TIMEOUT 5

#define TPM_ACCESS(t, l)                   (((uint8_t*)t->pages[l]) + 0x0000)
#define TPM_INT_ENABLE(t, l)               ((uint32_t*)(((uint8_t*)t->pages[l]) + 0x0008))
#define TPM_INT_VECTOR(t, l)               (((uint8_t*)t->pages[l]) + 0x000C)
#define TPM_INT_STATUS(t, l)               (((uint8_t*)t->pages[l]) + 0x0010)
#define TPM_INTF_CAPS(t, l)                ((uint32_t*)(((uint8_t*)t->pages[l]) + 0x0014))
#define TPM_STS(t, l)                      ((uint8_t*)(((uint8_t*)t->pages[l]) + 0x0018))
#define TPM_DATA_FIFO(t, l)                (((uint8_t*)t->pages[l]) + 0x0024)

#define TPM_DID_VID(t, l)                  ((uint32_t*)(((uint8_t*)t->pages[l]) + 0x0F00))
#define TPM_RID(t, l)                      (((uint8_t*)t->pages[l]) + 0x0F04)

struct tpm_chip {
   int enabled_localities;
   int locality;
   unsigned long baseaddr;
   uint8_t* pages[5];
   int did, vid, rid;

   uint8_t data_buffer[TPM_BUFSIZE];
   int data_len;

   s_time_t timeout_a, timeout_b, timeout_c, timeout_d;
   s_time_t duration[3];

#ifdef HAVE_LIBC
   int fd;
#endif

   unsigned int irq;
   struct wait_queue_head read_queue;
   struct wait_queue_head int_queue;
};


static void __init_tpm_chip(struct tpm_chip* tpm) {
   tpm->enabled_localities = TPM_TIS_EN_LOCLALL;
   tpm->locality = -1;
   tpm->baseaddr = 0;
   tpm->pages[0] = tpm->pages[1] = tpm->pages[2] = tpm->pages[3] = tpm->pages[4] = NULL;
   tpm->vid = 0;
   tpm->did = 0;
   tpm->irq = 0;
   init_waitqueue_head(&tpm->read_queue);
   init_waitqueue_head(&tpm->int_queue);

   tpm->data_len = -1;

#ifdef HAVE_LIBC
   tpm->fd = -1;
#endif
}

/*
 * Returns max number of nsecs to wait
 */
s_time_t tpm_calc_ordinal_duration(struct tpm_chip *chip,
      uint32_t ordinal)
{
   int duration_idx = TPM_UNDEFINED;
   s_time_t duration = 0;

   if (ordinal < TPM_MAX_ORDINAL)
      duration_idx = tpm_ordinal_duration[ordinal];
   else if ((ordinal & TPM_PROTECTED_ORDINAL_MASK) <
	 TPM_MAX_PROTECTED_ORDINAL)
      duration_idx =
	 tpm_protected_ordinal_duration[ordinal &
	 TPM_PROTECTED_ORDINAL_MASK];

   if (duration_idx != TPM_UNDEFINED) {
      duration = chip->duration[duration_idx];
   }

   if (duration <= 0) {
      return SECONDS(120);
   }
   else
   {
      return duration;
   }
}


static int locality_enabled(struct tpm_chip* tpm, int l) {
   return tpm->enabled_localities & (1 << l);
}

static int check_locality(struct tpm_chip* tpm, int l) {
   if(locality_enabled(tpm, l) && (ioread8(TPM_ACCESS(tpm, l)) &
	    (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) ==
	 (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) {
      return l;
   }
   return -1;
}

void release_locality(struct tpm_chip* tpm, int l, int force)
{
   if (locality_enabled(tpm, l) && (force || (ioread8(TPM_ACCESS(tpm, l)) &
	       (TPM_ACCESS_REQUEST_PENDING | TPM_ACCESS_VALID)) ==
	    (TPM_ACCESS_REQUEST_PENDING | TPM_ACCESS_VALID))) {
      iowrite8(TPM_ACCESS(tpm, l), TPM_ACCESS_RELINQUISH_LOCALITY);
   }
}

int tpm_tis_request_locality(struct tpm_chip* tpm, int l) {

   s_time_t stop;
   /*Make sure locality is valid */
   if(!locality_enabled(tpm, l)) {
      printk("tpm_tis_change_locality() Tried to change to locality %d, but it is disabled or invalid!\n", l);
      return -1;
   }
   /* Check if we already have the current locality */
   if(check_locality(tpm, l) >= 0) {
      return tpm->locality = l;
   }
   /* Set the new locality*/
   iowrite8(TPM_ACCESS(tpm, l), TPM_ACCESS_REQUEST_USE);

   if(tpm->irq) {
      /* Wait for interrupt */
      wait_event_deadline(tpm->int_queue, (check_locality(tpm, l) >= 0), NOW() + tpm->timeout_a);

      /* FIXME: Handle timeout event, should return error in that case */
      return l;
   } else {
      /* Wait for burstcount */
      stop = NOW() + tpm->timeout_a;
      do {
	 if(check_locality(tpm, l) >= 0) {
	    return tpm->locality = l;
	 }
	 msleep(TPM_TIMEOUT);
      } while(NOW() < stop);
   }

   printk("REQ LOCALITY FAILURE\n");
   return -1;
}

static uint8_t tpm_tis_status(struct tpm_chip* tpm) {
   return ioread8(TPM_STS(tpm, tpm->locality));
}

/* This causes the current command to be aborted */
static void tpm_tis_ready(struct tpm_chip* tpm) {
   iowrite8(TPM_STS(tpm, tpm->locality), TPM_STS_COMMAND_READY);
}
#define tpm_tis_cancel_cmd(v) tpm_tis_ready(v)

static int get_burstcount(struct tpm_chip* tpm) {
   s_time_t stop;
   int burstcnt;

   stop = NOW() + tpm->timeout_d;
   do {
      burstcnt = ioread8((TPM_STS(tpm, tpm->locality) + 1));
      burstcnt += ioread8(TPM_STS(tpm, tpm->locality) + 2) << 8;

      if (burstcnt) {
	 return burstcnt;
      }
      msleep(TPM_TIMEOUT);
   } while(NOW() < stop);
   return -EBUSY;
}

static int wait_for_stat(struct tpm_chip* tpm, uint8_t mask,
      unsigned long timeout, struct wait_queue_head* queue) {
   s_time_t stop;
   uint8_t status;

   status = tpm_tis_status(tpm);
   if((status & mask) == mask) {
      return 0;
   }

   if(tpm->irq) {
      wait_event_deadline(*queue, ((tpm_tis_status(tpm) & mask) == mask), timeout);
      /* FIXME: Check for timeout and return -ETIME */
      return 0;
   } else {
      stop = NOW() + timeout;
      do {
	 msleep(TPM_TIMEOUT);
	 status = tpm_tis_status(tpm);
	 if((status & mask) == mask)
	    return 0;
      } while( NOW() < stop);
   }
   return -ETIME;
}

static int recv_data(struct tpm_chip* tpm, uint8_t* buf, size_t count) {
   int size = 0;
   int burstcnt;
   while( size < count &&
	 wait_for_stat(tpm,
	    TPM_STS_DATA_AVAIL | TPM_STS_VALID,
	    tpm->timeout_c,
	    &tpm->read_queue)
	 == 0) {
      burstcnt = get_burstcount(tpm);
      for(; burstcnt > 0 && size < count; --burstcnt)
      {
	 buf[size++] = ioread8(TPM_DATA_FIFO(tpm, tpm->locality));
      }
   }
   return size;
}

int tpm_tis_recv(struct tpm_chip* tpm, uint8_t* buf, size_t count) {
   int size = 0;
   int expected, status;

   if (count < TPM_HEADER_SIZE) {
      size = -EIO;
      goto out;
   }

   /* read first 10 bytes, including tag, paramsize, and result */
   if((size =
	    recv_data(tpm, buf, TPM_HEADER_SIZE)) < TPM_HEADER_SIZE) {
      printk("Error reading tpm cmd header\n");
      goto out;
   }

   expected = be32_to_cpu(*((uint32_t*)(buf + 2)));
   if(expected > count) {
      size = -EIO;
      goto out;
   }

   if((size += recv_data(tpm, & buf[TPM_HEADER_SIZE],
	       expected - TPM_HEADER_SIZE)) < expected) {
      printk("Unable to read rest of tpm command size=%d expected=%d\n", size, expected);
      size = -ETIME;
      goto out;
   }

   wait_for_stat(tpm, TPM_STS_VALID, tpm->timeout_c, &tpm->int_queue);
   status = tpm_tis_status(tpm);
   if(status & TPM_STS_DATA_AVAIL) {
      printk("Error: left over data\n");
      size = -EIO;
      goto out;
   }

out:
   tpm_tis_ready(tpm);
   release_locality(tpm, tpm->locality, 0);
   return size;
}
int tpm_tis_send(struct tpm_chip* tpm, uint8_t* buf, size_t len) {
   int rc;
   int status, burstcnt = 0;
   int count = 0;
   uint32_t ordinal;

   if(tpm_tis_request_locality(tpm, tpm->locality) < 0) {
      return -EBUSY;
   }

   status = tpm_tis_status(tpm);
   if((status & TPM_STS_COMMAND_READY) == 0) {
      tpm_tis_ready(tpm);
      if(wait_for_stat(tpm, TPM_STS_COMMAND_READY, tpm->timeout_b, &tpm->int_queue) < 0) {
	 rc = -ETIME;
	 goto out_err;
      }
   }

   while(count < len - 1) {
      burstcnt = get_burstcount(tpm);
      for(;burstcnt > 0 && count < len -1; --burstcnt) {
	 iowrite8(TPM_DATA_FIFO(tpm, tpm->locality), buf[count++]);
      }

      wait_for_stat(tpm, TPM_STS_VALID, tpm->timeout_c, &tpm->int_queue);
      status = tpm_tis_status(tpm);
      if((status & TPM_STS_DATA_EXPECT) == 0) {
	 rc = -EIO;
	 goto out_err;
      }
   }

   /*Write last byte*/
   iowrite8(TPM_DATA_FIFO(tpm, tpm->locality), buf[count]);
   wait_for_stat(tpm, TPM_STS_VALID, tpm->timeout_c, &tpm->read_queue);
   status = tpm_tis_status(tpm);
   if((status & TPM_STS_DATA_EXPECT) != 0) {
      rc = -EIO;
      goto out_err;
   }

   /*go and do it*/
   iowrite8(TPM_STS(tpm, tpm->locality), TPM_STS_GO);

   if(tpm->irq) {
      /*Wait for interrupt */
      ordinal = be32_to_cpu(*(buf + 6));
      if(wait_for_stat(tpm,
	       TPM_STS_DATA_AVAIL | TPM_STS_VALID,
	       tpm_calc_ordinal_duration(tpm, ordinal),
	       &tpm->read_queue) < 0) {
	 rc = -ETIME;
	 goto out_err;
      }
   }
#ifdef HAVE_LIBC
   if(tpm->fd >= 0) {
      files[tpm->fd].read = 0;
      files[tpm->fd].tpm_tis.respgot = 0;
      files[tpm->fd].tpm_tis.offset = 0;
   }
#endif
   return len;

out_err:
   tpm_tis_ready(tpm);
   release_locality(tpm, tpm->locality, 0);
   return rc;
}

static void tpm_tis_irq_handler(evtchn_port_t port, struct pt_regs *regs, void* data)
{
   struct tpm_chip* tpm = data;
   uint32_t interrupt;
   int i;

   interrupt = ioread32(TPM_INT_STATUS(tpm, tpm->locality));
   if(interrupt == 0) {
      return;
   }

   if(interrupt & TPM_INTF_DATA_AVAIL_INT) {
      wake_up(&tpm->read_queue);
   }
   if(interrupt & TPM_INTF_LOCALITY_CHANGE_INT) {
      for(i = 0; i < 5; ++i) {
	 if(check_locality(tpm, i) >= 0) {
	    break;
	 }
      }
   }
   if(interrupt & (TPM_INTF_LOCALITY_CHANGE_INT | TPM_INTF_STS_VALID_INT |
	    TPM_INTF_CMD_READY_INT)) {
      wake_up(&tpm->int_queue);
   }

   /* Clear interrupts handled with TPM_EOI */
   iowrite32(TPM_INT_STATUS(tpm, tpm->locality), interrupt);
   ioread32(TPM_INT_STATUS(tpm, tpm->locality));
   return;
}

/*
 * Internal kernel interface to transmit TPM commands
 */
static ssize_t tpm_transmit(struct tpm_chip *chip, const uint8_t *buf,
      size_t bufsiz)
{
   ssize_t rc;
   uint32_t count, ordinal;
   s_time_t stop;

   count = be32_to_cpu(*((uint32_t *) (buf + 2)));
   ordinal = be32_to_cpu(*((uint32_t *) (buf + 6)));
   if (count == 0)
      return -ENODATA;
   if (count > bufsiz) {
      printk("Error: invalid count value %x %zx \n", count, bufsiz);
      return -E2BIG;
   }

   //down(&chip->tpm_mutex);

   if ((rc = tpm_tis_send(chip, (uint8_t *) buf, count)) < 0) {
      printk("tpm_transmit: tpm_send: error %ld\n", rc);
      goto out;
   }

   if (chip->irq)
      goto out_recv;

   stop = NOW() + tpm_calc_ordinal_duration(chip, ordinal);
   do {
      uint8_t status = tpm_tis_status(chip);
      if ((status & (TPM_STS_DATA_AVAIL | TPM_STS_VALID)) ==
	    (TPM_STS_DATA_AVAIL | TPM_STS_VALID))
	 goto out_recv;

      if ((status == TPM_STS_COMMAND_READY)) {
	 printk("TPM Error: Operation Canceled\n");
	 rc = -ECANCELED;
	 goto out;
      }

      msleep(TPM_TIMEOUT);    /* CHECK */
      rmb();
   } while (NOW() < stop);

   /* Cancel the command */
   tpm_tis_cancel_cmd(chip);
   printk("TPM Operation Timed out\n");
   rc = -ETIME;
   goto out;

out_recv:
   if((rc = tpm_tis_recv(chip, (uint8_t *) buf, bufsiz)) < 0) {
      printk("tpm_transmit: tpm_recv: error %d\n", rc);
   }
out:
   //up(&chip->tpm_mutex);
   return rc;
}

static ssize_t transmit_cmd(struct tpm_chip *chip, struct tpm_cmd_t *cmd,
                            int len, const char *desc)
{
        int err;

        len = tpm_transmit(chip,(uint8_t *) cmd, len);
        if (len <  0)
                return len;
        if (len == TPM_ERROR_SIZE) {
                err = be32_to_cpu(cmd->header.out.return_code);
                printk("A TPM error (%d) occurred %s\n", err, desc);
                return err;
        }
        return 0;
}

int tpm_get_timeouts(struct tpm_chip *chip)
{
   struct tpm_cmd_t tpm_cmd;
   struct timeout_t *timeout_cap;
   struct duration_t *duration_cap;
   ssize_t rc;
   uint32_t timeout;
   unsigned int scale = 1;

   tpm_cmd.header.in = tpm_getcap_header;
   tpm_cmd.params.getcap_in.cap = TPM_CAP_PROP;
   tpm_cmd.params.getcap_in.subcap_size = cpu_to_be32(4);
   tpm_cmd.params.getcap_in.subcap = TPM_CAP_PROP_TIS_TIMEOUT;

   if((rc = transmit_cmd(chip, &tpm_cmd, TPM_INTERNAL_RESULT_SIZE,
	 "attempting to determine the timeouts")) != 0) {
      printk("transmit failed %d\n", rc);
      goto duration;
   }

   if(be32_to_cpu(tpm_cmd.header.out.return_code) != 0 ||
         be32_to_cpu(tpm_cmd.header.out.length) !=
         sizeof(tpm_cmd.header.out) + sizeof(uint32_t) + 4 * sizeof(uint32_t)) {
      return -EINVAL;
   }

   timeout_cap = &tpm_cmd.params.getcap_out.cap.timeout;
   /* Don't overwrite default if value is 0 */
   timeout = be32_to_cpu(timeout_cap->a);
   if(timeout && timeout < 1000) {
      /* timeouts in msc rather usec */
      scale = 1000;
   }
   if (timeout)
      chip->timeout_a = MICROSECS(timeout * scale); /*Convert to msec */
   timeout = be32_to_cpu(timeout_cap->b);
   if (timeout)
      chip->timeout_b = MICROSECS(timeout * scale); /*Convert to msec */
   timeout = be32_to_cpu(timeout_cap->c);
   if (timeout)
      chip->timeout_c = MICROSECS(timeout * scale); /*Convert to msec */
   timeout = be32_to_cpu(timeout_cap->d);
   if (timeout)
      chip->timeout_d = MICROSECS(timeout * scale); /*Convert to msec */

duration:
   tpm_cmd.header.in = tpm_getcap_header;
   tpm_cmd.params.getcap_in.cap = TPM_CAP_PROP;
   tpm_cmd.params.getcap_in.subcap_size = cpu_to_be32(4);
   tpm_cmd.params.getcap_in.subcap = TPM_CAP_PROP_TIS_DURATION;

   if((rc = transmit_cmd(chip, &tpm_cmd, TPM_INTERNAL_RESULT_SIZE,
	 "attempting to determine the durations")) < 0) {
      return rc;
   }

   if(be32_to_cpu(tpm_cmd.header.out.return_code) != 0 ||
         be32_to_cpu(tpm_cmd.header.out.length) !=
         sizeof(tpm_cmd.header.out) + sizeof(uint32_t) + 3 * sizeof(uint32_t)) {
      return -EINVAL;
   }

   duration_cap = &tpm_cmd.params.getcap_out.cap.duration;
   chip->duration[TPM_SHORT] = MICROSECS(be32_to_cpu(duration_cap->tpm_short));
   chip->duration[TPM_MEDIUM] = MICROSECS(be32_to_cpu(duration_cap->tpm_medium));
   chip->duration[TPM_LONG] = MICROSECS(be32_to_cpu(duration_cap->tpm_long));

   /* The Broadcom BCM0102 chipset in a Dell Latitude D820 gets the above
    * value wrong and apparently reports msecs rather than usecs. So we
    * fix up the resulting too-small TPM_SHORT value to make things work.
    */
   if (chip->duration[TPM_SHORT] < MILLISECS(10)) {
      chip->duration[TPM_SHORT] = SECONDS(1);
      chip->duration[TPM_MEDIUM] *= 1000;
      chip->duration[TPM_LONG] *= 1000;
      printk("Adjusting TPM timeout parameters\n");
   }

   return 0;
}



void tpm_continue_selftest(struct tpm_chip* chip) {
   uint8_t data[] = {
      0, 193,                 /* TPM_TAG_RQU_COMMAND */
      0, 0, 0, 10,            /* length */
      0, 0, 0, 83,            /* TPM_ORD_GetCapability */
   };

   tpm_transmit(chip, data, sizeof(data));
}

ssize_t tpm_getcap(struct tpm_chip *chip, uint32_t subcap_id, cap_t *cap,
                   const char *desc)
{
        struct tpm_cmd_t tpm_cmd;
        int rc;

        tpm_cmd.header.in = tpm_getcap_header;
        if (subcap_id == CAP_VERSION_1_1 || subcap_id == CAP_VERSION_1_2) {
                tpm_cmd.params.getcap_in.cap = subcap_id;
                /*subcap field not necessary */
                tpm_cmd.params.getcap_in.subcap_size = cpu_to_be32(0);
                tpm_cmd.header.in.length -= cpu_to_be32(sizeof(uint32_t));
        } else {
                if (subcap_id == TPM_CAP_FLAG_PERM ||
                    subcap_id == TPM_CAP_FLAG_VOL)
                        tpm_cmd.params.getcap_in.cap = TPM_CAP_FLAG;
                else
                        tpm_cmd.params.getcap_in.cap = TPM_CAP_PROP;
                tpm_cmd.params.getcap_in.subcap_size = cpu_to_be32(4);
                tpm_cmd.params.getcap_in.subcap = subcap_id;
        }
        rc = transmit_cmd(chip, &tpm_cmd, TPM_INTERNAL_RESULT_SIZE, desc);
        if (!rc)
                *cap = tpm_cmd.params.getcap_out.cap;
        return rc;
}


struct tpm_chip* init_tpm_tis(unsigned long baseaddr, int localities, unsigned int irq)
{
   int i;
   unsigned long addr;
   struct tpm_chip* tpm = NULL;
   uint32_t didvid;
   uint32_t intfcaps;
   uint32_t intmask;

   printk("============= Init TPM TIS Driver ==============\n");

   /*Sanity check the localities input */
   if(localities & ~TPM_TIS_EN_LOCLALL) {
      printk("init_tpm_tis() Invalid locality specification! %X\n", localities);
      goto abort_egress;
   }

   printk("IOMEM Machine Base Address: %lX\n", baseaddr);

   /* Create the tpm data structure */
   tpm = malloc(sizeof(struct tpm_chip));
   __init_tpm_chip(tpm);

   /* Set the enabled localities - if 0 we leave default as all enabled */
   if(localities != 0) {
      tpm->enabled_localities = localities;
   }
   printk("Enabled Localities: ");
   for(i = 0; i < 5; ++i) {
      if(locality_enabled(tpm, i)) {
	 printk("%d ", i);
      }
   }
   printk("\n");

   /* Set the base machine address */
   tpm->baseaddr = baseaddr;

   /* Set default timeouts */
   tpm->timeout_a = MILLISECS(TIS_SHORT_TIMEOUT);
   tpm->timeout_b = MILLISECS(TIS_LONG_TIMEOUT);
   tpm->timeout_c = MILLISECS(TIS_SHORT_TIMEOUT);
   tpm->timeout_d = MILLISECS(TIS_SHORT_TIMEOUT);

   /*Map the mmio pages */
   addr = tpm->baseaddr;
   for(i = 0; i < 5; ++i) {
      if(locality_enabled(tpm, i)) {
	 /* Map the page in now */
	 if((tpm->pages[i] = ioremap_nocache(addr, PAGE_SIZE)) == NULL) {
	    printk("Unable to map iomem page a address %p\n", addr);
	    goto abort_egress;
	 }

	 /* Set default locality to the first enabled one */
	 if (tpm->locality < 0) {
	    if(tpm_tis_request_locality(tpm, i) < 0) {
	       printk("Unable to request locality %d??\n", i);
	       goto abort_egress;
	    }
	 }
      }
      addr += PAGE_SIZE;
   }


   /* Get the vendor and device ids */
   didvid = ioread32(TPM_DID_VID(tpm, tpm->locality));
   tpm->did = didvid >> 16;
   tpm->vid = didvid & 0xFFFF;


   /* Get the revision id */
   tpm->rid = ioread8(TPM_RID(tpm, tpm->locality));

   printk("1.2 TPM (device-id=0x%X vendor-id = %X rev-id = %X)\n", tpm->did, tpm->vid, tpm->rid);

   intfcaps = ioread32(TPM_INTF_CAPS(tpm, tpm->locality));
   printk("TPM interface capabilities (0x%x):\n", intfcaps);
   if (intfcaps & TPM_INTF_BURST_COUNT_STATIC)
      printk("\tBurst Count Static\n");
   if (intfcaps & TPM_INTF_CMD_READY_INT)
      printk("\tCommand Ready Int Support\n");
   if (intfcaps & TPM_INTF_INT_EDGE_FALLING)
      printk("\tInterrupt Edge Falling\n");
   if (intfcaps & TPM_INTF_INT_EDGE_RISING)
      printk("\tInterrupt Edge Rising\n");
   if (intfcaps & TPM_INTF_INT_LEVEL_LOW)
      printk("\tInterrupt Level Low\n");
   if (intfcaps & TPM_INTF_INT_LEVEL_HIGH)
      printk("\tInterrupt Level High\n");
   if (intfcaps & TPM_INTF_LOCALITY_CHANGE_INT)
      printk("\tLocality Change Int Support\n");
   if (intfcaps & TPM_INTF_STS_VALID_INT)
      printk("\tSts Valid Int Support\n");
   if (intfcaps & TPM_INTF_DATA_AVAIL_INT)
      printk("\tData Avail Int Support\n");

   /*Interupt setup */
   intmask = ioread32(TPM_INT_ENABLE(tpm, tpm->locality));

   intmask |= TPM_INTF_CMD_READY_INT
      | TPM_INTF_LOCALITY_CHANGE_INT | TPM_INTF_DATA_AVAIL_INT
      | TPM_INTF_STS_VALID_INT;

   iowrite32(TPM_INT_ENABLE(tpm, tpm->locality), intmask);

   /*If interupts are enabled, handle it */
   if(irq) {
      if(irq != TPM_PROBE_IRQ) {
	 tpm->irq = irq;
      } else {
	 /*FIXME add irq probing feature later */
	 printk("IRQ probing not implemented\n");
      }
   }

   if(tpm->irq) {
      iowrite8(TPM_INT_VECTOR(tpm, tpm->locality), tpm->irq);

      if(bind_pirq(tpm->irq, 1, tpm_tis_irq_handler, tpm) != 0) {
	 printk("Unabled to request irq: %u for use\n", tpm->irq);
	 printk("Will use polling mode\n");
	 tpm->irq = 0;
      } else {
	 /* Clear all existing */
	 iowrite32(TPM_INT_STATUS(tpm, tpm->locality), ioread32(TPM_INT_STATUS(tpm, tpm->locality)));

	 /* Turn on interrupts */
	 iowrite32(TPM_INT_ENABLE(tpm, tpm->locality), intmask | TPM_GLOBAL_INT_ENABLE);
      }
   }

   if(tpm_get_timeouts(tpm)) {
      printk("Could not get TPM timeouts and durations\n");
      goto abort_egress;
   }
   tpm_continue_selftest(tpm);


   return tpm;
abort_egress:
   if(tpm != NULL) {
      shutdown_tpm_tis(tpm);
   }
   return NULL;
}

void shutdown_tpm_tis(struct tpm_chip* tpm){
   int i;

   printk("Shutting down tpm_tis device\n");

   iowrite32(TPM_INT_ENABLE(tpm, tpm->locality), ~TPM_GLOBAL_INT_ENABLE);

   /*Unmap all of the mmio pages */
   for(i = 0; i < 5; ++i) {
      if(tpm->pages[i] != NULL) {
	 iounmap(tpm->pages[i], PAGE_SIZE);
	 tpm->pages[i] = NULL;
      }
   }
   free(tpm);
   return;
}


int tpm_tis_cmd(struct tpm_chip* tpm, uint8_t* req, size_t reqlen, uint8_t** resp, size_t* resplen)
{
   if(tpm->locality < 0) {
      printk("tpm_tis_cmd() failed! locality not set!\n");
      return -1;
   }
   if(reqlen > TPM_BUFSIZE) {
      reqlen = TPM_BUFSIZE;
   }
   memcpy(tpm->data_buffer, req, reqlen);
   *resplen = tpm_transmit(tpm, tpm->data_buffer, TPM_BUFSIZE);

   *resp = malloc(*resplen);
   memcpy(*resp, tpm->data_buffer, *resplen);
   return 0;
}

#ifdef HAVE_LIBC
int tpm_tis_open(struct tpm_chip* tpm)
{
   /* Silently prevent multiple opens */
   if(tpm->fd != -1) {
      return tpm->fd;
   }

   tpm->fd = alloc_fd(FTYPE_TPM_TIS);
   printk("tpm_tis_open() -> %d\n", tpm->fd);
   files[tpm->fd].tpm_tis.dev = tpm;
   files[tpm->fd].tpm_tis.offset = 0;
   files[tpm->fd].tpm_tis.respgot = 0;
   return tpm->fd;
}

int tpm_tis_posix_write(int fd, const uint8_t* buf, size_t count)
{
   struct tpm_chip* tpm;
   tpm = files[fd].tpm_tis.dev;

   if(tpm->locality < 0) {
      printk("tpm_tis_posix_write() failed! locality not set!\n");
      errno = EINPROGRESS;
      return -1;
   }
   if(count == 0) {
      return 0;
   }

   /* Return an error if we are already processing a command */
   if(count > TPM_BUFSIZE) {
      count = TPM_BUFSIZE;
   }
   /* Send the command now */
   memcpy(tpm->data_buffer, buf, count);
   if((tpm->data_len = tpm_transmit(tpm, tpm->data_buffer, TPM_BUFSIZE)) < 0) {
      errno = EIO;
      return -1;
   }
   return count;
}

int tpm_tis_posix_read(int fd, uint8_t* buf, size_t count)
{
   int rc;
   struct tpm_chip* tpm;
   tpm = files[fd].tpm_tis.dev;

   if(count == 0) {
      return 0;
   }

   /* If there is no tpm resp to read, return EIO */
   if(tpm->data_len < 0) {
      errno = EIO;
      return -1;
   }


   /* Handle EOF case */
   if(files[fd].tpm_tis.offset >= tpm->data_len) {
      rc = 0;
   } else {
      rc = min(tpm->data_len - files[fd].tpm_tis.offset, count);
      memcpy(buf, tpm->data_buffer + files[fd].tpm_tis.offset, rc);
   }
   files[fd].tpm_tis.offset += rc;
   /* Reset the data pending flag */
   return rc;
}
int tpm_tis_posix_fstat(int fd, struct stat* buf)
{
   struct tpm_chip* tpm;
   tpm = files[fd].tpm_tis.dev;

   buf->st_mode = O_RDWR;
   buf->st_uid = 0;
   buf->st_gid = 0;
   buf->st_size = be32_to_cpu(*((uint32_t*)(tpm->data_buffer + 2)));
   buf->st_atime = buf->st_mtime = buf->st_ctime = time(NULL);
   return 0;
}


#endif
