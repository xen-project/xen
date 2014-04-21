#ifndef __VTPM_DISK_H
#define __VTPM_DISK_H

#include "uuid.h"
#include <polarssl/aes.h>
#include "endian_int.h"

/* Type for disk sector indexes */
typedef be32_t sector_t;

/* A TPM authdata entry (160 random bits) */
struct tpm_authdata {
	uint8_t bits[20];
};

/* 160-bit hash (SHA-1) */
struct hash160 {
	uint8_t bits[20];
};

/* 256-bit hash (either SHA256 or SHA512-256) */
struct hash256 {
	uint8_t bits[32];
};

/* 128-bit MAC (AES-128 CMAC) */
struct mac128 {
	uint8_t bits[16];
};

struct key128 {
	uint8_t bits[16];
};

/********************************************************************/

/**
 * Unique identifying information for a vTPM group. Once a group has been
 * created, this data will be constant.
 *
 * This structure a component of struct disk_group_sector, stored directly.
 */
struct group_id_data {
	uuid_t uuid;
	uint8_t saa_pubkey[256];
	uint8_t tpm_aik_public[256];
	uint8_t tpm_aik_edata[256];
	struct hash256 rollback_pubkey_hash;
};

/**
 * Details of a vTPM group that change during normal operation.
 *
 * This structure a component of struct disk_group_sector, stored directly.
 */
struct group_details {
	be64_t sequence;
	be64_t cfg_seq;
	be64_t flags;
#define FLAG_ROLLBACK_DETECTED 1

	/* Seal(recovery_seal, PCR16 = H(RECOVERY_KEY)) */
	uint8_t recovery_data[256];
};

/**
 * The required input to TPM_Unseal to obtain key data
 *
 * This structure a component of several disk structures, stored directly.
 */
struct disk_seal_entry {
	le32_t pcr_selection;
	struct hash160 digest_at_seal;
	struct hash160 digest_release;
	uint8_t sealed_data[256];
};

/**
 * A vTPM group's configuration list and sealed key data
 *
 * This structure a component of struct disk_group_sector, stored directly.
 */
struct disk_group_boot_config_list {
#define NR_SEALS_PER_GROUP 5
	be32_t nr_cfgs;
	struct disk_seal_entry entry[NR_SEALS_PER_GROUP];
#define NR_KERNS_PER_GROUP 16
	be32_t nr_kerns;
	struct hash160 kernels[NR_KERNS_PER_GROUP];

	/* TODO support overflow of either nr_cfgs or nr_kerns */
	struct hash256 next;
};

/********************************************************************/

#define VTPM_FLAG_ADMIN 1
#define VTPM_FLAG_DISK_MASK (0xFFFF)
#define VTPM_FLAG_OPEN (1UL<<31)

/**
 * A single vTPM's in-memory data. Do not free if the open flag is set.
 */
struct mem_vtpm {
	uuid_t uuid;
	uint8_t data[64];
	uint32_t flags;
	uint32_t index_in_parent;
};

/**
 * Shortened form of struct disk_seal_entry
 */
struct mem_seal {
	le32_t pcr_selection;
	struct hash160 digest_release;
};

/**
 * Maximum number of vTPMs in one sector on the disk.
 *
 * 20 + 64 = 84 bytes per vTPM; 32 bytes overhead from IVs
 * 48*84 + 32 = 4064 bytes
 */
#define VTPMS_PER_SECTOR 48

/**
 * Decrypted and unpacked version of struct disk_vtpm_sector
 */
struct mem_vtpm_page {
	struct hash256 disk_hash;
	sector_t disk_loc;
	int size;

	struct mem_vtpm *vtpms[VTPMS_PER_SECTOR];
};

/**
 * In-memory representation of an open vTPM group
 */
struct mem_group {
	struct group_id_data id_data;
	struct group_details details;

	/* Obtained from sealed data */
	struct tpm_authdata aik_authdata;
	struct key128 group_key;
	struct key128 rollback_mac_key;

	int nr_vtpms;
	int nr_pages;
	struct mem_vtpm_page *data;

	int flags;
#define MEM_GROUP_FLAG_SEAL_VALID 1
#define MEM_GROUP_FLAG_FIRSTBOOT  2
	int nr_seals;
	struct mem_seal *seals;

	sector_t seal_next_loc;
	struct disk_group_boot_config_list seal_bits;
};

/**
 * In-memory representation of a vTPM group (open or not)
 */
struct mem_group_hdr {
	sector_t disk_loc;
	struct hash256 disk_hash;

	int disk_nr_inuse;
	sector_t *disk_inuse;

	struct mem_group *v;
};

/**
 * In-memory representation of the TPM Manager's permanent data
 */
struct mem_tpm_mgr {
	struct key128 tm_key;
	aes_context tm_key_e;
	struct key128 nv_key;
	uuid_t uuid;

	be32_t nvram_slot;
	struct tpm_authdata nvram_auth;
	be32_t counter_index;
	struct tpm_authdata counter_auth;
	be32_t counter_value;

	uint64_t sequence;

	int active_root;

	int nr_groups;
	struct mem_group_hdr *groups;

	int root_seals_valid;
};

int vtpm_storage_init(void);
int vtpm_load_disk(void);
int vtpm_new_disk(void);

enum vtpm_sync_depth {
	SEQ_UPDATE,       /* Just the soft sequence number */
	CTR_UPDATE,       /* Sequence and TPM counter */
	GROUP_KEY_UPDATE, /* Group key (and TPM counter) */
	MGR_KEY_UPDATE,   /* Manager key */
	CTR_AUTH_UPDATE,  /* TPM counter authdata */
	NV_AUTH_UPDATE    /* NVRAM authdata */
};

/*
 * For a full manager key flush, use this ordering of writes:
 *  MGR_KEY_UPDATE
 *  CTR_AUTH_UPDATE
 *  NV_AUTH_UPDATE
 *  CTR_UPDATE or GROUP_KEY_UPDATE
 */

extern struct mem_tpm_mgr *g_mgr;

int vtpm_sync_disk(struct mem_tpm_mgr *mgr, int depth);
int vtpm_sync_group(struct mem_group *group, int depth);
int vtpm_sync(struct mem_group *group, struct mem_vtpm *vtpm);

int create_vtpm(struct mem_group *group, struct mem_vtpm **vtpmp, const uuid_t uuid);
int delete_vtpm(struct mem_group *group, struct mem_vtpm *vtpm);
int find_vtpm(struct mem_group **groupp, struct mem_vtpm **vtpmp, const uuid_t uuid);

#endif
