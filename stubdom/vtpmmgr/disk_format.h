#ifndef __VTPMMGR_DISK_FORMAT_H
#define __VTPMMGR_DISK_FORMAT_H

static const uint8_t TPM_MGR_MAGIC[12] = {
	'T','P','M',0xfe,'M','G','R',0xdd,'D','O','M',0x00
};

/**
 * Sector 0 on disk: stored in plaintext
 */
struct disk_header {
	char magic[12];
#define TPM_MGR_VERSION 0
	be32_t version;
};

/**
 * Raw contents of disk sectors that need both encryption and authentication
 */
struct disk_crypt_sector_plain {
	struct mac128 mac;
	union {
		struct {
			uint8_t iv[16];
			char data[4096-32];
		};
		uint8_t iv_data[4096-16];
	};
};

/**
 * Contents of the sealed blob in the root seal list
 */
struct disk_root_sealed_data {
#define DISK_ROOT_BOUND_MAGIC "Root"
	char magic[4];
	uuid_t tpm_manager_uuid;

	be32_t nvram_slot;
	struct tpm_authdata nvram_auth;
	be32_t counter_index;
	struct tpm_authdata counter_auth;

	/* encrypted (AES-ECB) with key from NVRAM */
	struct key128 tm_key;
};

/**
 * Contents of the sealed blob in a group's seal list
 */
struct disk_group_sealed_data {
#define DISK_GROUP_BOUND_MAGIC "TGrp"
	char magic[4];
	uuid_t tpm_manager_uuid;
	struct tpm_authdata aik_authdata;

	struct key128 group_key;
	struct key128 rollback_mac_key;
};

/**
 * Contents of the seal_list_N sectors on disk (plaintext, linked list)
 *
 * The hdr field is unused except in sector 0
 */
struct disk_seal_list {
	struct disk_header hdr;
	be32_t length;
	sector_t next;
#define SEALS_PER_ROOT_SEAL_LIST 13
	struct disk_seal_entry entry[SEALS_PER_ROOT_SEAL_LIST];
};

/**
 * TODO - overflow for struct disk_group_boot_config_list
 */
struct disk_group_seal_list {
	sector_t next;
#define SEALS_PER_GROUP_SEAL_LIST 13
	struct disk_seal_entry entry[SEALS_PER_GROUP_SEAL_LIST];
};

/**
 * Rollback detection MAC entry
 */
struct disk_rb_mac_entry {
	be32_t id;
	struct mac128 mac;
};

#define NR_ENTRIES_PER_ROOT 16
/**
 * The area of the root sector protected by rollback MACs
 */
struct disk_root_sector_mac1_area {
	be64_t sequence;
	be32_t tpm_counter_value;

	be32_t nr_groups;
	struct hash256 group_hash[NR_ENTRIES_PER_ROOT];
};

/**
 * Decrypted contents of the root sector (sector 1 and 2) on disk
 */
struct disk_root_sector {
	struct disk_root_sector_mac1_area v;

	sector_t group_loc[NR_ENTRIES_PER_ROOT];

	uint8_t pad[8];

	/* Rollback detection MACs */
	be32_t nr_rb_macs;
	sector_t rb_next_loc;
	/* used if rb_macs overflows */
	struct hash256 rb_next_hash;

#define NR_RB_MACS_PER_ROOT 128
	struct disk_rb_mac_entry rb_macs[NR_RB_MACS_PER_ROOT];
};

/**
 * Hash tree for list expansion. Used for the list of groups in the root and for
 * the list of vTPMs in a group.
 */
struct disk_itree_sector {
#define NR_ENTRIES_PER_ITREE 112
	sector_t location[NR_ENTRIES_PER_ITREE];
	/* SECTOR-HASH { */
	struct hash256 hash[NR_ENTRIES_PER_ITREE];
	/* SECTOR-HASH } */
};

#define NR_ENTRIES_PER_GROUP_BASE 16
/**
 * Data that must remain constant if a group is not open
 */
struct disk_group_sector_mac3_area {
	struct group_id_data id_data; /* MAC2 */
	struct group_details details;
	struct disk_group_boot_config_list boot_configs;

	be32_t nr_vtpms;
	struct hash256 vtpm_hash[NR_ENTRIES_PER_GROUP_BASE];
};

/**
 * Group metadata sector
 *
 * Encrypted with TM_KEY - takes 16 bytes for IV; integrity from parent.
 */
struct disk_group_sector {
	/* SECTOR-HASH { */
	struct disk_group_sector_mac3_area v;

	/* MAC(MAC3, group_key) */
	struct mac128 group_mac;
	/* SECTOR-HASH } */

	sector_t vtpm_location[NR_ENTRIES_PER_GROUP_BASE];
	sector_t boot_configs_next;
};

/**
 * Data on a vTPM which is available when its group is not open
 */
struct disk_vtpm_plain {
	uuid_t uuid;
	be32_t flags;
};

/**
 * Data on a vTPM which is only available when its group is open
 */
struct disk_vtpm_secret {
	uint8_t data[64];
};

/**
 * Contents of a vTPM data disk sector
 *
 * Encrypted with TM_KEY - takes 16 bytes for IV
 */
struct disk_vtpm_sector {
	/* SECTOR-HASH { */
	struct disk_vtpm_plain header[VTPMS_PER_SECTOR];
	struct mac128 iv;
	struct disk_vtpm_secret data[VTPMS_PER_SECTOR];
	/* SECTOR-HASH } */
};

#endif
