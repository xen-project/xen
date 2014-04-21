#include <console.h>
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
#include "disk_crypto.h"
#include "disk_format.h"

static int disk_read_crypt_sector(void *data, size_t size, sector_t block, const struct mem_tpm_mgr *mgr)
{
	struct disk_crypt_sector_plain *sector = disk_read_sector(block);
	if (!sector)
		return 2;

	if (aes_cmac_verify(&sector->mac, sector->data, sizeof(sector->data), &mgr->tm_key_e))
		return 2;

	aes_decrypt_ctr(data, size, sector->iv_data, sizeof(sector->iv_data), &mgr->tm_key_e);
	return 0;
}

static void group_free(struct mem_group *group)
{
	int i, j;
	if (!group)
		return;
	if (group->data) {
		for (i = 0; i < group->nr_pages; i++) {
			for (j = 0; j < group->data[i].size; j++) {
				free(group->data[i].vtpms[j]);
			}
		}
		free(group->data);
	}
	free(group->seals);
	free(group);
}

static void mgr_free(struct mem_tpm_mgr *mgr)
{
	int i;
	if (!mgr)
		return;
	if (mgr->groups) {
		for(i=0; i < mgr->nr_groups; i++)
			group_free(mgr->groups[i].v);
		free(mgr->groups);
	}
	free(mgr);
}

/* Open the group keys from one of the sealed strutures */
static int find_group_key(struct mem_group *dst,
		const struct disk_group_sector *group,
		const struct mem_tpm_mgr *parent)
{
	int i, rc, rv = 1;
	struct hash160 buf;
	struct disk_group_sealed_data sealed;

	dst->nr_seals = be32_native(group->v.boot_configs.nr_cfgs);
	if (dst->nr_seals > NR_SEALS_PER_GROUP)
		return 3; // TODO support spill to extra pages

	dst->seals = calloc(dst->nr_seals, sizeof(dst->seals[0]));
	if (!dst->seals) {
		vtpmlogerror(VTPM_LOG_VTPM, "find_group_key alloc %x\n", dst->nr_seals);
		return 2;
	}

	for(i=0; i < dst->nr_seals; i++) {
		const struct disk_seal_entry *cfg = &group->v.boot_configs.entry[i];
		dst->seals[i].pcr_selection = cfg->pcr_selection;
		memcpy(&dst->seals[i].digest_release, &cfg->digest_release, 20);

		TPM_pcr_digest(&buf, cfg->pcr_selection);
		if (memcmp(&buf, &cfg->digest_release, 20))
			continue;
		rc = TPM_disk_unseal(&sealed, sizeof(sealed), cfg);
		if (rc)
			continue;
		if (memcmp(&sealed.magic, DISK_GROUP_BOUND_MAGIC, 4))
			continue;
		if (memcmp(sealed.tpm_manager_uuid, parent->uuid, 16))
			continue;

		memcpy(&dst->rollback_mac_key, &sealed.rollback_mac_key, 16);
		memcpy(&dst->group_key, &sealed.group_key, 16);
		memcpy(&dst->aik_authdata, &sealed.aik_authdata, 20);
		rv = 0;
	}

	// cache the list to allow writes without touching the TPM
	memcpy(&dst->seal_bits, &group->v.boot_configs, sizeof(dst->seal_bits));
	dst->flags |= MEM_GROUP_FLAG_SEAL_VALID;

	return rv;
}

static int parse_root_key(struct mem_tpm_mgr *dst, struct disk_seal_entry *src)
{
	int rc;
	struct disk_root_sealed_data sealed;

	rc = TPM_disk_unseal(&sealed, sizeof(sealed), src);
	if (rc)
		return rc;

	if (memcmp(&sealed.magic, DISK_ROOT_BOUND_MAGIC, 4))
		return 1;

	rc = TPM_disk_nvread(&dst->nv_key, 16, sealed.nvram_slot, sealed.nvram_auth);
	if (rc)
		return rc;

	// TODO when an NV slot in the physical TPM is used to populate nv_key,
	// that value should be used to mask the master key so that the value
	// can be changed to revoke old disk state
#if 0
	aes_decrypt_one(&dst->tm_key, &sealed.tm_key, &dst->nv_key);
#else
	memcpy(&dst->tm_key, &sealed.tm_key, 16);
#endif

	memcpy(dst->uuid, sealed.tpm_manager_uuid, 16);
	dst->nvram_slot = sealed.nvram_slot;
	memcpy(&dst->nvram_auth, &sealed.nvram_auth, sizeof(struct tpm_authdata));
	dst->counter_index = sealed.counter_index;
	memcpy(&dst->counter_auth, &sealed.counter_auth, sizeof(struct tpm_authdata));

	return 0;
}

static struct mem_tpm_mgr *find_root_key(int active_root)
{
	sector_t seal_list = native_be32(active_root);
	struct disk_seal_list *seal = disk_read_sector(seal_list);
	struct hash160 buf;
	int i, rc, nr;
	struct mem_tpm_mgr *dst;

	if (memcmp(seal->hdr.magic, TPM_MGR_MAGIC, 12))
		return NULL;

	if (be32_native(seal->hdr.version) != TPM_MGR_VERSION)
		return NULL;

	dst = calloc(1, sizeof(*dst));
	dst->active_root = active_root;

	for (nr = 0; nr < 100; nr++) {
		disk_set_used(seal_list, dst);
		uint32_t nr_seals = be32_native(seal->length);
		if (nr_seals > SEALS_PER_ROOT_SEAL_LIST)
			break;
		for (i = 0; i < nr_seals; i++) {
			struct disk_seal_entry *src = &seal->entry[i];

			TPM_pcr_digest(&buf, src->pcr_selection);
			if (memcmp(&buf, &src->digest_release, 20))
				continue;

			rc = parse_root_key(dst, src);
			if (rc)
				continue;
			return dst;
		}
		seal_list = seal->next;
		if (seal_list.value == 0)
			break;
		seal = disk_read_sector(seal_list);
	}
	mgr_free(dst);
	return NULL;
}

/* Load and verify one sector's worth of vTPMs. This loads all the vTPM entries
 * and decrypts their state data into memory.
 */
static int load_verify_vtpm_page(struct mem_vtpm_page *dst, int base,
		const struct mem_tpm_mgr *mgr, const aes_context *group_key)
{
	struct disk_vtpm_sector pt;
	int i, rc;

	disk_set_used(dst->disk_loc, mgr);

	rc = disk_read_crypt_sector(&pt, sizeof(pt), dst->disk_loc, mgr);
	if (rc) {
		printk("Malformed sector %d\n", be32_native(dst->disk_loc));
		return rc;
	}
	
	rc = sha256_verify(&dst->disk_hash, &pt, sizeof(pt));
	if (rc) {
		printk("Hash mismatch in sector %d\n", be32_native(dst->disk_loc));
		return rc;
	}

	if (!group_key)
		return 0;

	aes_decrypt_ctr(pt.data, sizeof(pt.data), &pt.iv, sizeof(pt.data) + 16, group_key);

	for (i = 0; i < dst->size; i++) {
		struct mem_vtpm *vtpm = calloc(1, sizeof(*vtpm));
		dst->vtpms[i] = vtpm;
		memcpy(vtpm->uuid, pt.header[i].uuid, 16);
		memcpy(vtpm->data, pt.data[i].data, 64);
		vtpm->flags = be32_native(pt.header[i].flags);
		vtpm->index_in_parent = i + base;
	}
	return 0;
}

static int load_verify_vtpm_pages(struct mem_group *group, int base, int size,
		const struct hash256 *hash, const sector_t *loc,
		const struct mem_tpm_mgr *mgr, const aes_context *group_key)
{
	int i, rc;
	struct mem_vtpm_page *page = group->data + base;

	/* base was in terms of sectors; convert to vtpms */
	base *= VTPMS_PER_SECTOR;

	for (i = 0; i < size; i++) {
		page->disk_hash = hash[i];
		page->disk_loc = loc[i];
		if (group->nr_vtpms - base > VTPMS_PER_SECTOR)
			page->size = VTPMS_PER_SECTOR;
		else
			page->size = group->nr_vtpms - base;
		rc = load_verify_vtpm_page(page, base, mgr, group_key);
		if (rc)
			return rc;
		base += VTPMS_PER_SECTOR;
	}

	return 0;
}

static int load_verify_vtpm_itree(struct mem_group_hdr *hdr, int base, int nr_entries,
		const struct hash256 *hash, const sector_t *loc, int hsize,
		const struct mem_tpm_mgr *mgr, const aes_context *group_key);

static int load_verify_vtpm_itree(struct mem_group_hdr *hdr, int base, int nr_entries,
		const struct hash256 *hash, const sector_t *loc, int hsize,
		const struct mem_tpm_mgr *mgr, const aes_context *group_key)
{
	int i, rc, incr = 1, inuse_base = hdr->disk_nr_inuse, lsize;

	// increase tree depth until all entries fit
	while (nr_entries > incr * hsize)
		incr *= NR_ENTRIES_PER_ITREE;

	// save the list of used sectors (itree and vtpm) in the header
	lsize = 1 + (nr_entries - 1) / incr;
	hdr->disk_nr_inuse += lsize;
	hdr->disk_inuse = realloc(hdr->disk_inuse, hdr->disk_nr_inuse * sizeof(sector_t));
	memcpy(&hdr->disk_inuse[inuse_base], loc, lsize * sizeof(sector_t));

	// if the entries already fit, process vtpm pages
	if (nr_entries <= hsize)
		return load_verify_vtpm_pages(hdr->v, base, nr_entries, hash, loc, mgr, group_key);

	for (i = 0; i * incr < nr_entries; i++) {
		struct disk_itree_sector pt;
		int child_entries = incr;

		// the last sector is not completely full
		if (nr_entries - i * incr < incr)
			child_entries = nr_entries - i * incr;

		disk_set_used(loc[i], mgr);
		hdr->disk_inuse[inuse_base++] = loc[i];

		rc = disk_read_crypt_sector(&pt, sizeof(pt), loc[i], mgr);
		if (rc) {
			printk("Malformed sector %d\n", be32_native(loc[i]));
			return rc;
		}

		rc = sha256_verify(&hash[i], pt.hash, sizeof(pt.hash));
		if (rc) {
			printk("Hash mismatch in sector %d\n", be32_native(loc[i]));
			return rc;
		}

		rc = load_verify_vtpm_itree(hdr, base, child_entries, pt.hash, pt.location,
				NR_ENTRIES_PER_ITREE, mgr, group_key);
		if (rc)
			return rc;

		base += incr;
	}

	return 0;
}

/* Load and verify one group's data structure, including its vTPMs.
 */
static int load_verify_group(struct mem_group_hdr *dst, const struct mem_tpm_mgr *mgr)
{
	struct mem_group *group;
	struct disk_group_sector disk;
	int rc;
	aes_context key_e;
	aes_context *opened_key = NULL;

	disk_set_used(dst->disk_loc, mgr);

	rc = disk_read_crypt_sector(&disk, sizeof(disk), dst->disk_loc, mgr);
	if (rc) {
		printk("Malformed sector %d\n", be32_native(dst->disk_loc));
		return rc;
	}
	
	rc = sha256_verify(&dst->disk_hash, &disk.v, sizeof(disk.v) + sizeof(disk.group_mac));
	if (rc) {
		printk("Hash mismatch in sector %d\n", be32_native(dst->disk_loc));
		return rc;
	}
	
	dst->v = group = calloc(1, sizeof(*group));

	rc = find_group_key(group, &disk, mgr);
	if (rc == 0) {
		opened_key = &key_e;
		/* Verify the group with the group's own key */
		aes_setup(opened_key, &group->group_key);
		if (aes_cmac_verify(&disk.group_mac, &disk.v, sizeof(disk.v), opened_key)) {
			printk("Group CMAC failed\n");
			return 2;
		}

		memcpy(&group->id_data, &disk.v.id_data, sizeof(group->id_data));
		memcpy(&group->details, &disk.v.details, sizeof(group->details));
	} else if (rc == 1) {
		// still need to walk the vtpm list
		rc = 0;
	} else {
		printk("Group key unsealing failed\n");
		return rc;
	}

	group->nr_vtpms = be32_native(disk.v.nr_vtpms);
	group->nr_pages = (group->nr_vtpms + VTPMS_PER_SECTOR - 1) / VTPMS_PER_SECTOR;

	group->data = calloc(group->nr_pages, sizeof(group->data[0]));

	rc = load_verify_vtpm_itree(dst, 0, group->nr_pages, disk.v.vtpm_hash,
			disk.vtpm_location, NR_ENTRIES_PER_GROUP_BASE, mgr, opened_key);

	if (!opened_key) {
		/* remove the struct */
		free(group->data);
		free(group->seals);
		free(group);
		dst->v = NULL;
	}

	return rc;
}

static int load_root_pre(struct disk_root_sector *root, struct mem_tpm_mgr *dst)
{
	int rc;

	aes_setup(&dst->tm_key_e, &dst->tm_key);

	rc = disk_read_crypt_sector(root, sizeof(*root), root_loc(dst), dst);

	if (rc) {
		vtpmloginfo(VTPM_LOG_VTPM, "root cmac verify failed in slot %d\n", dst->active_root);
		return 2;
	}

	dst->root_seals_valid = 1 + dst->active_root;
	dst->sequence = be64_native(root->v.sequence);

	return 0;
}

static int load_verify_group_itree(struct mem_tpm_mgr *dst, int base, int nr_entries,
		const struct hash256 *hash, const sector_t *loc, int hsize);

static int load_verify_group_itree(struct mem_tpm_mgr *dst, int base, int nr_entries,
		const struct hash256 *hash, const sector_t *loc, int hsize)
{
	int i, rc, incr = 1;

	if (nr_entries <= hsize) {
		for(i=0; i < nr_entries; i++) {
			struct mem_group_hdr *group = dst->groups + base + i;
			group->disk_loc = loc[i];
			memcpy(&group->disk_hash, &hash[i], sizeof(group->disk_hash));
			rc = load_verify_group(group, dst);
			if (rc) {
				printk("Error loading group %d\n", base + i);
				return rc;
			}
		}
		return 0;
	}

	// increase tree depth until all entries fit
	while (nr_entries > incr * hsize)
		incr *= NR_ENTRIES_PER_ITREE;

	for (i = 0; i * incr < nr_entries; i++) {
		struct disk_itree_sector pt;
		int child_entries = incr;

		// the last sector is not completely full
		if (nr_entries - i * incr < incr)
			child_entries = nr_entries - i * incr;

		disk_set_used(loc[i], dst);

		rc = disk_read_crypt_sector(&pt, sizeof(pt), loc[i], dst);
		if (rc) {
			printk("Malformed sector %d\n", be32_native(loc[i]));
			return rc;
		}

		rc = sha256_verify(&hash[i], pt.hash, sizeof(pt.hash));
		if (rc) {
			printk("Hash mismatch in sector %d\n", be32_native(loc[i]));
			return rc;
		}

		rc = load_verify_group_itree(dst, base, child_entries, pt.hash, pt.location, NR_ENTRIES_PER_ITREE);
		if (rc)
			return rc;

		base += incr;
	}

	return 0;
}

static int load_root_post(struct mem_tpm_mgr *dst, const struct disk_root_sector *root)
{
	int rc, i, j;
	uint32_t nr_disk_rbs = be32_native(root->nr_rb_macs);

	rc = TPM_disk_check_counter(dst->counter_index, dst->counter_auth,
			root->v.tpm_counter_value);
	if (rc)
		return 2;
	dst->counter_value = root->v.tpm_counter_value;

	dst->nr_groups = be32_native(root->v.nr_groups);
	dst->groups = calloc(sizeof(dst->groups[0]), dst->nr_groups);

	if (!dst->groups) {
		vtpmlogerror(VTPM_LOG_VTPM, "load_root_post alloc %x\n", dst->nr_groups);
		return 2;
	}

	rc = load_verify_group_itree(dst, 0, dst->nr_groups,
			root->v.group_hash, root->group_loc, NR_ENTRIES_PER_ROOT);
	if (rc)
		return rc;

	/* Sanity check: group0 must be open */
	if (!dst->groups[0].v) {
		printk("Error opening group 0\n");
		return 2;
	}

	/* TODO support for spilling rollback list */
	if (nr_disk_rbs > NR_RB_MACS_PER_ROOT)
		return 3;

	i = 0;
	j = 0;
	while (i < dst->nr_groups) {
		aes_context key_e;
		struct mem_group_hdr *group = &dst->groups[i];
		struct mem_group *groupv = group->v;
		const struct disk_rb_mac_entry *ent = &root->rb_macs[j];

		if (!groupv) {
			i++;
			// this group is not open - no need to verify now
			continue;
		}

		if (be32_native(ent->id) < i) {
			// this entry is for a group that is not open
			j++;
			continue;
		}

		if (j >= nr_disk_rbs || be32_native(ent->id) != i) {
			// TODO allow delegation
			if (!(groupv->details.flags.value & FLAG_ROLLBACK_DETECTED)) {
				groupv->details.flags.value |= FLAG_ROLLBACK_DETECTED;
				group->disk_loc.value = 0;
			}
			i++;
			continue;
		}

		aes_setup(&key_e, &groupv->rollback_mac_key);
		if (aes_cmac_verify(&ent->mac, &root->v, sizeof(root->v), &key_e)) {
			if (!(groupv->details.flags.value & FLAG_ROLLBACK_DETECTED)) {
				groupv->details.flags.value |= FLAG_ROLLBACK_DETECTED;
				group->disk_loc.value = 0;
			}
		}
		i++; j++;
	}

	return 0;
}

int vtpm_load_disk(void)
{
	struct disk_root_sector root1, root2;
	int rc = 0;
	TPM_read_pcrs();

	printk("TPM Manager - disk format %d\n", TPM_MGR_VERSION);
	printk(" root seal: %lu; sector of %d: %lu\n",
		sizeof(struct disk_root_sealed_data), SEALS_PER_ROOT_SEAL_LIST, sizeof(struct disk_seal_list));
	printk(" root: %lu v=%lu\n", sizeof(root1), sizeof(root1.v));
	printk(" itree: %lu; sector of %d: %lu\n",
		4 + 32, NR_ENTRIES_PER_ITREE, sizeof(struct disk_itree_sector));
	printk(" group: %lu v=%lu id=%lu md=%lu\n",
		sizeof(struct disk_group_sector), sizeof(struct disk_group_sector_mac3_area),
		sizeof(struct group_id_data), sizeof(struct group_details));
	printk(" group seal: %lu; %d in parent: %lu; sector of %d: %lu\n",
		sizeof(struct disk_group_sealed_data), NR_SEALS_PER_GROUP, sizeof(struct disk_group_boot_config_list),
		SEALS_PER_GROUP_SEAL_LIST, sizeof(struct disk_group_seal_list));
	printk(" vtpm: %lu+%lu; sector of %d: %lu\n",
		sizeof(struct disk_vtpm_plain), sizeof(struct disk_vtpm_secret),
		VTPMS_PER_SECTOR, sizeof(struct disk_vtpm_sector));

	struct mem_tpm_mgr *mgr1 = find_root_key(0);
	struct mem_tpm_mgr *mgr2 = find_root_key(1);

	rc = mgr1 ? load_root_pre(&root1, mgr1) : 0;
	if (rc) {
		mgr_free(mgr1);
		mgr1 = NULL;
	}

	rc = mgr2 ? load_root_pre(&root2, mgr2) : 0;
	if (rc) {
		mgr_free(mgr2);
		mgr2 = NULL;
	}

	printk("load_root_pre: %c/%c\n", mgr1 ? 'y' : 'n', mgr2 ? 'y' : 'n');

	if (!mgr1 && !mgr2)
		return 2;

	if (mgr1 && mgr2 && mgr2->sequence > mgr1->sequence) {
		rc = load_root_post(mgr2, &root2);
		if (rc) {
			mgr_free(mgr2);
			mgr2 = NULL;
		} else {
			mgr_free(mgr1);
			g_mgr = mgr2;
			return 0;
		}
	}
	if (mgr1) {
		rc = load_root_post(mgr1, &root1);
		if (rc) {
			mgr_free(mgr1);
		} else {
			mgr_free(mgr2);
			g_mgr = mgr1;
			return 0;
		}
	}
	if (mgr2) {
		rc = load_root_post(mgr2, &root2);
		if (rc) {
			mgr_free(mgr2);
		} else {
			g_mgr = mgr2;
			return 0;
		}
	}
	printk("Could not read vTPM disk\n");

	return 2;
}
