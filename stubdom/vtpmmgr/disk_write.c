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
#include "mgmt_authority.h"

static void disk_write_crypt_sector(sector_t *dst, const void *data, size_t size, const struct mem_tpm_mgr *mgr)
{
	struct disk_crypt_sector_plain *sector = disk_write_buf();
	*dst = disk_find_free(mgr);
	aes_encrypt_ctr(sector->iv_data, sizeof(sector->iv_data), data, size, &mgr->tm_key_e);
	aes_cmac(&sector->mac, sector->data, sizeof(sector->data), &mgr->tm_key_e);
	disk_write_sector(*dst, sector, sizeof(*sector));
}

/*
 * Mark unchanged sectors on disk as being used
 */
static void disk_populate_used_vtpm(const struct mem_vtpm_page *src, const struct mem_tpm_mgr *mgr)
{
	if (be32_native(src->disk_loc) != 0)
		disk_set_used(src->disk_loc, mgr);
}

/*
 * Write out a vTPM page to disk, doing nothing if the existing copy is valid
 */
static void disk_write_vtpm_page(struct mem_vtpm_page *dst, const aes_context *auth_key,
		const struct mem_tpm_mgr *mgr)
{
	struct disk_vtpm_sector pt;
	int i;
	memset(&pt, 0, sizeof(pt));
	if (be32_native(dst->disk_loc) != 0)
		return;

	for(i=0; i < dst->size; i++) {
		memcpy(pt.header[i].uuid, dst->vtpms[i]->uuid, 16);
		memcpy(pt.data[i].data, dst->vtpms[i]->data, 64);
		pt.header[i].flags = native_be32(dst->vtpms[i]->flags & VTPM_FLAG_DISK_MASK);
	}
	aes_encrypt_ctr(&pt.iv, sizeof(pt.data) + 16, &pt.data, sizeof(pt.data), auth_key);

	sha256(&dst->disk_hash, &pt, sizeof(pt));

	disk_write_crypt_sector(&dst->disk_loc, &pt, sizeof(pt), mgr);
}

/*
 * Generate TPM seal blobs for a group's keys; do nothing if existing copy is valid
 */
static void generate_group_seals(struct mem_group *src, const struct mem_tpm_mgr *parent)
{
	int i;
	struct disk_group_sealed_data sblob;

	// previous seals are still valid, skip talking to the TPM
	if (src->flags & MEM_GROUP_FLAG_SEAL_VALID)
		return;

	memcpy(&sblob.magic, DISK_GROUP_BOUND_MAGIC, 4);
	memcpy(sblob.tpm_manager_uuid, parent->uuid, 16);
	memcpy(&sblob.aik_authdata, &src->aik_authdata, 20);
	memcpy(&sblob.group_key, &src->group_key, 16);
	memcpy(&sblob.rollback_mac_key, &src->rollback_mac_key, 16);

	/* TODO support for more than NR_SEALS_PER_GROUP seals */
	if (src->nr_seals > NR_SEALS_PER_GROUP)
		abort();

	for(i=0; i < src->nr_seals; i++) {
		struct disk_seal_entry *dst = &src->seal_bits.entry[i];
		dst->pcr_selection = src->seals[i].pcr_selection;
		memcpy(&dst->digest_release, &src->seals[i].digest_release, 20);
		TPM_pcr_digest(&dst->digest_at_seal, dst->pcr_selection);

        /*TPM 2.0 bind | TPM 1.x seal*/
        if (hw_is_tpm2())
            TPM2_disk_bind(dst, &sblob, sizeof(sblob));
        else
            TPM_disk_seal(dst, &sblob, sizeof(sblob));
	}
	src->seal_bits.nr_cfgs = native_be32(src->nr_seals);

	src->flags |= MEM_GROUP_FLAG_SEAL_VALID;
}

/*
 * Mark unchanged sectors on disk as being used
 */
static void disk_populate_used_group(const struct mem_group_hdr *src, const struct mem_tpm_mgr *mgr)
{
	int i;
	struct mem_group *group = src->v;
	if (be32_native(src->disk_loc) != 0) {
		// entire group is unchanged - mark group, itree, and vtpm sectors
		// TODO mark other children (seal)
		disk_set_used(src->disk_loc, mgr);
		for(i = 0; i < src->disk_nr_inuse; i++)
			disk_set_used(src->disk_inuse[i], mgr);
		return;
	}

	// unopened groups should never have been invalidated
	if (!group)
		abort();

	for (i = 0; i < group->nr_pages; i++)
		disk_populate_used_vtpm(&group->data[i], mgr);
}

static void disk_write_vtpm_itree(struct mem_group_hdr *hdr, int base, int nr_entries,
		struct hash256 *hash, sector_t *loc, int hsize,
		const aes_context *group_key, const struct mem_tpm_mgr *mgr);

static void disk_write_vtpm_itree(struct mem_group_hdr *hdr, int base, int nr_entries,
		struct hash256 *hash, sector_t *loc, int hsize,
		const aes_context *group_key, const struct mem_tpm_mgr *mgr)
{
	int i, incr = 1, inuse_base, lsize;

	while (nr_entries > incr * hsize)
		incr *= NR_ENTRIES_PER_ITREE;

	if (nr_entries <= hsize) {
		struct mem_group *group = hdr->v;
		for (i = 0; i < nr_entries; i++) {
			struct mem_vtpm_page *page = group->data + base + i;
			disk_write_vtpm_page(page, group_key, mgr);
			loc[i] = page->disk_loc;
			hash[i] = page->disk_hash;
		}
	} else {
		for (i = 0; i * incr < nr_entries; i++) {
			struct disk_itree_sector pt;
			int child_entries = incr;

			// the last sector is not completely full
			if (nr_entries - i * incr < incr)
				child_entries = nr_entries - i * incr;

			disk_write_vtpm_itree(hdr, base, child_entries, pt.hash, pt.location,
					NR_ENTRIES_PER_ITREE, group_key, mgr);

			sha256(&hash[i], &pt.hash, sizeof(pt.hash));
			disk_write_crypt_sector(&loc[i], &pt, sizeof(pt), mgr);

			base += incr;
		}
	}

	// save the list of used sectors (itree and vtpm) in the header
	inuse_base = hdr->disk_nr_inuse;
	lsize = 1 + (nr_entries - 1) / incr;
	hdr->disk_nr_inuse += lsize;
	hdr->disk_inuse = realloc(hdr->disk_inuse, hdr->disk_nr_inuse * sizeof(sector_t));
	memcpy(&hdr->disk_inuse[inuse_base], loc, lsize * sizeof(sector_t));
}

/*
 * Write out a vTPM group sector and its children
 */
static void disk_write_group_sector(struct mem_group_hdr *src,
		const struct mem_tpm_mgr *mgr)
{
	struct disk_group_sector disk;
	struct mem_group *group = src->v;
	aes_context key_e;

	/* Don't write if the data hasn't changed */
	if (be32_native(src->disk_loc) != 0)
		return;

	// if the group was not opened, it should not have been changed
	if (!group)
		abort();

	memset(&disk, 0, sizeof(disk));
	memcpy(&disk.v.id_data, &group->id_data, sizeof(disk.v.id_data));
	memcpy(&disk.v.details, &group->details, sizeof(disk.v.details));

	aes_setup(&key_e, &group->group_key);

	disk.v.nr_vtpms = native_be32(group->nr_vtpms);

	// regenerated
	src->disk_nr_inuse = 0;

	disk_write_vtpm_itree(src, 0, group->nr_pages, disk.v.vtpm_hash, disk.vtpm_location,
			NR_ENTRIES_PER_GROUP_BASE, &key_e, mgr);

	generate_group_seals(group, mgr);
	memcpy(&disk.v.boot_configs, &group->seal_bits, sizeof(group->seal_bits));

	aes_cmac(&disk.group_mac, &disk.v, sizeof(disk.v), &key_e);
	sha256(&src->disk_hash, &disk.v, sizeof(disk.v) + sizeof(disk.group_mac));
	disk_write_crypt_sector(&src->disk_loc, &disk, sizeof(disk), mgr);
}

/*
 * Write TPM seal blobs for the manager's keys, using the given group's list
 * of valid configurations
 */
static void disk_write_seal_list(struct mem_tpm_mgr *mgr, struct mem_group *group)
{
	int i;
	struct disk_seal_list *seal = disk_write_buf();
	struct disk_root_sealed_data sblob;

	if (mgr->root_seals_valid & (1 + mgr->active_root))
		return;

	memcpy(&sblob.magic, DISK_ROOT_BOUND_MAGIC, 4);
	memcpy(sblob.tpm_manager_uuid, mgr->uuid, 16);
	memcpy(&sblob.nvram_slot, &mgr->nvram_slot, 4);
	memcpy(&sblob.nvram_auth, &mgr->nvram_auth, 20);
	memcpy(&sblob.counter_index, &mgr->counter_index, 4);
	memcpy(&sblob.counter_auth, &mgr->counter_auth, 20);

	// TODO when an NV slot in the physical TPM is used to populate nv_key,
	// that value should be used to mask the master key so that the value
	// can be changed to revoke old disk state
#if 0
	aes_encrypt_one(&sblob.tm_key, &mgr->tm_key, &mgr->nv_key);
#else
	memcpy(&sblob.tm_key, &mgr->tm_key, 16);
#endif

	memset(seal, 0, sizeof(*seal));
	seal->length = native_be32(group->nr_seals);

	// TODO support for more entries
	if (group->nr_seals > SEALS_PER_ROOT_SEAL_LIST)
		abort();

	for(i=0; i < group->nr_seals; i++) {
		struct mem_seal *src = &group->seals[i];
		struct disk_seal_entry *dst = &seal->entry[i];
		dst->pcr_selection = src->pcr_selection;
		memcpy(&dst->digest_release, &src->digest_release, 20);
		TPM_pcr_digest(&dst->digest_at_seal, dst->pcr_selection);

        /*TPM 2.0 bind / TPM 1.x seal*/
        if (hw_is_tpm2())
            TPM2_disk_bind(dst, &sblob, sizeof(sblob));
        else
            TPM_disk_seal(dst, &sblob, sizeof(sblob));
	}

	memcpy(seal->hdr.magic, TPM_MGR_MAGIC, 12);
	seal->hdr.version = native_be32(TPM_MGR_VERSION);

	disk_write_sector(seal_loc(mgr), seal, sizeof(*seal));
	mgr->root_seals_valid |= 1 + mgr->active_root;
}

/*
 * Mark unchanged sectors on disk as being used
 */
static void disk_populate_used_mgr(const struct mem_tpm_mgr *mgr)
{
	int i;

	// TODO walk the linked lists for seals, rb_macs here (when supported)

	for(i=0; i < mgr->nr_groups; i++)
		disk_populate_used_group(&mgr->groups[i], mgr);
}

static void disk_write_group_itree(struct mem_tpm_mgr *mgr, int base, int nr_entries,
		struct hash256 *hash, sector_t *loc, int hsize);

static void disk_write_group_itree(struct mem_tpm_mgr *mgr, int base, int nr_entries,
		struct hash256 *hash, sector_t *loc, int hsize)
{
	int i, incr = 1;

	if (nr_entries <= hsize) {
		for(i=0; i < mgr->nr_groups; i++) {
			struct mem_group_hdr *group = mgr->groups + base + i;
			disk_write_group_sector(group, mgr);
			loc[i] = group->disk_loc;
			hash[i] = group->disk_hash;
		}
		return;
	}

	while (nr_entries > incr * hsize)
		incr *= NR_ENTRIES_PER_ITREE;

	for (i = 0; i * incr < nr_entries; i++) {
		struct disk_itree_sector pt;
		int child_entries = incr;

		// the last sector is not completely full
		if (nr_entries - i * incr < incr)
			child_entries = nr_entries - i * incr;

		disk_write_group_itree(mgr, base, child_entries, pt.hash, pt.location, NR_ENTRIES_PER_ITREE);

		sha256(&hash[i], &pt.hash, sizeof(pt.hash));
		disk_write_crypt_sector(&loc[i], &pt, sizeof(pt), mgr);

		base += incr;
	}
}

/*
 * Write out the root TPM Manager sector and its children
 */
static void disk_write_root_sector(struct mem_tpm_mgr *mgr)
{
	int i, j;
	struct disk_root_sector root;
	memset(&root, 0, sizeof(root));
	root.v.sequence = native_be64(mgr->sequence);
	root.v.tpm_counter_value = mgr->counter_value;

	root.v.nr_groups = native_be32(mgr->nr_groups);

	disk_write_group_itree(mgr, 0, mgr->nr_groups, root.v.group_hash, root.group_loc, NR_ENTRIES_PER_ROOT);

	i = 0;
	j = 0;
	while (i < mgr->nr_groups) {
		aes_context key_e;
		struct mem_group_hdr *group = &mgr->groups[i];
		struct mem_group *groupv = group->v;

		if (!groupv) {
			i++;
			continue;
		}
		if (groupv->details.flags.value & FLAG_ROLLBACK_DETECTED) {
			i++;
			continue;
		}
		if (j >= NR_RB_MACS_PER_ROOT)
			break; // TODO support for nr_rb_macs > 128

		aes_setup(&key_e, &groupv->rollback_mac_key);
		root.rb_macs[j].id = native_be32(i);
		aes_cmac(&root.rb_macs[j].mac, &root.v, sizeof(root.v), &key_e);
		i++; j++;
	}
	root.nr_rb_macs = native_be32(j);

	struct disk_crypt_sector_plain *root_sect = disk_write_buf();
	aes_encrypt_ctr(root_sect->iv_data, sizeof(root_sect->iv_data), &root, sizeof(root), &mgr->tm_key_e);
	aes_cmac(&root_sect->mac, &root_sect->data, sizeof(root_sect->data), &mgr->tm_key_e);
	disk_write_sector(root_loc(mgr), root_sect, sizeof(*root_sect));
}

/*
 * Write out changes to disk
 */
void disk_write_all(struct mem_tpm_mgr *mgr)
{
	disk_flush_slot(mgr);
	disk_populate_used_mgr(mgr);
	disk_write_root_sector(mgr);

	disk_write_seal_list(mgr, mgr->groups[0].v);

	disk_write_barrier();
}

/*
 * Create a new (blank) TPM Manager disk image.
 *
 * Does not actually write anything to disk.
 */
int vtpm_new_disk(void)
{
	int rc;
	struct mem_tpm_mgr *mgr = calloc(1, sizeof(*mgr));

	do_random(mgr->uuid, 16);
	do_random(&mgr->tm_key, 16);
	do_random(&mgr->nvram_auth, 20);
	do_random(&mgr->counter_auth, 20);
	do_random(&mgr->nv_key, 16);

	aes_setup(&mgr->tm_key_e, &mgr->tm_key);

	// TODO postpone these allocs until first write?
	rc = TPM_disk_nvalloc(&mgr->nvram_slot, mgr->nvram_auth);
	if (rc)
		return rc;

	rc = TPM_disk_alloc_counter(&mgr->counter_index, mgr->counter_auth, &mgr->counter_value);
	if (rc)
		return rc;

	mgr->nr_groups = 1;
	mgr->groups = calloc(1, sizeof(mgr->groups[0]));
	mgr->groups[0].v = vtpm_new_group(NULL);

	TPM_disk_nvwrite(&mgr->nv_key, 16, mgr->nvram_slot, mgr->nvram_auth);

	g_mgr = mgr;

	return 0;
}
