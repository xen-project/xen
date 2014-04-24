/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * based off of the original tools/vtpm_manager code base which is:
 * Copyright (c) 2005, Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <mini-os/console.h>
#include <polarssl/sha1.h>
#include <polarssl/sha2.h>

#include "marshal.h"
#include "log.h"
#include "vtpm_disk.h"
#include "vtpmmgr.h"
#include "tpm.h"
#include "tpmrsa.h"
#include "tcg.h"
#include "mgmt_authority.h"
#include "disk_crypto.h"

static void gen_random_uuid(uuid_t uuid)
{
	do_random(uuid, 16);
	// make the 128-bit random number a valid UUID (122 bits remain)
	uuid[6] = 0x40 | (uuid[6] & 0x0F);
	uuid[8] = 0x80 | (uuid[8] & 0x3F);
}

/*
 * Instead of using a kernel hash, which requires a trusted domain builder to
 * report, use the XSM label as a substitute.
 */
static TPM_RESULT find_vtpm_khash(int domid, struct tpm_opaque *opq)
{
	char buf[128];
	int i, rv;
	buf[127] = 0;
	rv = tpmback_get_peercontext(opq->domid, opq->handle, buf, sizeof(buf) - 1);
	if (rv < 0)
		return TPM_FAIL;

	sha1((void*)buf, strlen(buf), opq->kern_hash);

	/*
	 * As a hack to support the use of the XSM user field as an optional
	 * wildcard, check the hash against the group here. If it fails, replace
	 * the user field with a "*" and return the hash of that value.
	 */
	for(i=0; i < be32_native(opq->group->seal_bits.nr_kerns); i++) {
		if (!memcmp(opq->group->seal_bits.kernels[i].bits, opq->kern_hash, 20)) {
			return TPM_SUCCESS;
		}
	}

	char* upos = strchr(buf, ':');
	if (upos == NULL || upos == buf)
		return TPM_SUCCESS;

	upos--;
	upos[0] = '*';

	sha1((void*)upos, strlen(upos), opq->kern_hash);
	return TPM_SUCCESS;
}

static TPM_RESULT find_vtpm_verified(int domid, struct tpm_opaque *opq)
{
	TPM_RESULT rc;
	int i;
	if (opq->vtpm)
		return TPM_SUCCESS;

	rc = find_vtpm(&opq->group, &opq->vtpm, *opq->uuid);
	if (rc)
		return TPM_BAD_PARAMETER;

	if (opq->vtpm->flags & VTPM_FLAG_OPEN) {
		printk("Attempted to open vTPM twice!\n");
		opq->vtpm = NULL;
		opq->group = NULL;
		return TPM_DISABLED;
	}

	rc = find_vtpm_khash(domid, opq);
	if (rc)
		return rc;

	for(i=0; i < be32_native(opq->group->seal_bits.nr_kerns); i++) {
		if (!memcmp(opq->group->seal_bits.kernels[i].bits, opq->kern_hash, 20)) {
			opq->vtpm->flags |= VTPM_FLAG_OPEN;
			return TPM_SUCCESS;
		}
	}
	printk("Unauthorized vTPM kernel image used!\n");
	return TPM_DISABLED;
}

static TPM_RESULT vtpmmgr_SaveHashKey(struct tpm_opaque *opq, tpmcmd_t* tpmcmd)
{
	TPM_RESULT status = TPM_SUCCESS;
	int rc = 0;

	size_t bufsize = tpmcmd->req_len - VTPM_COMMAND_HEADER_SIZE;
	const void *buf = tpmcmd->req + VTPM_COMMAND_HEADER_SIZE;

	if (bufsize < 52) {
		vtpmlogerror(VTPM_LOG_VTPM, "VTPM_ORD_SAVEHASHKEY hashkey too short!\n");
		status = TPM_BAD_PARAMETER;
		goto abort_egress;
	}
	if (bufsize > 64) {
		vtpmlogerror(VTPM_LOG_VTPM, "VTPM_ORD_SAVEHASHKEY hashkey too long!\n");
		status = TPM_BAD_PARAMETER;
		goto abort_egress;
	}

	vtpmloginfo(VTPM_LOG_VTPM, "vtpmmgr_SaveHashKey\n");
	status = find_vtpm_verified(tpmcmd->domid, opq);

	// auto-create vTPMs in group0 when saving a new UUID
	// TODO restrict to certain UUIDs (such as all-zero)
	// this is not done yet to simplify use of the TPM Manager
	if (status == TPM_BAD_PARAMETER) {
		opq->group = g_mgr->groups[0].v;
		rc = create_vtpm(opq->group, &opq->vtpm, *opq->uuid);
		if (rc) {
			status = TPM_BAD_PARAMETER;
			goto abort_egress;
		}
		if (opq->group->nr_vtpms == 1)
			opq->vtpm->flags = VTPM_FLAG_ADMIN;
		printk("SaveHashKey with unknown UUID="UUID_FMT" - creating in auth0 (f=%d)\n",
				UUID_BYTES((*opq->uuid)), opq->vtpm->flags);
		status = TPM_SUCCESS;
	}
	if (status)
		goto abort_egress;

	memcpy(opq->vtpm->data, buf, bufsize);
	memset(opq->vtpm->data + bufsize, 0, 64 - bufsize);

	vtpm_sync(opq->group, opq->vtpm);

abort_egress:
	pack_TPM_RSP_HEADER(tpmcmd->resp, VTPM_TAG_RSP, VTPM_COMMAND_HEADER_SIZE, status);
	tpmcmd->resp_len = VTPM_COMMAND_HEADER_SIZE;

	return status;
}

static TPM_RESULT vtpmmgr_LoadHashKey(struct tpm_opaque *opq, tpmcmd_t* tpmcmd)
{
	TPM_RESULT status = TPM_SUCCESS;
	int i;
	uint8_t *buf = tpmcmd->resp + VTPM_COMMAND_HEADER_SIZE;

	vtpmloginfo(VTPM_LOG_VTPM, "vtpmmgr_LoadHashKey\n");
	tpmcmd->resp_len = VTPM_COMMAND_HEADER_SIZE;

	status = find_vtpm_verified(tpmcmd->domid, opq);
	if (status)
		goto abort_egress;

	memcpy(buf, opq->vtpm->data, 64);

	for(i=52; i < 64; i++) {
		if (buf[i]) {
			tpmcmd->resp_len += 64;
			goto abort_egress;
		}
	}
	tpmcmd->resp_len += 52;

abort_egress:
	pack_TPM_RSP_HEADER(tpmcmd->resp, VTPM_TAG_RSP, tpmcmd->resp_len, status);

	return status;
}

#define CMD_BEGIN \
	TPM_RESULT status = TPM_SUCCESS; \
	uint32_t in_pos = VTPM_COMMAND_HEADER_SIZE; \
	tpmcmd->resp_len = VTPM_COMMAND_HEADER_SIZE; \
	vtpmloginfo(VTPM_LOG_TPM, "%s\n", __func__);

#define CMD_END \
 abort_egress: \
	if (status) \
		tpmcmd->resp_len = VTPM_COMMAND_HEADER_SIZE; \
	pack_TPM_RSP_HEADER(tpmcmd->resp, VTPM_TAG_RSP, tpmcmd->resp_len, status); \
	return status

#define UNPACK_IN(type, item...) do { \
	status = unpack3_ ## type (tpmcmd->req, &in_pos, tpmcmd->req_len, item); \
	if (status) { \
		status = TPM_BAD_PARAMETER; \
		goto abort_egress; \
	} \
} while (0)

#define UNPACK_GROUP(group) do { \
	uint32_t group_idx; \
	UNPACK_IN(UINT32, &group_idx); \
	if (group_idx >= g_mgr->nr_groups) { \
		status = TPM_BADINDEX; \
		goto abort_egress; \
	} \
	group = g_mgr->groups[group_idx].v; \
	if (!group) { \
		status = TPM_AUTHFAIL; \
		goto abort_egress; \
	} \
} while (0)

#define UNPACK_DONE() do { \
	if (in_pos != tpmcmd->req_len) { \
		status = TPM_BAD_PARAMETER; \
		goto abort_egress; \
	} \
} while (0)

#define PACK_OUT(type, item...) do { \
	UINT32 isize = sizeof_ ## type(item); \
	if (isize + tpmcmd->resp_len > TCPA_MAX_BUFFER_LENGTH) { \
		status = TPM_SIZE; \
		goto abort_egress; \
	} \
	pack_ ## type (tpmcmd->resp + tpmcmd->resp_len, item); \
	tpmcmd->resp_len += isize; \
} while (0)

#define PACK_BUF ((void*)(tpmcmd->resp + tpmcmd->resp_len))

static TPM_RESULT vtpmmgr_GetBootHash(struct tpm_opaque *opq, tpmcmd_t* tpmcmd)
{
	CMD_BEGIN;
	UNPACK_DONE();

	PACK_OUT(BUFFER, opq->kern_hash, 20);

	CMD_END;
}

static TPM_RESULT vtpmmgr_GetQuote(struct tpm_opaque *opq, tpmcmd_t* tpmcmd)
{
	CMD_BEGIN;
	int i;
	void *ibuf;
	uint32_t pcr_size;
	TPM_PCR_SELECTION sel;

	UNPACK_IN(VPTR, &ibuf, 20, UNPACK_ALIAS);
	UNPACK_IN(TPM_PCR_SELECTION, &sel, UNPACK_ALIAS);
	UNPACK_DONE();

	if (!opq->vtpm) {
		status = TPM_BAD_PARAMETER;
		goto abort_egress;
	}

	printk("ibuf: ");
	for (i=0; i < 20; i++)
		printk("%02x", ((uint8_t*)ibuf)[i]);
	printk("\n");

	status = vtpm_do_quote(opq->group, *opq->uuid, opq->kern_hash, ibuf, &sel, PACK_BUF + 256, &pcr_size, PACK_BUF);
	if (status)
		goto abort_egress;
	tpmcmd->resp_len += 256 + pcr_size;

	CMD_END;
}

static TPM_RESULT vtpmmgr_GroupList(tpmcmd_t* tpmcmd)
{
	CMD_BEGIN;
	UNPACK_DONE();
	PACK_OUT(UINT32, g_mgr->nr_groups);
	CMD_END;
}

static TPM_RESULT vtpmmgr_GroupNew(tpmcmd_t* tpmcmd)
{
	void *privCADigest;
	BYTE *pubkey;
	struct mem_group *group;
	uint32_t group_idx;
	CMD_BEGIN;

	UNPACK_IN(VPTR, &privCADigest, 20, UNPACK_ALIAS);
	UNPACK_IN(PTR, &pubkey, 256, UNPACK_ALIAS);
	UNPACK_DONE();

	group = vtpm_new_group(privCADigest);
	if (!group) {
		status = TPM_FAIL;
		goto abort_egress;
	}

	memcpy(group->id_data.saa_pubkey, pubkey, 256);

	PACK_OUT(BUFFER, group->id_data.uuid, 16);
	PACK_OUT(BUFFER, group->id_data.tpm_aik_public, 256);
	PACK_OUT(BUFFER, group->details.recovery_data, 256);

	memset(group->details.recovery_data, 0, 256);

	group->details.sequence = native_be64(g_mgr->sequence);

	if (group != g_mgr->groups[0].v) {
		group_idx = g_mgr->nr_groups;
		g_mgr->nr_groups++;
		g_mgr->groups = realloc(g_mgr->groups, g_mgr->nr_groups*sizeof(struct mem_group_hdr));
		memset(&g_mgr->groups[group_idx], 0, sizeof(g_mgr->groups[0]));
		g_mgr->groups[group_idx].v = group;
	}

	vtpm_sync_group(group, SEQ_UPDATE);
	CMD_END;
}

static TPM_RESULT vtpmmgr_GroupDel(tpmcmd_t* tpmcmd)
{
	CMD_BEGIN;
	struct mem_group *group;
	uint32_t group_idx, nr_mov;

	UNPACK_IN(UINT32, &group_idx);
	UNPACK_DONE();

	if (group_idx > g_mgr->nr_groups) {
		status = TPM_BADINDEX;
		goto abort_egress;
	}
	group = g_mgr->groups[group_idx].v;

	if (group) {
		int i, j;
		for (i = 0; i < group->nr_pages; i++) {
			for (j = 0; j < group->data[i].size; j++) {
				if (group->data[i].vtpms[j]->flags & VTPM_FLAG_OPEN) {
					status = TPM_FAIL;
					goto abort_egress;
				}
			}
		}

		for (i = 0; i < group->nr_pages; i++) {
			for (j = 0; j < group->data[i].size; j++) {
				free(group->data[i].vtpms[j]);
			}
		}
		free(group->data);
		free(group->seals);
		free(group);
	}

	g_mgr->nr_groups--;
	nr_mov = g_mgr->nr_groups - group_idx;
	memmove(&g_mgr->groups[group_idx], &g_mgr->groups[group_idx + 1], nr_mov * sizeof(g_mgr->groups[0]));

	vtpm_sync_disk(g_mgr, CTR_UPDATE);

	CMD_END;
}

static int pack_cfg_list(void* buf, struct mem_group *group)
{
	int i;
	void *bstart = buf;
	memcpy(buf, &group->details.cfg_seq, 8); buf += 8;
	buf = pack_UINT32(buf, group->nr_seals);
	for(i=0; i < group->nr_seals; i++) {
		memcpy(buf, &group->seals[i].digest_release, 20);
		buf += 20;
	}
	memcpy(buf, &group->seal_bits.nr_kerns, 4); buf += 4;
	memcpy(buf, &group->seal_bits.kernels, 20 * be32_native(group->seal_bits.nr_kerns));
	return buf - bstart + 20 * be32_native(group->seal_bits.nr_kerns);
}

static TPM_RESULT vtpmmgr_GroupShow(tpmcmd_t* tpmcmd)
{
	CMD_BEGIN;
	struct mem_group *group;

	UNPACK_GROUP(group);
	UNPACK_DONE();

	// TODO show is read-only access, need to hit disk if group is NULL

	PACK_OUT(BUFFER, group->id_data.uuid, 16);
	PACK_OUT(BUFFER, group->id_data.saa_pubkey, 256);
	tpmcmd->resp_len += pack_cfg_list(PACK_BUF, group);

	CMD_END;
}

static TPM_RESULT vtpmmgr_GroupActivate(tpmcmd_t* tpmcmd)
{
	CMD_BEGIN;
	struct mem_group *group;
	uint32_t blobSize;
	void *blob;

	UNPACK_GROUP(group);
	UNPACK_IN(UINT32, &blobSize);
	UNPACK_IN(VPTR, &blob, blobSize, UNPACK_ALIAS);
	UNPACK_DONE();

	status = group_do_activate(group, blob, blobSize, tpmcmd->resp, &tpmcmd->resp_len);

	CMD_END;
}

/* 2048-bit MODP Group from RFC3526:
 *   2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
 * mpi objects use little endian word ordering
 */
static t_uint Pp[256 / sizeof(t_uint)] = {
#ifdef __x86_64__
	0xFFFFFFFFFFFFFFFFUL, 0x15728E5A8AACAA68UL, 0x15D2261898FA0510UL,
	0x3995497CEA956AE5UL, 0xDE2BCBF695581718UL, 0xB5C55DF06F4C52C9UL,
	0x9B2783A2EC07A28FUL, 0xE39E772C180E8603UL, 0x32905E462E36CE3BUL,
	0xF1746C08CA18217CUL, 0x670C354E4ABC9804UL, 0x9ED529077096966DUL,
	0x1C62F356208552BBUL, 0x83655D23DCA3AD96UL, 0x69163FA8FD24CF5FUL,
	0x98DA48361C55D39AUL, 0xC2007CB8A163BF05UL, 0x49286651ECE45B3DUL,
	0xAE9F24117C4B1FE6UL, 0xEE386BFB5A899FA5UL, 0x0BFF5CB6F406B7EDUL,
	0xF44C42E9A637ED6BUL, 0xE485B576625E7EC6UL, 0x4FE1356D6D51C245UL,
	0x302B0A6DF25F1437UL, 0xEF9519B3CD3A431BUL, 0x514A08798E3404DDUL,
	0x020BBEA63B139B22UL, 0x29024E088A67CC74UL, 0xC4C6628B80DC1CD1UL,
	0xC90FDAA22168C234UL, 0xFFFFFFFFFFFFFFFFUL,
#else
	0xFFFFFFFF, 0xFFFFFFFF, 0x8AACAA68, 0x15728E5A, 0x98FA0510, 0x15D22618,
	0xEA956AE5, 0x3995497C, 0x95581718, 0xDE2BCBF6, 0x6F4C52C9, 0xB5C55DF0,
	0xEC07A28F, 0x9B2783A2, 0x180E8603, 0xE39E772C, 0x2E36CE3B, 0x32905E46,
	0xCA18217C, 0xF1746C08, 0x4ABC9804, 0x670C354E, 0x7096966D, 0x9ED52907,
	0x208552BB, 0x1C62F356, 0xDCA3AD96, 0x83655D23, 0xFD24CF5F, 0x69163FA8,
	0x1C55D39A, 0x98DA4836, 0xA163BF05, 0xC2007CB8, 0xECE45B3D, 0x49286651,
	0x7C4B1FE6, 0xAE9F2411, 0x5A899FA5, 0xEE386BFB, 0xF406B7ED, 0x0BFF5CB6,
	0xA637ED6B, 0xF44C42E9, 0x625E7EC6, 0xE485B576, 0x6D51C245, 0x4FE1356D,
	0xF25F1437, 0x302B0A6D, 0xCD3A431B, 0xEF9519B3, 0x8E3404DD, 0x514A0879,
	0x3B139B22, 0x020BBEA6, 0x8A67CC74, 0x29024E08, 0x80DC1CD1, 0xC4C6628B,
	0x2168C234, 0xC90FDAA2, 0xFFFFFFFF, 0xFFFFFFFF,
#endif
};
static t_uint Gp[] = { 2 };

static void tm_dhkx_gen(void* dhkx1, void* dhkx2, void* out)
{
	mpi GX = { 0 }, GY = { 0 }, K = { 0 }, RP = { 0 };

	int XpElts = 256 / sizeof(t_uint);
	t_uint Xp[XpElts];
	mpi X = {
		.s = 1,
		.n = XpElts,
		.p = Xp
	};
	mpi P = {
		.s = 1,
		.n = XpElts,
		.p = Pp,
	};
	mpi G = {
		.s = 1,
		.n = 1,
		.p = Gp,
	};

	do_random(Xp, sizeof(Xp));
	while (Xp[XpElts - 1] == 0 || Xp[XpElts - 1] == -1UL)
		do_random(Xp + XpElts - 1, sizeof(Xp[0]));

	mpi_exp_mod(&GX, &G, &X, &P, &RP);
	mpi_write_binary(&GX, dhkx2, 256);
	mpi_free(&GX);

	mpi_read_binary(&GY, dhkx1, 256);
	mpi_exp_mod(&K, &GY, &X, &P, &RP);
	mpi_free(&RP);
	mpi_free(&GY);

	mpi_write_binary(&K, (void*)Xp, 256);
	mpi_free(&K);
	sha2((void*)Xp, 256, out, 0);
}

static void xor2_256b(void *xv, const void* yv)
{
	int i;
	uint64_t *x = xv;
	const uint64_t *y = yv;
	for(i=0; i < 4; i++)
		x[i] ^= y[i];
}

static TPM_RESULT vtpmmgr_GroupRegister(tpmcmd_t* tpmcmd)
{
	CMD_BEGIN;
	struct mem_group *group = NULL;
	tpmrsa_context saa_rsa = TPMRSA_CTX_INIT;
	struct tpm_authdata digest;
	sha1_context ctx;
	TPM_PCR_SELECTION sel;
	void *dhkx1, *dhkx2, *gk, *sig;

	UNPACK_GROUP(group);
	UNPACK_IN(VPTR, &dhkx1, 256, UNPACK_ALIAS);
	UNPACK_IN(VPTR, &sig, 256, UNPACK_ALIAS);
	UNPACK_IN(TPM_PCR_SELECTION, &sel, UNPACK_ALIAS);
	UNPACK_DONE();

	/* Only generating this quote during the same boot that this group was
	 * created in allows the quote to prove that the group key has never
	 * been available outside a configuration approved by its SAA.
	 */
	if (!(group->flags & MEM_GROUP_FLAG_FIRSTBOOT)) {
		status = TPM_FAIL;
		goto abort_egress;
	}

	sha1(dhkx1, 256, digest.bits);
	tpmrsa_set_pubkey(&saa_rsa, group->id_data.saa_pubkey, 256, 0, 0);
	if (tpmrsa_sigcheck(&saa_rsa, sig, digest.bits))
		status = TPM_FAIL;
	tpmrsa_free(&saa_rsa);
	if (status)
		goto abort_egress;

	dhkx2 = PACK_BUF;
	tpmcmd->resp_len += 256;
	gk = PACK_BUF;
	tpmcmd->resp_len += 32;

	tm_dhkx_gen(dhkx1, dhkx2, gk);
	xor2_256b(gk, &group->group_key);

	sha1_starts(&ctx);
	sha1_update(&ctx, (void*)"REGR", 4);
	sha1_update(&ctx, dhkx1, 256);
	sha1_update(&ctx, dhkx2, 256 + 32);
	sha1_finish(&ctx, digest.bits);

	status = vtpm_do_quote(group, NULL, NULL, &digest, &sel, NULL, NULL, PACK_BUF);
	tpmcmd->resp_len += 256;

	CMD_END;
}

static TPM_RESULT vtpmmgr_GroupUpdate(tpmcmd_t* tpmcmd)
{
	CMD_BEGIN;
	struct mem_group *group;
	int i;
	int hstart;
	uint32_t nr_kerns, nr_seals;
	uint64_t old_seq, new_seq;
	struct mem_seal *seals = NULL;
	tpmrsa_context saa_rsa = TPMRSA_CTX_INIT;
	unsigned char digest[20];
	TPM_RESULT rc;
	void *sig, *seal_bits, *kern_bits;

	UNPACK_GROUP(group);
	UNPACK_IN(VPTR, &sig, 256, UNPACK_ALIAS);

	// Hash starts here
	hstart = in_pos;

	new_seq = be64_native(*(be64_t*)(tpmcmd->req + in_pos));
	old_seq = be64_native(group->details.cfg_seq);
	in_pos += 8;
	if (old_seq > new_seq) {
		status = TPM_FAIL;
		goto abort_egress;
	}

	UNPACK_IN(UINT32, &nr_seals);
	UNPACK_IN(VPTR, &seal_bits, nr_seals * 20, UNPACK_ALIAS);

	UNPACK_IN(UINT32, &nr_kerns);
	UNPACK_IN(VPTR, &kern_bits, nr_kerns * 20, UNPACK_ALIAS);

	// TODO handle saving larger lists on disk
	if (nr_seals > NR_SEALS_PER_GROUP) {
		status = TPM_SIZE;
		goto abort_egress;
	}

	if (nr_kerns > NR_KERNS_PER_GROUP) {
		status = TPM_SIZE;
		goto abort_egress;
	}

	sha1(tpmcmd->req + hstart, in_pos - hstart, digest);

	seals = calloc(nr_seals, sizeof(seals[0]));

	for(i=0; i < nr_seals; i++) {
		TPM_PCR_SELECTION sel;
		UNPACK_IN(TPM_PCR_SELECTION, &sel, UNPACK_ALIAS);
		memcpy(&seals[i].digest_release, seal_bits, 20);
		seal_bits += 20;
		if (sel.sizeOfSelect > 4) {
			status = TPM_BAD_PARAMETER;
			goto abort_egress;
		}
		seals[i].pcr_selection = native_le32(0);
		memcpy(&seals[i].pcr_selection, sel.pcrSelect, sel.sizeOfSelect);
	}

	UNPACK_DONE();

	tpmrsa_set_pubkey(&saa_rsa, group->id_data.saa_pubkey, 256, 0, 0);
	rc = tpmrsa_sigcheck(&saa_rsa, sig, digest);
	tpmrsa_free(&saa_rsa);
	if (rc) {
		printk("sigcheck failed: %d\n", rc);
		status = rc;
		goto abort_egress;
	}

	// Commit
	free(group->seals);

	memcpy(&group->seal_bits.kernels, kern_bits, 20 * nr_kerns);
	group->details.cfg_seq = native_be64(new_seq);
	group->nr_seals = nr_seals;
	group->seals = seals;
	group->seal_bits.nr_kerns = native_be32(nr_kerns);

	seals = NULL;

	group->flags &= ~MEM_GROUP_FLAG_SEAL_VALID;
	if (group == g_mgr->groups[0].v)
		g_mgr->root_seals_valid = 0;

	// TODO use GROUP_KEY_UPDATE or MGR_KEY_UPDATE here?
	// only required if this update was to address a potential key leak
	vtpm_sync_group(group, SEQ_UPDATE);

 abort_egress:
	free(seals);

	pack_TPM_RSP_HEADER(tpmcmd->resp, VTPM_TAG_RSP, tpmcmd->resp_len, status);
	return status;
}

static TPM_RESULT vtpmmgr_VtpmList(tpmcmd_t* tpmcmd)
{
	CMD_BEGIN;
	struct mem_group *group;
	uint32_t vtpm_offset;
	int i, j;

	UNPACK_GROUP(group);
	UNPACK_IN(UINT32, &vtpm_offset);

	PACK_OUT(UINT32, group->nr_vtpms);
	if (vtpm_offset > group->nr_vtpms)
		goto egress;

	for(i=0; i < group->nr_pages; i++) {
		struct mem_vtpm_page *pg = &group->data[i];
		for(j=0; j < pg->size; j++) {
			if (vtpm_offset) {
				// TODO a proper seek would be far faster
				vtpm_offset--;
				continue;
			}
			memcpy(PACK_BUF, pg->vtpms[j]->uuid, 16);
			tpmcmd->resp_len += 16;
			if (tpmcmd->resp_len + 16 > TCPA_MAX_BUFFER_LENGTH)
				goto egress;
		}
	}

 egress:
	CMD_END;
}

static TPM_RESULT vtpmmgr_VtpmNew(tpmcmd_t* tpmcmd)
{
	CMD_BEGIN;
	struct mem_group *group;
	struct mem_vtpm *vtpm;
	uuid_t newuuid;
	int rc;

	UNPACK_GROUP(group);

	// XXX allow non-random UUIDs for testing
	if (tpmcmd->req_len == 14 + 16)
		UNPACK_IN(BUFFER, newuuid, 16);
	else
		gen_random_uuid(newuuid);
	UNPACK_DONE();

	rc = create_vtpm(group, &vtpm, newuuid);
	if (rc) {
		status = TPM_FAIL;
		goto abort_egress;
	}
	memset(vtpm->data, 0, 64);
	vtpm_sync(group, vtpm);

	PACK_OUT(BUFFER, newuuid, 16);
	CMD_END;
}

static TPM_RESULT vtpmmgr_VtpmDel(tpmcmd_t* tpmcmd)
{
	CMD_BEGIN;
	uuid_t uuid;
	struct mem_group *group;
	struct mem_vtpm *vtpm;
	int rc;

	UNPACK_IN(BUFFER, uuid, 16);
	UNPACK_DONE();
	rc = find_vtpm(&group, &vtpm, uuid);
	if (rc) {
		status = TPM_FAIL;
		goto abort_egress;
	}

	if (vtpm->flags & VTPM_FLAG_OPEN) {
		status = TPM_FAIL;
		goto abort_egress;
	}

	delete_vtpm(group, vtpm);

	CMD_END;
}

static int vtpmmgr_permcheck(struct tpm_opaque *opq)
{
	if (!opq->vtpm)
		return 1;
	if (opq->vtpm->flags & VTPM_FLAG_ADMIN)
		return 0;
	return 1;
}

TPM_RESULT vtpmmgr_handle_cmd(
		struct tpm_opaque *opaque,
		tpmcmd_t* tpmcmd)
{
	TPM_RESULT status = TPM_SUCCESS;
	TPM_TAG tag;
	UINT32 size;
	TPM_COMMAND_CODE ord;

	unpack_TPM_RQU_HEADER(tpmcmd->req,
			&tag, &size, &ord);

	/* Handle the command now */
	switch(tag) {
	case VTPM_TAG_REQ:
		// This is a vTPM command
		switch(ord) {
		case VTPM_ORD_SAVEHASHKEY:
			return vtpmmgr_SaveHashKey(opaque, tpmcmd);
		case VTPM_ORD_LOADHASHKEY:
			return vtpmmgr_LoadHashKey(opaque, tpmcmd);
		case VTPM_ORD_GET_BOOT_HASH:
			return vtpmmgr_GetBootHash(opaque, tpmcmd);
		case VTPM_ORD_GET_QUOTE:
			return vtpmmgr_GetQuote(opaque, tpmcmd);
		default:
			vtpmlogerror(VTPM_LOG_VTPM, "Invalid vTPM Ordinal %" PRIu32 "\n", ord);
			status = TPM_BAD_ORDINAL;
		}
		break;
	case VTPM_TAG_REQ2:
		// This is a management command
		if (vtpmmgr_permcheck(opaque)) {
			status = TPM_AUTHFAIL;
			vtpmlogerror(VTPM_LOG_VTPM, "Rejected attempt to use management command from client\n");
			break;
		}
		switch (ord) {
		case VTPM_ORD_GROUP_LIST:
			return vtpmmgr_GroupList(tpmcmd);
		case VTPM_ORD_GROUP_NEW:
			return vtpmmgr_GroupNew(tpmcmd);
		case VTPM_ORD_GROUP_DEL:
			return vtpmmgr_GroupDel(tpmcmd);
		case VTPM_ORD_GROUP_ACTIVATE:
			return vtpmmgr_GroupActivate(tpmcmd);
		case VTPM_ORD_GROUP_REGISTER:
			return vtpmmgr_GroupRegister(tpmcmd);
		case VTPM_ORD_GROUP_UPDATE:
			return vtpmmgr_GroupUpdate(tpmcmd);
		case VTPM_ORD_GROUP_SHOW:
			return vtpmmgr_GroupShow(tpmcmd);
		case VTPM_ORD_VTPM_LIST:
			return vtpmmgr_VtpmList(tpmcmd);
		case VTPM_ORD_VTPM_NEW:
			return vtpmmgr_VtpmNew(tpmcmd);
		case VTPM_ORD_VTPM_DEL:
			return vtpmmgr_VtpmDel(tpmcmd);
		default:
			vtpmlogerror(VTPM_LOG_VTPM, "Invalid TM Ordinal %" PRIu32 "\n", ord);
			status = TPM_BAD_ORDINAL;
		}
		break;
	case TPM_TAG_RQU_COMMAND:
	case TPM_TAG_RQU_AUTH1_COMMAND:
	case TPM_TAG_RQU_AUTH2_COMMAND:
		//This is a TPM passthrough command
		switch(ord) {
		case TPM_ORD_GetRandom:
			vtpmloginfo(VTPM_LOG_VTPM, "Passthrough: TPM_GetRandom\n");
			break;
		case TPM_ORD_PcrRead:
			vtpmloginfo(VTPM_LOG_VTPM, "Passthrough: TPM_PcrRead\n");
			// Quotes also need to be restricted to hide PCR values
			break;
		case TPM_ORD_Extend:
			// TODO allow to certain clients? A malicious client
			// could scramble PCRs and make future quotes invalid.
			if (vtpmmgr_permcheck(opaque)) {
				vtpmlogerror(VTPM_LOG_VTPM, "Disallowed TPM_Extend\n");
				status = TPM_DISABLED_CMD;
				goto abort_egress;
			} else {
				vtpmloginfo(VTPM_LOG_VTPM, "Passthrough: TPM_Extend\n");
			}
			break;
		default:
			vtpmlogerror(VTPM_LOG_VTPM, "TPM Disallowed Passthrough ord=%" PRIu32 "\n", ord);
			status = TPM_DISABLED_CMD;
			goto abort_egress;
		}

		size = TCPA_MAX_BUFFER_LENGTH;
		TPMTRYRETURN(TPM_TransmitData(tpmcmd->req, tpmcmd->req_len, tpmcmd->resp, &size));
		tpmcmd->resp_len = size;

		return TPM_SUCCESS;
	default:
		vtpmlogerror(VTPM_LOG_VTPM, "Invalid tag=%" PRIu16 "\n", tag);
		status = TPM_BADTAG;
	}

abort_egress:
	tpmcmd->resp_len = VTPM_COMMAND_HEADER_SIZE;
	pack_TPM_RSP_HEADER(tpmcmd->resp, tag + 3, tpmcmd->resp_len, status);

	return status;
}
