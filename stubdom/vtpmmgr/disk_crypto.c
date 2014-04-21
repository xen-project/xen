#include <inttypes.h>
#include <mini-os/byteorder.h>
#include <polarssl/aes.h>
#include <polarssl/sha2.h>
#include <polarssl/ctr_drbg.h>

#include "log.h"
#include "vtpmmgr.h"
#include "vtpm_disk.h"
#include "disk_io.h"
#include "disk_crypto.h"

// XXX defining this stubs out all disk encryption for easier debugging
#undef DISK_IS_PLAINTEXT

void do_random(void *buf, size_t size)
{
	int rc = ctr_drbg_random(&vtpm_globals.ctr_drbg, buf, size);
	if (rc) abort();
}

void aes_setup(aes_context *ctx, const struct key128 *key)
{
	aes_setkey_enc(ctx, (void*)key, 128);
}

static void aes_encrypt_ecb(void *target, const void *src, const aes_context *key_e)
{
	aes_crypt_ecb((void*)key_e, AES_ENCRYPT, src, target);
}

void aes_encrypt_one(void *target, const void *src, const struct key128 *key)
{
	aes_context ctx;
	aes_setkey_enc(&ctx, (void*)key, 128);
	aes_crypt_ecb(&ctx, AES_ENCRYPT, src, target);
}

void aes_decrypt_one(void *target, const void *src, const struct key128 *key)
{
	aes_context ctx;
	aes_setkey_dec(&ctx, (void*)key, 128);
	aes_crypt_ecb(&ctx, AES_DECRYPT, src, target);
}

static void aes_ctr_one(uint64_t out[2], uint64_t ctr[2], const aes_context *key_e)
{
#ifdef DISK_IS_PLAINTEXT
	memset(out, 0, 16);
#else
	aes_encrypt_ecb(out, ctr, key_e);
#endif
	ctr[1]++;
}

void aes_encrypt_ctr(void *target, size_t target_size, const void *srcv, size_t pt_size, const aes_context *key_e)
{
	uint64_t ctr[2];
	uint64_t tmp[2];
	uint64_t *dst = target;
	const uint64_t *src = srcv;

	do_random(ctr, sizeof(ctr));
	dst[0] = ctr[0];
	dst[1] = ctr[1];
	dst += 2;
	target_size -= 16;

	if (pt_size > target_size)
		abort(); // invalid argument: target too small for plaintext

	while (pt_size >= 16) {
		aes_ctr_one(tmp, ctr, key_e);

		dst[0] = tmp[0] ^ src[0];
		dst[1] = tmp[1] ^ src[1];

		dst += 2;
		src += 2;
		pt_size -= 16;
		target_size -= 16;
	}
	if (pt_size) {
		uint64_t stmp[2];
		uint64_t dtmp[2];
		memset(stmp, 0, 16);
		memcpy(stmp, src, pt_size);

		aes_ctr_one(tmp, ctr, key_e);

		dtmp[0] = tmp[0] ^ stmp[0];
		dtmp[1] = tmp[1] ^ stmp[1];
		if (target_size < 16) {
			memcpy(dst, dtmp, target_size);
			return;
		} else {
			memcpy(dst, dtmp, 16);
			target_size -= 16;
		}
	}
	while (target_size >= 16) {
		aes_ctr_one(dst, ctr, key_e);

		dst += 2;
		target_size -= 16;
	}
	if (target_size)
		abort(); // invalid argument: overlarge target size is not a full block
}

void aes_decrypt_ctr(void *target, size_t pt_size, const void *srcv, size_t src_size, const aes_context *key_e)
{
	uint64_t ctr[2];
	uint64_t tmp[2];
	uint64_t *dst = target;
	const uint64_t *src = srcv;

	ctr[0] = src[0];
	ctr[1] = src[1];
	src += 2;
	src_size -= 16;

	if (pt_size > src_size)
		abort(); // invalid argument: source too small for plaintext
	// we discard src_size now

	while (pt_size >= 16) {
		aes_ctr_one(tmp, ctr, key_e);
		dst[0] = tmp[0] ^ src[0];
		dst[1] = tmp[1] ^ src[1];

		dst += 2;
		src += 2;
		pt_size -= 16;
	}
	if (pt_size) {
		uint64_t stmp[2];
		uint64_t dtmp[2];
		memset(stmp, 0, 16);
		memcpy(stmp, src, pt_size);

		aes_ctr_one(tmp, ctr, key_e);

		dtmp[0] = tmp[0] ^ stmp[0];
		dtmp[1] = tmp[1] ^ stmp[1];
		memcpy(dst, dtmp, pt_size);
	}
}

static void shl_128_mod_hex87(struct mac128 *dst, const struct mac128 *src)
{
	int i;
	int carry = 0x87 * !!(src->bits[0] & 0x80);
	for(i=0; i < 15; i++)
		dst->bits[i] = (src->bits[i] << 1) | (src->bits[i+1] >> 7);
	dst->bits[15] = (src->bits[15] << 1) ^ carry;
}

static void xor128(struct mac128 *dst, const struct mac128 *s1, const struct mac128 *s2)
{
	int i;
	for(i=0; i < 16; i++)
		dst->bits[i] = s1->bits[i] ^ s2->bits[i];
}

void aes_cmac(struct mac128 *target, const void *src, size_t size, const aes_context *key)
{
	const struct mac128 *M = src;
	struct mac128 x, y, L, K1, K2;
	int i;
	size_t bsize = (size - 1) / 16;

	memset(&x, 0, sizeof(x));
	aes_encrypt_ecb(&L, &x, key);
	shl_128_mod_hex87(&K1, &L);
	shl_128_mod_hex87(&K2, &K1);

	for(i=0; i < bsize; i++) {
		xor128(&y, &x, &M[i]);
		aes_encrypt_ecb(&x, &y, key);
	}
	if (size & 0xF) {
		struct mac128 z;
		memset(&z, 0, sizeof(z));
		memcpy(&z, M + bsize, size & 0xF);
		xor128(&y, &x, &K2);
		xor128(&x, &y, &z);
	} else {
		xor128(&y, &x, &K1);
		xor128(&x, &y, M + bsize);
	}
	aes_encrypt_ecb(target, &x, key);
}

static int verify_128(const void *a, const void* b)
{
	const volatile uint64_t *x = a;
	const volatile uint64_t *y = b;
	if ((x[0] ^ y[0]) | (x[1] ^ y[1]))
		return 1;
	return 0;
}

int aes_cmac_verify(const struct mac128 *target, const void *src, size_t size, const aes_context *key)
{
	struct mac128 mac;
	aes_cmac(&mac, src, size, key);
	return verify_128(&mac, target);
}

static int verify_256(const void *a, const void* b)
{
	const volatile uint64_t *x = a;
	const volatile uint64_t *y = b;
	if ((x[0] ^ y[0]) | (x[1] ^ y[1]) | (x[2] ^ y[2]) | (x[3] ^ y[3]))
		return 1;
	return 0;
}

void sha256(struct hash256 *target, const void *src, size_t size)
{
	void* dst = target;
	sha2(src, size, dst, 0);
}

int sha256_verify(const struct hash256 *targ, const void *data, size_t size)
{
	struct hash256 hash;
	sha256(&hash, data, size);
	return verify_256(&hash, targ);
}
