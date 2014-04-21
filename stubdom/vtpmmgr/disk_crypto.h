#ifndef __VTPMMGR_DISK_CRYPTO_H
#define __VTPMMGR_DISK_CRYPTO_H

void do_random(void *buf, size_t size);
void aes_encrypt_one(void *target, const void *src, const struct key128 *key);
void aes_decrypt_one(void *target, const void *src, const struct key128 *key);

void aes_setup(aes_context *ctx, const struct key128 *key);
void aes_encrypt_ctr(void *target, size_t target_size, const void *srcv, size_t src_size, const aes_context *key_e);
void aes_decrypt_ctr(void *target, size_t target_size, const void *srcv, size_t src_size, const aes_context *key_e);
void aes_cmac(struct mac128 *target, const void *src, size_t size, const aes_context *key);
int aes_cmac_verify(const struct mac128 *target, const void *src, size_t size, const aes_context *key);

void sha256(struct hash256 *target, const void *src, size_t size);
int sha256_verify(const struct hash256 *targ, const void *data, size_t size);

#endif
