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

#ifndef VTPMMGR_H
#define VTPMMGR_H

#include <mini-os/tpmback.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

#include "uuid.h"
#include "tcg.h"
#include "vtpm_manager.h"

#define RSA_KEY_SIZE 0x0800
#define RSA_CIPHER_SIZE (RSA_KEY_SIZE / 8)

struct vtpm_globals {
   int tpm_fd;
   TPM_AUTH_SESSION    oiap;                // OIAP session for storageKey

   TPM_AUTHDATA        owner_auth;
   TPM_AUTHDATA        srk_auth;

   entropy_context     entropy;
   ctr_drbg_context    ctr_drbg;

   int hw_locality;
};

struct tpm_opaque {
	uuid_t *uuid;
	struct mem_group *group;
	struct mem_vtpm *vtpm;

	domid_t domid;
	unsigned int handle;

	uint8_t kern_hash[20];
};

// --------------------------- Global Values --------------------------
extern struct vtpm_globals vtpm_globals;   // Key info and DMI states

TPM_RESULT vtpmmgr_init(int argc, char** argv);
void vtpmmgr_shutdown(void);

TPM_RESULT vtpmmgr_handle_cmd(struct tpm_opaque *opq, tpmcmd_t* tpmcmd);

inline TPM_RESULT vtpmmgr_rand(unsigned char* bytes, size_t num_bytes) {
   return ctr_drbg_random(&vtpm_globals.ctr_drbg, bytes, num_bytes) == 0 ? 0 : TPM_FAIL;
}

#endif
