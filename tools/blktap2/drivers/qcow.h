/* 
 * Copyright (c) 2008, XenSource Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of XenSource Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _QCOW_H_
#define _QCOW_H_

#include "aes.h"
/**************************************************************/
/* QEMU COW block driver with compression and encryption support */

#define QCOW_MAGIC (('Q' << 24) | ('F' << 16) | ('I' << 8) | 0xfb)
#define XEN_MAGIC  (('X' << 24) | ('E' << 16) | ('N' << 8) | 0xfb)
#define QCOW_VERSION 1

#define QCOW_CRYPT_NONE 0x00
#define QCOW_CRYPT_AES  0x01

#define QCOW_OFLAG_COMPRESSED (1LL << 63)
#define SPARSE_FILE 0x01
#define EXTHDR_L1_BIG_ENDIAN 0x02

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define ROUNDUP(l, s) \
({ \
    (uint64_t)( \
        (l + (s - 1)) - ((l + (s - 1)) % s)); \
})

typedef struct QCowHeader {
	uint32_t magic;
	uint32_t version;
	uint64_t backing_file_offset;
	uint32_t backing_file_size;
	uint32_t mtime;
	uint64_t size; /* in bytes */
	uint8_t cluster_bits;
	uint8_t l2_bits;
	uint32_t crypt_method;
	uint64_t l1_table_offset;
} QCowHeader;

/*Extended header for Xen enhancements*/
typedef struct QCowHeader_ext {
        uint32_t xmagic;
        uint32_t cksum;
        uint32_t min_cluster_alloc;
        uint32_t flags;
} QCowHeader_ext;

uint32_t gen_cksum(char *ptr, int len);
int get_filesize(char *filename, uint64_t *size, struct stat *st);
int qtruncate(int fd, off_t length, int sparse);

#define L2_CACHE_SIZE 16  /*Fixed allocation in Qemu*/

struct tdqcow_state {
        int fd;                        /*Main Qcow file descriptor */
	uint64_t fd_end;               /*Store a local record of file length */
	char *name;                    /*Record of the filename*/
	uint32_t backing_file_size;
	uint64_t backing_file_offset;
	uint8_t extended;              /*File contains extended header*/
	int encrypted;                 /*File contents are encrypted or plain*/
	int cluster_bits;              /*Determines length of cluster as 
					*indicated by file hdr*/
	int cluster_size;              /*Length of cluster*/
	int cluster_sectors;           /*Number of sectors per cluster*/
	int cluster_alloc;             /*Blktap fix for allocating full 
					*extents*/
	int min_cluster_alloc;         /*Blktap historical extent alloc*/
	int sparse;                    /*Indicates whether to preserve sparseness*/
	int l2_bits;                   /*Size of L2 table entry*/
	int l2_size;                   /*Full table size*/
	int l1_size;                   /*L1 table size*/
	uint64_t cluster_offset_mask;    
	uint64_t l1_table_offset;      /*L1 table offset from beginning of 
					*file*/
	uint64_t *l1_table;            /*L1 table entries*/
	uint64_t *l2_cache;            /*We maintain a cache of size 
					*L2_CACHE_SIZE of most read entries*/
	uint64_t l2_cache_offsets[L2_CACHE_SIZE];     /*L2 cache entries*/
	uint32_t l2_cache_counts[L2_CACHE_SIZE];      /*Cache access record*/
	uint8_t *cluster_cache;          
	uint8_t *cluster_data;
	uint64_t cluster_cache_offset; /**/
	uint32_t crypt_method;         /*current crypt method, 0 if no 
					*key yet */
	uint32_t crypt_method_header;  /**/
	AES_KEY aes_encrypt_key;       /*AES key*/
	AES_KEY aes_decrypt_key;       /*AES key*/

        /* libaio state */
	int                  aio_free_count;	
	int                  max_aio_reqs;
	struct qcow_request   *aio_requests;
	struct qcow_request  **aio_free_list;

};

int qcow_create(const char *filename, uint64_t total_size,
		const char *backing_file, int sparse);

#endif //_QCOW_H_
